// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT

//go:build linux

package route_test

import (
	"net"
	"net/netip"
	"os"
	"testing"

	"github.com/vishvananda/netlink"

	"github.com/veldmesh/veld/internal/route"
)

// hasNetAdmin reports whether route writes are permitted in the current
// environment. Requires root and CAP_NET_ADMIN — true on a privileged
// Linux box, false in containers and CI runners.
func hasNetAdmin() bool {
	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "veldprobe0"}}
	if err := netlink.LinkAdd(link); err != nil {
		return false
	}
	_ = netlink.LinkDel(link)
	return true
}

func parseIPNet(s string) *net.IPNet {
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return ipnet
}

// routesFor returns every IPv4 route for dst on link.
func routesFor(t *testing.T, link netlink.Link, dst string) []netlink.Route {
	t.Helper()
	routes, err := netlink.RouteList(link, netlink.FAMILY_V4)
	if err != nil {
		t.Fatalf("list routes: %v", err)
	}
	var out []netlink.Route
	for _, r := range routes {
		if r.Dst != nil && r.Dst.String() == dst {
			out = append(out, r)
		}
	}
	return out
}

// routeVia returns the route for dst whose gateway is gw, or nil.
func routeVia(rs []netlink.Route, gw netip.Addr) *netlink.Route {
	for i := range rs {
		if rs[i].Gw.Equal(gw.AsSlice()) {
			return &rs[i]
		}
	}
	return nil
}

// TestRouteReplaceTakesOverVPNRoute is the end-to-end coexistence test for
// the "commercial VPN connected first" ordering:
//
//  1. a conflicting route with a non-zero metric is installed (as a VPN would),
//  2. the route manager adds veld's route for the same prefix,
//  3. veld's route is installed at DefaultRouteMetric alongside the VPN's
//     route, which is left untouched; the kernel prefers veld's lower metric,
//  4. Close removes only veld's route; the VPN's route survives.
//
// A replace only displaces a route with the same prefix and metric, so a VPN
// route at a different metric is outranked rather than overwritten.
func TestRouteReplaceTakesOverVPNRoute(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("route installation requires root")
	}
	if !hasNetAdmin() {
		t.Skip("route installation requires CAP_NET_ADMIN")
	}

	const (
		dummyName = "veldcoex0"
		dummyAddr = "10.198.18.1/24"
		testDst   = "10.99.77.0/24"
	)

	dummy := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: dummyName}}
	if err := netlink.LinkAdd(dummy); err != nil {
		t.Fatalf("create dummy link: %v", err)
	}
	defer func() { _ = netlink.LinkDel(dummy) }()

	if err := netlink.LinkSetUp(dummy); err != nil {
		t.Fatalf("link up: %v", err)
	}
	addr, err := netlink.ParseAddr(dummyAddr)
	if err != nil {
		t.Fatalf("parse addr: %v", err)
	}
	if err := netlink.AddrAdd(dummy, addr); err != nil {
		t.Fatalf("addr add: %v", err)
	}

	dst := netip.MustParsePrefix(testDst)
	gwVPN := netip.MustParseAddr("10.198.18.2")
	gwVeld := netip.MustParseAddr("10.198.18.3")

	// Simulate the commercial VPN: it claimed the prefix first with a
	// non-zero metric route.
	vpnRoute := &netlink.Route{
		Dst:       parseIPNet(testDst),
		Gw:        gwVPN.AsSlice(),
		LinkIndex: dummy.Attrs().Index,
		Priority:  600,
	}
	if err := netlink.RouteAdd(vpnRoute); err != nil {
		t.Fatalf("install VPN route: %v", err)
	}

	m := route.New()
	defer m.Close()
	if err := m.Add(dst, gwVeld); err != nil {
		t.Fatalf("Add: %v", err)
	}

	rs := routesFor(t, dummy, testDst)
	if len(rs) != 2 {
		t.Fatalf("after Add: %d routes for %s, want 2 (veld's alongside the VPN's)", len(rs), testDst)
	}
	veldRoute := routeVia(rs, gwVeld)
	if veldRoute == nil {
		t.Fatalf("after Add: no route for %s via veld gateway %v", testDst, gwVeld)
	}
	if veldRoute.Priority != route.DefaultRouteMetric {
		t.Errorf("veld route metric = %d, want %d", veldRoute.Priority, route.DefaultRouteMetric)
	}
	vpnFound := routeVia(rs, gwVPN)
	if vpnFound == nil {
		t.Errorf("VPN route via %v was removed by Add; it must be left in place", gwVPN)
	} else if vpnFound.Priority != vpnRoute.Priority {
		t.Errorf("VPN route metric = %d, want %d (unchanged)", vpnFound.Priority, vpnRoute.Priority)
	}

	got, err := netlink.RouteGet(net.ParseIP("10.99.77.1"))
	if err != nil {
		t.Fatalf("route get: %v", err)
	}
	if len(got) == 0 || !got[0].Gw.Equal(gwVeld.AsSlice()) {
		t.Errorf("kernel selects route via %v, want veld's %v", got, gwVeld)
	}

	if err := m.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	rs = routesFor(t, dummy, testDst)
	if routeVia(rs, gwVeld) != nil {
		t.Errorf("veld route for %s leaked after Close", testDst)
	}
	if routeVia(rs, gwVPN) == nil {
		t.Errorf("VPN route for %s removed by Close; it must survive", testDst)
	}
}
