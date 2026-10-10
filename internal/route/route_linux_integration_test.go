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

// TestRouteReplaceTakesOverVPNRoute is the end-to-end coexistence test for
// the "commercial VPN connected first" ordering:
//
//  1. a conflicting route with a non-zero metric is installed (as a VPN would),
//  2. the route manager adds veld's route for the same prefix,
//  3. veld's route must hold the prefix with metric DefaultRouteMetric,
//  4. Close removes it again, leaving nothing behind.
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
		Dst:       mustIPNet(testDst),
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

	routes, err := netlink.RouteList(dummy, netlink.FAMILY_V4)
	if err != nil {
		t.Fatalf("list routes: %v", err)
	}
	var found *netlink.Route
	for i := range routes {
		if routes[i].Dst != nil && routes[i].Dst.String() == testDst {
			found = &routes[i]
		}
	}
	if found == nil {
		t.Fatalf("route %s not present after Add", testDst)
	}
	if found.Priority != route.DefaultRouteMetric {
		t.Errorf("route metric = %d, want %d (veld must win ties)", found.Priority, route.DefaultRouteMetric)
	}
	if !found.Gw.Equal(gwVeld.AsSlice()) {
		t.Errorf("route gw = %v, want %v (veld must take over the prefix)", found.Gw, gwVeld)
	}

	if err := m.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	routes, err = netlink.RouteList(dummy, netlink.FAMILY_V4)
	if err != nil {
		t.Fatalf("list routes: %v", err)
	}
	for _, r := range routes {
		if r.Dst != nil && r.Dst.String() == testDst {
			t.Errorf("route %s leaked after Close", testDst)
		}
	}
}

func mustIPNet(s string) *net.IPNet {
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return ipnet
}
