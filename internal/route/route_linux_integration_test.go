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
	"golang.org/x/sys/unix"

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

// routeDev returns the device route (no gateway) for dst on link, or nil.
func routeDev(rs []netlink.Route, linkIndex int) *netlink.Route {
	for i := range rs {
		if rs[i].Gw == nil && rs[i].LinkIndex == linkIndex {
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

// TestRouteRestoreSameMetricVPNRoute tests the case where a VPN route at the
// same metric (DefaultRouteMetric) is displaced by veld's Add and restored on Close.
//
//  1. a dummy link is created (simulating a VPN tunnel interface)
//  2. a route at metric 0 is installed on the dummy link (as a VPN would)
//  3. veld Add installs its route for the same prefix, displacing the VPN route
//  4. veld Close removes its route and restores the VPN route
func TestRouteRestoreSameMetricVPNRoute(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("route installation requires root")
	}
	if !hasNetAdmin() {
		t.Skip("route installation requires CAP_NET_ADMIN")
	}

	const (
		dummyName = "veldrstore0"
		dummyAddr = "10.199.10.1/24"
		testDst   = "10.88.55.0/24"
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
	gwVPN := netip.MustParseAddr("10.199.10.2")  // VPN gateway on dummy link
	gwVeld := netip.MustParseAddr("10.199.10.3") // Veld's gateway

	// Simulate a VPN that installed a route at metric 0 (same as veld) on its tunnel interface.
	// This route will be displaced by veld's Add.
	vpnRoute := &netlink.Route{
		Dst:       parseIPNet(testDst),
		Gw:        gwVPN.AsSlice(),
		LinkIndex: dummy.Attrs().Index,
		Priority:  route.DefaultRouteMetric, // same metric as veld
		Table:     unix.RT_TABLE_MAIN,
	}
	if err := netlink.RouteAdd(vpnRoute); err != nil {
		t.Fatalf("install VPN route at metric 0: %v", err)
	}

	// Verify VPN route is there before veld Add
	rs := routesFor(t, dummy, testDst)
	if len(rs) != 1 {
		t.Fatalf("before Add: %d routes for %s, want 1 (VPN route)", len(rs), testDst)
	}
	if routeVia(rs, gwVPN) == nil {
		t.Fatalf("before Add: VPN route via %v not found", gwVPN)
	}

	m := route.New()
	defer m.Close()
	if err := m.Add(dst, gwVeld); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// After Add, veld's route should be installed (kernel prefers it due to
	// replace semantics), and the VPN route should be displaced.
	rs = routesFor(t, dummy, testDst)
	// RouteReplace with same prefix/metric displaces the existing route
	// The kernel may show only one route for the prefix at this metric
	// because replace overwrites it. But we can check what the kernel selects.
	if routeVia(rs, gwVeld) == nil {
		t.Logf("after Add: veld route not found in RouteList on link; checking kernel selection")
	}
	// Kernel should select veld's route because it was the last one installed
	// with the same metric via replace.
	got, err := netlink.RouteGet(net.ParseIP("10.88.55.1"))
	if err != nil {
		t.Fatalf("route get: %v", err)
	}
	if len(got) == 0 || !got[0].Gw.Equal(gwVeld.AsSlice()) {
		t.Errorf("kernel selects route via %v, want veld's %v", got, gwVeld)
	}

	// Now Close should remove veld's route and restore the VPN route.
	if err := m.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// After Close, the VPN route should be back.
	rs = routesFor(t, dummy, testDst)
	if routeVia(rs, gwVeld) != nil {
		t.Errorf("veld route for %s leaked after Close", testDst)
	}
	if routeVia(rs, gwVPN) == nil {
		t.Errorf("VPN route for %s not restored after Close", testDst)
	}

	// Verify kernel selects the restored VPN route
	got, err = netlink.RouteGet(net.ParseIP("10.88.55.1"))
	if err != nil {
		t.Fatalf("route get after Close: %v", err)
	}
	if len(got) == 0 || !got[0].Gw.Equal(gwVPN.AsSlice()) {
		t.Errorf("kernel selects route via %v after Close, want VPN's %v", got, gwVPN)
	}
}

// TestRouteRemoveRestoresSameMetricVPNRoute tests that Remove (not just Close)
// restores a same-metric displaced route.
func TestRouteRemoveRestoresSameMetricVPNRoute(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("route installation requires root")
	}
	if !hasNetAdmin() {
		t.Skip("route installation requires CAP_NET_ADMIN")
	}

	const (
		dummyName = "veldrstore1"
		dummyAddr = "10.199.20.1/24"
		testDst   = "10.77.44.0/24"
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
	gwVPN := netip.MustParseAddr("10.199.20.2")
	gwVeld := netip.MustParseAddr("10.199.20.3")

	// VPN route at metric 0 on dummy link
	vpnRoute := &netlink.Route{
		Dst:       parseIPNet(testDst),
		Gw:        gwVPN.AsSlice(),
		LinkIndex: dummy.Attrs().Index,
		Priority:  route.DefaultRouteMetric,
		Table:     unix.RT_TABLE_MAIN,
	}
	if err := netlink.RouteAdd(vpnRoute); err != nil {
		t.Fatalf("install VPN route: %v", err)
	}

	m := route.New()
	defer m.Close()
	if err := m.Add(dst, gwVeld); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// Verify veld's route is selected
	got, err := netlink.RouteGet(net.ParseIP("10.77.44.1"))
	if err != nil {
		t.Fatalf("route get: %v", err)
	}
	if len(got) == 0 || !got[0].Gw.Equal(gwVeld.AsSlice()) {
		t.Errorf("kernel selects route via %v, want veld's %v", got, gwVeld)
	}

	// Remove the prefix - should restore VPN route
	if err := m.Remove(dst); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	// VPN route should be back
	rs := routesFor(t, dummy, testDst)
	if routeVia(rs, gwVeld) != nil {
		t.Errorf("veld route for %s leaked after Remove", testDst)
	}
	if routeVia(rs, gwVPN) == nil {
		t.Errorf("VPN route for %s not restored after Remove", testDst)
	}

	got, err = netlink.RouteGet(net.ParseIP("10.77.44.1"))
	if err != nil {
		t.Fatalf("route get after Remove: %v", err)
	}
	if len(got) == 0 || !got[0].Gw.Equal(gwVPN.AsSlice()) {
		t.Errorf("kernel selects route via %v after Remove, want VPN's %v", got, gwVPN)
	}
}

// TestRouteRestoreSameMetricDeviceRoute tests the case where a VPN device
// route (no gateway, Scope: netlink.SCOPE_LINK) at metric 0 is displaced by
// veld's Add and restored on Close.
//
//  1. a dummy link is created (simulating a VPN tunnel interface like wg0)
//  2. a device route at metric 0 is installed on the dummy link (as WireGuard/OpenVPN/nordlynx would)
//  3. veld Add installs its route for the same prefix, displacing the VPN route
//  4. veld Close removes its route and restores the VPN device route
func TestRouteRestoreSameMetricDeviceRoute(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("route installation requires root")
	}
	if !hasNetAdmin() {
		t.Skip("route installation requires CAP_NET_ADMIN")
	}

	const (
		dummyName = "veldrstore2"
		dummyAddr = "10.199.30.1/24"
		testDst   = "10.66.33.0/24"
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
	gwVeld := netip.MustParseAddr("10.199.30.3") // Veld's gateway

	// Simulate a VPN (WireGuard/OpenVPN/nordlynx) that installed a device route
	// at metric 0 on its tunnel interface. No gateway, Scope: LINK.
	vpnRoute := &netlink.Route{
		Dst:       parseIPNet(testDst),
		LinkIndex: dummy.Attrs().Index,
		Priority:  route.DefaultRouteMetric, // same metric as veld
		Table:     unix.RT_TABLE_MAIN,
		Scope:     netlink.SCOPE_LINK,
	}
	if err := netlink.RouteAdd(vpnRoute); err != nil {
		t.Fatalf("install VPN device route at metric 0: %v", err)
	}

	// Verify VPN device route is there before veld Add
	rs := routesFor(t, dummy, testDst)
	if len(rs) != 1 {
		t.Fatalf("before Add: %d routes for %s, want 1 (VPN device route)", len(rs), testDst)
	}
	if routeDev(rs, dummy.Attrs().Index) == nil {
		t.Fatalf("before Add: VPN device route on link %d not found", dummy.Attrs().Index)
	}

	m := route.New()
	defer m.Close()
	if err := m.Add(dst, gwVeld); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// After Add, veld's route should be installed, and the VPN device route displaced.
	// Kernel should select veld's route because it was the last one installed
	// with the same metric via replace.
	got, err := netlink.RouteGet(net.ParseIP("10.66.33.1"))
	if err != nil {
		t.Fatalf("route get: %v", err)
	}
	if len(got) == 0 || !got[0].Gw.Equal(gwVeld.AsSlice()) {
		t.Errorf("kernel selects route via %v, want veld's %v", got, gwVeld)
	}

	// Now Close should remove veld's route and restore the VPN device route.
	if err := m.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// After Close, the VPN device route should be back.
	rs = routesFor(t, dummy, testDst)
	if routeVia(rs, gwVeld) != nil {
		t.Errorf("veld route for %s leaked after Close", testDst)
	}
	if routeDev(rs, dummy.Attrs().Index) == nil {
		t.Errorf("VPN device route for %s not restored after Close", testDst)
	}

	// Verify kernel selects the restored VPN device route (no gateway, link index matches)
	got, err = netlink.RouteGet(net.ParseIP("10.66.33.1"))
	if err != nil {
		t.Fatalf("route get after Close: %v", err)
	}
	if len(got) == 0 || got[0].Gw != nil {
		t.Errorf("kernel selects route with gateway %v after Close, want device route", got[0].Gw)
	}
	if got[0].LinkIndex != dummy.Attrs().Index {
		t.Errorf("kernel selects route on link %d after Close, want VPN's link %d", got[0].LinkIndex, dummy.Attrs().Index)
	}
}
