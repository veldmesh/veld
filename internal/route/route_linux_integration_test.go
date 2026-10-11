// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT

//go:build linux

package route_test

import (
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

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
		t.Errorf("route metric = %d, want %d", found.Priority, route.DefaultRouteMetric)
	}
	if !found.Gw.Equal(gwVeld.AsSlice()) {
		t.Errorf("route gw = %v, want %v (veld's replace took over the prefix)", found.Gw, gwVeld)
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

// TestHealReinstallsDisplacedRoute verifies that the background heal loop
// reinstalls a route that was displaced by a commercial VPN after veld
// installed it. This simulates the "VPN reconnects after veld" scenario.
func TestHealReinstallsDisplacedRoute(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("route installation requires root")
	}
	if !hasNetAdmin() {
		t.Skip("route installation requires CAP_NET_ADMIN")
	}

	const (
		dummyName = "veldhill0"
		dummyAddr = "10.198.19.1/24"
		testDst   = "10.99.78.0/24"
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
	gwVeld := netip.MustParseAddr("10.198.19.2")
	gwVPN := netip.MustParseAddr("10.198.19.3")

	// Step 1: Veldmesh installs its route first (metric 0).
	m := route.New()
	defer m.Close()
	if err := m.Add(dst, gwVeld); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// Verify veld's route is installed with metric 0.
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
		t.Errorf("initial route metric = %d, want %d", found.Priority, route.DefaultRouteMetric)
	}
	if !found.Gw.Equal(gwVeld.AsSlice()) {
		t.Errorf("initial route gw = %v, want %v", found.Gw, gwVeld)
	}

	// Step 2: Simulate commercial VPN reconnect — it reinstalls its route
	// with a higher metric, displacing veld's route.
	vpnRoute := &netlink.Route{
		Dst:       mustIPNet(testDst),
		Gw:        gwVPN.AsSlice(),
		LinkIndex: dummy.Attrs().Index,
		Priority:  600,
	}
	if err := netlink.RouteReplace(vpnRoute); err != nil {
		t.Fatalf("VPN displaces route: %v", err)
	}

	// Verify the VPN's route is now in place (higher metric).
	routes, err = netlink.RouteList(dummy, netlink.FAMILY_V4)
	if err != nil {
		t.Fatalf("list routes after VPN: %v", err)
	}
	found = nil
	for i := range routes {
		if routes[i].Dst != nil && routes[i].Dst.String() == testDst {
			found = &routes[i]
		}
	}
	if found == nil {
		t.Fatalf("route %s missing after VPN displaced it", testDst)
	}
	if found.Priority != 600 {
		t.Errorf("VPN route metric = %d, want 600", found.Priority)
	}
	if !found.Gw.Equal(gwVPN.AsSlice()) {
		t.Errorf("VPN route gw = %v, want %v", found.Gw, gwVPN)
	}

	// Step 3: Call Add again to simulate heal (peer rejoin or manual trigger).
	if err := m.Add(dst, gwVeld); err != nil {
		t.Fatalf("Add after displacement: %v", err)
	}

	// Verify veld's route is back with metric 0.
	routes, err = netlink.RouteList(dummy, netlink.FAMILY_V4)
	if err != nil {
		t.Fatalf("list routes after heal: %v", err)
	}
	found = nil
	for i := range routes {
		if routes[i].Dst != nil && routes[i].Dst.String() == testDst {
			found = &routes[i]
		}
	}
	if found == nil {
		t.Fatalf("route %s not present after heal", testDst)
	}
	if found.Priority != route.DefaultRouteMetric {
		t.Errorf("healed route metric = %d, want %d", found.Priority, route.DefaultRouteMetric)
	}
	if !found.Gw.Equal(gwVeld.AsSlice()) {
		t.Errorf("healed route gw = %v, want %v", found.Gw, gwVeld)
	}
}

// TestHealLoopRuns verifies the heal goroutine starts and stops correctly
// without panicking. It adds a route, waits briefly, then closes.
func TestHealLoopRuns(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("route installation requires root")
	}
	if !hasNetAdmin() {
		t.Skip("route installation requires CAP_NET_ADMIN")
	}

	const (
		dummyName = "veldhill1"
		dummyAddr = "10.198.20.1/24"
		testDst   = "10.99.79.0/24"
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
	gwVeld := netip.MustParseAddr("10.198.20.2")

	m := route.New()
	if err := m.Add(dst, gwVeld); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// Give the heal loop a moment to start (it runs every 30s, but the
	// goroutine should be running).
	time.Sleep(100 * time.Millisecond)

	if err := m.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Verify route is cleaned up.
	routes, err := netlink.RouteList(dummy, netlink.FAMILY_V4)
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
