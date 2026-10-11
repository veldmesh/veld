// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT

//go:build linux

package coexist_test

import (
	"net"
	"net/netip"
	"os"
	"testing"

	"github.com/vishvananda/netlink"

	"github.com/veldmesh/veld/internal/coexist"
)

// hasNetAdmin reports whether route writes are permitted in the current
// environment. Requires root and CAP_NET_ADMIN — true on a privileged
// Linux box, false in containers and CI runners.
func hasNetAdmin() bool {
	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "veldprobe1"}}
	if err := netlink.LinkAdd(link); err != nil {
		return false
	}
	_ = netlink.LinkDel(link)
	return true
}

func mustIPNet(s string) *net.IPNet {
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return ipnet
}

// TestObserveSeesNonMainTableRoutes proves the snapshot covers ALL routing
// tables, not just main. wg-quick, Mullvad, NordLynx and Tailscale install
// their routes in dedicated policy-routing tables (wg-quick's default:
// 51820); a main-table-only dump misses the most common VPNs entirely, so
// full-tunnel detection and CIDR collision checks must see off-main routes.
//
// The test stands up a stand-in VPN tunnel: a dummy link whose name matches
// the generic tunnel pattern, carrying a default route and a mesh-prefix
// claim in table 51820 — then verifies Observe, full-tunnel detection and
// collision detection all catch it.
func TestObserveSeesNonMainTableRoutes(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("route installation requires root")
	}
	if !hasNetAdmin() {
		t.Skip("route installation requires CAP_NET_ADMIN")
	}

	const (
		tunName = "tun51820" // matches the generic tunnel pattern; stands in for the VPN's interface
		tableID = 51820      // wg-quick's standard policy-routing table
		tunAddr = "10.198.19.1/24"
		gw      = "10.198.19.2"
		meshDst = "10.100.0.0/24"
	)

	tun := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: tunName}}
	if err := netlink.LinkAdd(tun); err != nil {
		t.Fatalf("create dummy link: %v", err)
	}
	defer func() { _ = netlink.LinkDel(tun) }()

	if err := netlink.LinkSetUp(tun); err != nil {
		t.Fatalf("link up: %v", err)
	}
	addr, err := netlink.ParseAddr(tunAddr)
	if err != nil {
		t.Fatalf("parse addr: %v", err)
	}
	if err := netlink.AddrAdd(tun, addr); err != nil {
		t.Fatalf("addr add: %v", err)
	}

	gwIP := net.ParseIP(gw)
	added := []*netlink.Route{
		{Dst: mustIPNet(meshDst), Gw: gwIP, LinkIndex: tun.Attrs().Index, Table: tableID},
		{Dst: mustIPNet("0.0.0.0/0"), Gw: gwIP, LinkIndex: tun.Attrs().Index, Table: tableID},
	}
	for _, r := range added {
		if err := netlink.RouteAdd(r); err != nil {
			t.Fatalf("install route %s in table %d: %v", r.Dst, r.Table, err)
		}
	}
	defer func() {
		for _, r := range added {
			_ = netlink.RouteDel(r)
		}
	}()

	s, err := coexist.Observe()
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}

	// The off-main mesh-prefix claim is in the snapshot, tagged with its table.
	var seen *coexist.RouteEntry
	for i := range s.Routes {
		if s.Routes[i].Dst == netip.MustParsePrefix(meshDst) && s.Routes[i].Table == tableID {
			seen = &s.Routes[i]
		}
	}
	if seen == nil {
		t.Fatalf("route %s in table %d missing from snapshot — all-tables dump broken: %+v", meshDst, tableID, s.Routes)
	}
	if seen.Iface != tunName {
		t.Errorf("route should name %s as egress interface, got %q", tunName, seen.Iface)
	}

	// Full-tunnel detection: the default route lives in the VPN's table.
	vpns := coexist.DetectVPNs(s, "")
	var fullTunnel bool
	for _, v := range vpns {
		if v.Iface == tunName && v.FullTunnel {
			fullTunnel = true
		}
	}
	if !fullTunnel {
		t.Errorf("default route in table %d must mark %s as full-tunnel, got %+v", tableID, tunName, vpns)
	}

	// Collision detection: the off-main claim on the mesh prefix counts.
	cs := coexist.FindCollisions(s, "", netip.MustParsePrefix(meshDst))
	if len(cs) != 1 || cs[0].Kind != coexist.CollisionEqual {
		t.Fatalf("off-main equal collision for %s must be reported, got %+v", meshDst, cs)
	}
	if cs[0].Iface != tunName {
		t.Errorf("collision should name %s, got %+v", tunName, cs[0])
	}
}
