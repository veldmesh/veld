// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT

//go:build linux

package coexist_test

import (
	"net/netip"
	"testing"

	"github.com/veldmesh/veld/internal/coexist"
)

// TestObserveLinux verifies real netlink gathering on Linux: the loopback
// link must be present, the routing snapshot must span every table — main
// (254) with a default route, and local (255) with loopback host routes —
// because VPNs like wg-quick, Mullvad and NordLynx install their routes in
// dedicated policy tables. Route and link dumps are unprivileged read-only
// operations, so this runs everywhere Linux runs, including CI.
func TestObserveLinux(t *testing.T) {
	s, err := coexist.Observe()
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}

	var lo, def, local bool
	for _, l := range s.Links {
		if l.Name == "lo" {
			lo = true
		}
	}
	for _, r := range s.Routes {
		if r.Dst == netip.MustParsePrefix("0.0.0.0/0") && r.Table != 255 {
			def = true
			if r.Iface == "" {
				t.Errorf("default route should name an egress interface")
			}
		}
		if r.Table == 255 {
			local = true
		}
	}
	if !lo {
		t.Errorf("loopback link missing from snapshot: %+v", s.Links)
	}
	if !def {
		t.Errorf("no IPv4 default route in snapshot: %+v", s.Routes)
	}
	if !local {
		t.Errorf("no local-table (255) route in snapshot — all-tables dump broken: %+v", s.Routes)
	}
}

// TestCheckRouteRealState exercises collision detection against the real
// routing table: the connected route of any non-loopback interface must be
// reported as an equal collision — unless it belongs to us.
func TestCheckRouteRealState(t *testing.T) {
	s, err := coexist.Observe()
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}

	var conn *coexist.RouteEntry
	for i, r := range s.Routes {
		// Local-table (255) host routes are skipped by collision checks;
		// pick a real main-table route so the assertion below is meaningful.
		if r.Dst != netip.MustParsePrefix("0.0.0.0/0") && r.Iface != "" && r.Iface != "lo" && r.Table != 255 {
			conn = &s.Routes[i]
			break
		}
	}
	if conn == nil {
		t.Skip("no connected non-loopback route present")
	}

	cs := coexist.CheckRoute(conn.Dst, "")
	if len(cs) == 0 {
		t.Fatalf("expected equal collision for %s via %s, got none", conn.Dst, conn.Iface)
	}
	if cs[0].Kind != coexist.CollisionEqual {
		t.Errorf("Kind = %v, want CollisionEqual (%+v)", cs[0].Kind, cs[0])
	}

	// Claiming the route's own interface as ours suppresses the collision.
	if cs := coexist.CheckRoute(conn.Dst, conn.Iface); len(cs) != 0 {
		t.Errorf("collision on own interface should be skipped, got %+v", cs)
	}
}
