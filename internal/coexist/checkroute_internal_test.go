// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package coexist

import (
	"errors"
	"log"
	"net/netip"
	"strings"
	"testing"
)

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }

// TestCheckRouteLogsObserveError verifies that CheckRoute logs an error when
// Observe fails, and returns nil (does not block route installation).
func TestCheckRouteLogsObserveError(t *testing.T) {
	// Save original observe function
	origObserve := observe
	defer func() { observe = origObserve }()

	// Replace with a failing function
	observe = func() (Snapshot, error) {
		return Snapshot{}, errors.New("netlink dump failed: permission denied")
	}

	// Capture log output
	var logBuf strings.Builder
	log.SetOutput(&logBuf)
	log.SetFlags(0)
	defer log.SetOutput(nil) // Reset to default

	result := CheckRoute(pfx("10.100.0.0/24"), "veld0")

	if result != nil {
		t.Errorf("CheckRoute must return nil on Observe failure, got %+v", result)
	}

	output := logBuf.String()
	if !strings.Contains(output, "could not inspect host network state for route check") {
		t.Errorf("CheckRoute must log Observe error; got: %q", output)
	}
	if !strings.Contains(output, "netlink dump failed: permission denied") {
		t.Errorf("log must contain the underlying error; got: %q", output)
	}
}

// TestCheckRouteWithCustomObserve verifies the checkRoute internal function
// with an injected observer (tests the seam directly).
func TestCheckRouteWithCustomObserve(t *testing.T) {
	// Save original observe function
	origObserve := observe
	defer func() { observe = origObserve }()

	// Test success case
	observe = func() (Snapshot, error) {
		return Snapshot{
			Routes: []RouteEntry{
				{Dst: pfx("10.100.0.0/24"), Iface: "nordlynx"},
			},
		}, nil
	}

	cs := CheckRoute(pfx("10.100.0.0/24"), "veld0")
	if len(cs) != 1 || cs[0].Kind != CollisionEqual {
		t.Errorf("expected equal collision, got %+v", cs)
	}

	// Test error case
	observe = func() (Snapshot, error) {
		return Snapshot{}, errors.New("snapshot failed")
	}

	var logBuf strings.Builder
	log.SetOutput(&logBuf)
	log.SetFlags(0)

	cs = CheckRoute(pfx("10.100.0.0/24"), "veld0")
	if cs != nil {
		t.Errorf("expected nil on error, got %+v", cs)
	}

	log.SetOutput(nil)
	output := logBuf.String()
	if !strings.Contains(output, "could not inspect host network state for route check") {
		t.Errorf("expected error log, got: %q", output)
	}
}

// TestCheckRouteSuccess verifies CheckRoute returns collisions when Observe succeeds.
func TestCheckRouteSuccess(t *testing.T) {
	origObserve := observe
	defer func() { observe = origObserve }()

	observe = func() (Snapshot, error) {
		return Snapshot{
			Routes: []RouteEntry{
				{Dst: pfx("10.0.0.0/8"), Iface: "tun0"},
				{Dst: pfx("192.168.1.0/24"), Iface: "eth0"},
			},
		}, nil
	}

	cs := CheckRoute(pfx("10.100.0.0/24"), "veld0")
	if len(cs) != 1 {
		t.Fatalf("expected 1 collision (broader), got %+v", cs)
	}
	if cs[0].Kind != CollisionBroader {
		t.Errorf("expected CollisionBroader, got %v", cs[0].Kind)
	}
}

// TestCheckRouteSkipsSelfInterface verifies selfIface exclusion works.
func TestCheckRouteSkipsSelfInterface(t *testing.T) {
	origObserve := observe
	defer func() { observe = origObserve }()

	observe = func() (Snapshot, error) {
		return Snapshot{
			Routes: []RouteEntry{
				{Dst: pfx("10.100.0.0/24"), Iface: "veld0"},
			},
		}, nil
	}

	cs := CheckRoute(pfx("10.100.0.0/24"), "veld0")
	if len(cs) != 0 {
		t.Errorf("expected no collision (self-interface excluded), got %+v", cs)
	}
}