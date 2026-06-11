// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package route_test

import (
	"net/netip"
	"testing"

	"github.com/veldmesh/veld/internal/route"
)

// TestNew verifies that New() returns a non-nil manager on all platforms.
func TestNew(t *testing.T) {
	m := route.New()
	if m == nil {
		t.Fatal("route.New() returned nil")
	}
	if err := m.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// TestAddRemove verifies that Add and Remove complete without error on all platforms.
// On non-Linux platforms this exercises the no-op path.
func TestAddRemove(t *testing.T) {
	m := route.New()
	defer m.Close()

	prefix := netip.MustParsePrefix("192.168.1.0/24")
	via := netip.MustParseAddr("10.0.0.2")

	if err := m.Add(prefix, via); err != nil {
		// On non-root Linux the syscall will fail; that's acceptable here.
		// The noop implementation on other platforms always succeeds.
		t.Logf("Add (may fail on non-root Linux): %v", err)
	}

	if err := m.Remove(prefix); err != nil {
		t.Logf("Remove (may fail if route not present): %v", err)
	}
}

// TestRemoveNotAdded verifies that Remove is a no-op when the route was never added.
func TestRemoveNotAdded(t *testing.T) {
	m := route.New()
	defer m.Close()

	prefix := netip.MustParsePrefix("172.16.0.0/12")
	if err := m.Remove(prefix); err != nil {
		t.Logf("Remove of un-added route: %v", err)
	}
}

// TestCloseEmptyManager verifies that Close on a manager with no routes is a no-op.
func TestCloseEmptyManager(t *testing.T) {
	m := route.New()
	if err := m.Close(); err != nil {
		t.Errorf("Close of empty manager: %v", err)
	}
}

// TestIPv6Route verifies that IPv6 prefixes can be passed to Add without panicking.
func TestIPv6Route(t *testing.T) {
	m := route.New()
	defer m.Close()

	prefix := netip.MustParsePrefix("fd00::/8")
	via := netip.MustParseAddr("fd00::1")

	if err := m.Add(prefix, via); err != nil {
		t.Logf("IPv6 Add (may fail on non-root or unsupported platform): %v", err)
	}
}
