// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT

//go:build linux

package route

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/vishvananda/netlink"
)

// recordingHandle records route operations for inspection and lets tests
// inject errors. It verifies exactly what the manager asks the kernel to do.
type recordingHandle struct {
	mu       sync.Mutex
	replaced []*netlink.Route
	deleted  []*netlink.Route
	err      error
}

func (h *recordingHandle) RouteReplace(r *netlink.Route) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.err != nil {
		return h.err
	}
	clone := *r
	h.replaced = append(h.replaced, &clone)
	return nil
}

func (h *recordingHandle) RouteDel(r *netlink.Route) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.err != nil {
		return h.err
	}
	clone := *r
	h.deleted = append(h.deleted, &clone)
	return nil
}

func newTestManager(h *recordingHandle) *linuxManager {
	return newLinuxManager(h)
}

// TestAddReplacesWithExplicitMetric verifies what Add asks the kernel for on
// Linux, the two properties of the install:
//
//  1. The route is installed via replace, not add, so a stale route veld
//     left at the same prefix and metric is overwritten rather than failing
//     with "file exists".
//  2. The route carries metric DefaultRouteMetric — the metric the kernel
//     would use for an unqualified route add, made explicit. The lowest
//     metric wins for a prefix, which is what lets veld outrank a VPN route.
func TestAddReplacesWithExplicitMetric(t *testing.T) {
	h := &recordingHandle{}
	m := newTestManager(h)

	prefix := netip.MustParsePrefix("192.168.1.0/24")
	via := netip.MustParseAddr("10.100.0.2")
	if err := m.Add(prefix, via); err != nil {
		t.Fatalf("Add: %v", err)
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.replaced) != 1 {
		t.Fatalf("Add must install exactly one route via replace, got %d calls", len(h.replaced))
	}
	r := h.replaced[0]
	if r.Dst == nil || r.Dst.String() != "192.168.1.0/24" {
		t.Errorf("Dst = %v, want 192.168.1.0/24", r.Dst)
	}
	if r.Gw == nil || !r.Gw.Equal(net.ParseIP("10.100.0.2")) {
		t.Errorf("Gw = %v, want 10.100.0.2", r.Gw)
	}
	if r.Priority != DefaultRouteMetric {
		t.Errorf("Priority = %d, want %d (the explicit default metric)", r.Priority, DefaultRouteMetric)
	}
}

func TestAddIPv6SetsMetric(t *testing.T) {
	h := &recordingHandle{}
	m := newTestManager(h)

	if err := m.Add(netip.MustParsePrefix("fd00::/8"), netip.MustParseAddr("fd00::1")); err != nil {
		t.Fatalf("Add: %v", err)
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.replaced) != 1 {
		t.Fatalf("expected 1 replace, got %d", len(h.replaced))
	}
	if h.replaced[0].Dst == nil || h.replaced[0].Dst.String() != "fd00::/8" {
		t.Errorf("Dst = %v, want fd00::/8", h.replaced[0].Dst)
	}
	if h.replaced[0].Priority != DefaultRouteMetric {
		t.Errorf("Priority = %d, want %d", h.replaced[0].Priority, DefaultRouteMetric)
	}
}

func TestAddPropagatesKernelError(t *testing.T) {
	h := &recordingHandle{err: errFakeKernel}
	m := newTestManager(h)

	err := m.Add(netip.MustParsePrefix("192.168.1.0/24"), netip.MustParseAddr("10.100.0.2"))
	if err == nil {
		t.Fatal("Add must propagate kernel errors")
	}
	if !strings.Contains(err.Error(), "route replace") {
		t.Errorf("error should mention the failed operation: %v", err)
	}
}

// TestCloseRemovesAllAddedRoutes verifies every Add is tracked and removed
// by Close, so veld never leaks routes across restarts.
func TestCloseRemovesAllAddedRoutes(t *testing.T) {
	h := &recordingHandle{}
	m := newTestManager(h)

	added := []netip.Prefix{
		netip.MustParsePrefix("192.168.1.0/24"),
		netip.MustParsePrefix("10.200.0.0/16"),
		netip.MustParsePrefix("fd00::/8"),
	}
	for _, p := range added {
		if err := m.Add(p, netip.MustParseAddr("10.100.0.2")); err != nil {
			t.Fatalf("Add %s: %v", p, err)
		}
	}
	if err := m.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.deleted) != len(added) {
		t.Fatalf("Close removed %d routes, want %d", len(h.deleted), len(added))
	}
	removed := map[string]bool{}
	for _, r := range h.deleted {
		removed[r.Dst.String()] = true
	}
	for _, p := range added {
		if !removed[p.String()] {
			t.Errorf("route %s not removed by Close", p)
		}
	}
}

// errFakeKernel simulates a netlink failure (e.g. EPERM without
// CAP_NET_ADMIN, or a route collision the kernel rejects).
var errFakeKernel = errors.New("netlink: operation not permitted")

// TestRemoveMatchesGateway checks that Remove deletes only veld's own route:
// another route for the same prefix (a VPN that reconnected after veld) must
// not be removed by a delete that matches on destination alone.
func TestRemoveMatchesGateway(t *testing.T) {
	h := &recordingHandle{}
	m := newLinuxManager(h)
	pfx := netip.MustParsePrefix("192.168.50.0/24")
	via := netip.MustParseAddr("10.0.0.2")
	if err := m.Add(pfx, via); err != nil {
		t.Fatal(err)
	}
	if err := m.Remove(pfx); err != nil {
		t.Fatal(err)
	}
	if len(h.deleted) != 1 || !h.deleted[0].Gw.Equal(net.IP(via.AsSlice())) {
		t.Fatalf("Remove: got %+v, want one delete via %s", h.deleted, via)
	}

	// A prefix veld never installed is left alone.
	if err := m.Remove(netip.MustParsePrefix("192.168.51.0/24")); err != nil {
		t.Fatal(err)
	}
	if len(h.deleted) != 1 {
		t.Errorf("Remove of an unknown prefix issued a delete")
	}
}

func TestEnableIPForwardRestores(t *testing.T) {
	path := t.TempDir() + "/ip_forward"
	old := ipForwardPath
	ipForwardPath = path
	defer func() { ipForwardPath = old }()

	for _, prev := range []string{"0\n", "1\n"} {
		if err := os.WriteFile(path, []byte(prev), 0644); err != nil {
			t.Fatal(err)
		}
		restore, err := EnableIPForward()
		if err != nil {
			t.Fatal(err)
		}
		if b, _ := os.ReadFile(path); string(b) != "1\n" {
			t.Errorf("prev %q: forwarding not enabled: %q", prev, b)
		}
		if err := restore(); err != nil {
			t.Fatal(err)
		}
		if b, _ := os.ReadFile(path); string(b) != prev {
			t.Errorf("restore: got %q, want %q", b, prev)
		}
	}
}
