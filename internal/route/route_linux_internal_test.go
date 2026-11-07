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
	"golang.org/x/sys/unix"
)

// recordingHandle records route operations for inspection and lets tests
// inject errors. It verifies exactly what the manager asks the kernel to do.
type recordingHandle struct {
	mu           sync.Mutex
	replaced     []*netlink.Route
	added        []*netlink.Route
	deleted      []*netlink.Route
	listFiltered []*netlink.Route // routes returned by RouteListFiltered (pre-filtered by test)
	listFilter   *netlink.Route   // last filter passed to RouteListFiltered
	listMask     uint64           // last filterMask passed to RouteListFiltered
	errReplace   error            // error to return from RouteReplace
	errAdd       error            // error to return from RouteAdd
	errDel       error            // error to return from RouteDel
	errList      error            // error to return from RouteListFiltered
}

func (h *recordingHandle) RouteReplace(r *netlink.Route) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	clone := *r
	h.replaced = append(h.replaced, &clone)
	if h.errReplace != nil {
		return h.errReplace
	}
	return nil
}

func (h *recordingHandle) RouteAdd(r *netlink.Route) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	clone := *r
	h.added = append(h.added, &clone)
	if h.errAdd != nil {
		return h.errAdd
	}
	return nil
}

func (h *recordingHandle) RouteDel(r *netlink.Route) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	clone := *r
	h.deleted = append(h.deleted, &clone)
	if h.errDel != nil {
		return h.errDel
	}
	return nil
}

func (h *recordingHandle) RouteListFiltered(family int, filter *netlink.Route, filterMask uint64) ([]netlink.Route, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.listFilter = filter
	h.listMask = filterMask
	if h.errList != nil {
		return nil, h.errList
	}
	// Apply basic filtering to match the filter criteria
	var result []netlink.Route
	for _, r := range h.listFiltered {
		if h.routeMatchesFilter(r, filter, filterMask) {
			result = append(result, *r)
		}
	}
	return result, nil
}

func (h *recordingHandle) routeMatchesFilter(r *netlink.Route, filter *netlink.Route, mask uint64) bool {
	if mask&netlink.RT_FILTER_DST != 0 && filter.Dst != nil {
		if r.Dst == nil || !ipNetEqual(r.Dst, filter.Dst) {
			return false
		}
	}
	if mask&netlink.RT_FILTER_PRIORITY != 0 {
		if r.Priority != filter.Priority {
			return false
		}
	}
	if mask&netlink.RT_FILTER_TABLE != 0 {
		if r.Table != filter.Table {
			return false
		}
	}
	if mask&netlink.RT_FILTER_GW != 0 && filter.Gw != nil {
		if r.Gw == nil || !r.Gw.Equal(filter.Gw) {
			return false
		}
	}
	if mask&netlink.RT_FILTER_OIF != 0 {
		if r.LinkIndex != filter.LinkIndex {
			return false
		}
	}
	return true
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
	h := &recordingHandle{errReplace: errFakeKernel}
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

// TestAddRemembersDisplacedRoute verifies that when a route exists at the same
// prefix and metric with a different gateway, Add remembers it for later
// restoration.
func TestAddRemembersDisplacedRoute(t *testing.T) {
	h := &recordingHandle{
		listFiltered: []*netlink.Route{
			{
				Dst:       parseIPNet("10.99.77.0/24"),
				Gw:        net.ParseIP("10.198.18.2"),
				LinkIndex: 5,
				Priority:  DefaultRouteMetric,
				Table:     unix.RT_TABLE_MAIN,
			},
		},
	}
	m := newTestManager(h)

	prefix := netip.MustParsePrefix("10.99.77.0/24")
	via := netip.MustParseAddr("10.198.18.3")
	if err := m.Add(prefix, via); err != nil {
		t.Fatalf("Add: %v", err)
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if h.listFilter == nil {
		t.Fatal("RouteListFiltered called with nil filter")
	}
	if h.listFilter.Dst == nil || h.listFilter.Dst.String() != "10.99.77.0/24" {
		t.Errorf("RouteListFiltered Dst = %v, want 10.99.77.0/24", h.listFilter.Dst)
	}
	if h.listFilter.Priority != DefaultRouteMetric {
		t.Errorf("RouteListFiltered Priority = %d, want %d", h.listFilter.Priority, DefaultRouteMetric)
	}
	if h.listFilter.Table != unix.RT_TABLE_MAIN {
		t.Errorf("RouteListFiltered Table = %d, want %d", h.listFilter.Table, unix.RT_TABLE_MAIN)
	}
	if h.listMask != (netlink.RT_FILTER_DST | netlink.RT_FILTER_PRIORITY | netlink.RT_FILTER_TABLE) {
		t.Errorf("RouteListFiltered mask = %d, want %d", h.listMask, netlink.RT_FILTER_DST|netlink.RT_FILTER_PRIORITY|netlink.RT_FILTER_TABLE)
	}

	// Verify the displaced route was remembered
	m.mu.Lock()
	displaced := m.displaced[prefix]
	m.mu.Unlock()
	if displaced == nil {
		t.Fatal("displaced route not remembered")
	}
	if displaced.Gw == nil || !displaced.Gw.Equal(net.ParseIP("10.198.18.2")) {
		t.Errorf("displaced route Gw = %v, want 10.198.18.2", displaced.Gw)
	}
	if displaced.LinkIndex != 5 {
		t.Errorf("displaced route LinkIndex = %d, want 5", displaced.LinkIndex)
	}
}

// TestAddRemembersDisplacedDeviceRoute verifies that Add remembers a device
// route (no gateway, different link index) at the same prefix and metric.
func TestAddRemembersDisplacedDeviceRoute(t *testing.T) {
	h := &recordingHandle{
		listFiltered: []*netlink.Route{
			{
				Dst:       parseIPNet("10.99.77.0/24"),
				LinkIndex: 7, // VPN tunnel interface
				Priority:  DefaultRouteMetric,
				Table:     unix.RT_TABLE_MAIN,
				Scope:     netlink.SCOPE_LINK,
			},
		},
	}
	m := newTestManager(h)

	prefix := netip.MustParsePrefix("10.99.77.0/24")
	via := netip.MustParseAddr("10.198.18.3")
	if err := m.Add(prefix, via); err != nil {
		t.Fatalf("Add: %v", err)
	}

	m.mu.Lock()
	displaced := m.displaced[prefix]
	m.mu.Unlock()
	if displaced == nil {
		t.Fatal("displaced device route not remembered")
	}
	if displaced.Gw != nil {
		t.Errorf("displaced device route should have no gateway, got %v", displaced.Gw)
	}
	if displaced.LinkIndex != 7 {
		t.Errorf("displaced device route LinkIndex = %d, want 7", displaced.LinkIndex)
	}
}

// TestAddDoesNotRememberDeviceRouteOnOwnTUNLink verifies that Add does not
// remember a device route on veld's own TUN link (stale from a previous run).
func TestAddDoesNotRememberDeviceRouteOnOwnTUNLink(t *testing.T) {
	h := &recordingHandle{
		listFiltered: []*netlink.Route{
			{
				Dst:       parseIPNet("10.99.77.0/24"),
				LinkIndex: 42, // veld's own TUN link
				Priority:  DefaultRouteMetric,
				Table:     unix.RT_TABLE_MAIN,
				Scope:     netlink.SCOPE_LINK,
			},
		},
	}
	m := newTestManager(h)
	m.SetTUNLink(42) // Set veld's TUN link index

	prefix := netip.MustParsePrefix("10.99.77.0/24")
	via := netip.MustParseAddr("10.198.18.3")
	if err := m.Add(prefix, via); err != nil {
		t.Fatalf("Add: %v", err)
	}

	m.mu.Lock()
	displaced := m.displaced[prefix]
	m.mu.Unlock()
	if displaced != nil {
		t.Errorf("displaced route remembered for own TUN link, want nil")
	}
}

// TestAddDoesNotRememberGatewayRouteOnOwnTUNLink verifies that Add does not
// remember a gateway route on veld's own TUN link, even if the gateway
// differs (e.g., a stale route from a previous run with a different VPN
// address). Only routes on other links are considered displaced VPN routes.
func TestAddDoesNotRememberGatewayRouteOnOwnTUNLink(t *testing.T) {
	h := &recordingHandle{
		listFiltered: []*netlink.Route{
			{
				Dst:       parseIPNet("10.99.77.0/24"),
				Gw:        net.ParseIP("10.198.18.99"), // different gateway (stale from old VPN address)
				LinkIndex: 42,                          // veld's own TUN link
				Priority:  DefaultRouteMetric,
				Table:     unix.RT_TABLE_MAIN,
			},
		},
	}
	m := newTestManager(h)
	m.SetTUNLink(42) // Set veld's TUN link index

	prefix := netip.MustParsePrefix("10.99.77.0/24")
	via := netip.MustParseAddr("10.198.18.3") // current veld gateway
	if err := m.Add(prefix, via); err != nil {
		t.Fatalf("Add: %v", err)
	}

	m.mu.Lock()
	displaced := m.displaced[prefix]
	m.mu.Unlock()
	if displaced != nil {
		t.Errorf("displaced route remembered for gateway route on own TUN link, want nil")
	}
}

// TestAddDoesNotRememberSameGateway verifies that Add does not remember a
// route that has the same gateway (i.e., a stale veld route).
func TestAddDoesNotRememberSameGateway(t *testing.T) {
	h := &recordingHandle{
		listFiltered: []*netlink.Route{
			{
				Dst:      parseIPNet("10.99.77.0/24"),
				Gw:       net.ParseIP("10.198.18.3"), // same as veld's gateway
				Priority: DefaultRouteMetric,
				Table:    unix.RT_TABLE_MAIN,
			},
		},
	}
	m := newTestManager(h)

	prefix := netip.MustParsePrefix("10.99.77.0/24")
	via := netip.MustParseAddr("10.198.18.3")
	if err := m.Add(prefix, via); err != nil {
		t.Fatalf("Add: %v", err)
	}

	m.mu.Lock()
	displaced := m.displaced[prefix]
	m.mu.Unlock()
	if displaced != nil {
		t.Errorf("displaced route remembered for same gateway, want nil")
	}
}

// TestAddDoesNotRememberDifferentMetric verifies that Add does not remember a
// route at a different metric.
func TestAddDoesNotRememberDifferentMetric(t *testing.T) {
	h := &recordingHandle{
		listFiltered: []*netlink.Route{
			{
				Dst:      parseIPNet("10.99.77.0/24"),
				Gw:       net.ParseIP("10.198.18.2"),
				Priority: 600, // different metric
				Table:    unix.RT_TABLE_MAIN,
			},
		},
	}
	m := newTestManager(h)

	prefix := netip.MustParsePrefix("10.99.77.0/24")
	via := netip.MustParseAddr("10.198.18.3")
	if err := m.Add(prefix, via); err != nil {
		t.Fatalf("Add: %v", err)
	}

	m.mu.Lock()
	displaced := m.displaced[prefix]
	m.mu.Unlock()
	if displaced != nil {
		t.Errorf("displaced route remembered for different metric, want nil")
	}
}

// TestAddDoesNotRememberDisplacedRouteOnReplaceFailure verifies that if
// RouteReplace fails, the displaced route is not remembered.
func TestAddDoesNotRememberDisplacedRouteOnReplaceFailure(t *testing.T) {
	h := &recordingHandle{
		listFiltered: []*netlink.Route{
			{
				Dst:      parseIPNet("10.99.77.0/24"),
				Gw:       net.ParseIP("10.198.18.2"),
				Priority: DefaultRouteMetric,
				Table:    unix.RT_TABLE_MAIN,
			},
		},
		errReplace: errors.New("netlink: permission denied"),
	}
	m := newTestManager(h)

	prefix := netip.MustParsePrefix("10.99.77.0/24")
	via := netip.MustParseAddr("10.198.18.3")
	err := m.Add(prefix, via)
	if err == nil {
		t.Fatal("Add should have failed")
	}

	m.mu.Lock()
	displaced := m.displaced[prefix]
	m.mu.Unlock()
	if displaced != nil {
		t.Errorf("displaced route remembered despite Replace failure, want nil")
	}
	if len(m.routes) != 0 {
		t.Errorf("route tracked despite Replace failure")
	}
}

// TestAddIPv6RemembersDisplacedRoute verifies that Add remembers a displaced
// route for IPv6 prefixes (metric 1024).
func TestAddIPv6RemembersDisplacedRoute(t *testing.T) {
	h := &recordingHandle{
		listFiltered: []*netlink.Route{
			{
				Dst:       parseIPNet("fd00:1234::/64"),
				Gw:        net.ParseIP("fd00:1234::2"),
				LinkIndex: 5,
				Priority:  1024, // IP6_RT_PRIO_USER
				Table:     unix.RT_TABLE_MAIN,
			},
		},
	}
	m := newTestManager(h)

	prefix := netip.MustParsePrefix("fd00:1234::/64")
	via := netip.MustParseAddr("fd00:1234::3")
	if err := m.Add(prefix, via); err != nil {
		t.Fatalf("Add: %v", err)
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if h.listFilter == nil {
		t.Fatal("RouteListFiltered called with nil filter")
	}
	if h.listFilter.Priority != 1024 {
		t.Errorf("RouteListFiltered Priority = %d, want 1024 for IPv6", h.listFilter.Priority)
	}
	if h.listFilter.Table != unix.RT_TABLE_MAIN {
		t.Errorf("RouteListFiltered Table = %d, want %d", h.listFilter.Table, unix.RT_TABLE_MAIN)
	}

	m.mu.Lock()
	displaced := m.displaced[prefix]
	m.mu.Unlock()
	if displaced == nil {
		t.Fatal("displaced IPv6 route not remembered")
	}
	if displaced.Gw == nil || !displaced.Gw.Equal(net.ParseIP("fd00:1234::2")) {
		t.Errorf("displaced IPv6 route Gw = %v, want fd00:1234::2", displaced.Gw)
	}
}

// TestAddTwiceDifferentGatewayRemembersVPNRoute verifies that when Add is
// called twice for the same prefix with different gateways (VPN address
// change in coord mode, or multiple peers advertising the same subnet), the
// VPN route is remembered, not the first veld route.
func TestAddTwiceDifferentGatewayRemembersVPNRoute(t *testing.T) {
	// Scenario: VPN route at metric 0 exists. First Add with gateway A
	// installs veld's route, remembering the VPN route. Second Add with
	// gateway B (VPN address change) should still remember the VPN route,
	// not the first veld route (gateway A).
	h := &recordingHandle{
		listFiltered: []*netlink.Route{
			{
				Dst:       parseIPNet("10.99.77.0/24"),
				Gw:        net.ParseIP("10.198.18.2"), // VPN gateway
				LinkIndex: 5,
				Priority:  DefaultRouteMetric,
				Table:     unix.RT_TABLE_MAIN,
			},
		},
	}
	m := newTestManager(h)

	prefix := netip.MustParsePrefix("10.99.77.0/24")
	via1 := netip.MustParseAddr("10.198.18.3") // First veld gateway
	via2 := netip.MustParseAddr("10.198.18.4") // Second veld gateway (address change)

	// First Add: VPN route exists, should be remembered
	if err := m.Add(prefix, via1); err != nil {
		t.Fatalf("First Add: %v", err)
	}

	m.mu.Lock()
	displacedAfterFirst := m.displaced[prefix]
	m.mu.Unlock()
	if displacedAfterFirst == nil {
		t.Fatal("VPN route not remembered after first Add")
	}
	if displacedAfterFirst.Gw == nil || !displacedAfterFirst.Gw.Equal(net.ParseIP("10.198.18.2")) {
		t.Errorf("displaced after first Add: Gw = %v, want VPN 10.198.18.2", displacedAfterFirst.Gw)
	}

	// Second Add: now the kernel has the first veld route (via1) at the same prefix/metric.
	// The listFiltered should return both the VPN route and the first veld route.
	// We simulate this by updating listFiltered to include both.
	h.mu.Lock()
	h.listFiltered = []*netlink.Route{
		{
			Dst:       parseIPNet("10.99.77.0/24"),
			Gw:        net.ParseIP("10.198.18.2"), // VPN gateway
			LinkIndex: 5,
			Priority:  DefaultRouteMetric,
			Table:     unix.RT_TABLE_MAIN,
		},
		{
			Dst:       parseIPNet("10.99.77.0/24"),
			Gw:        net.ParseIP("10.198.18.3"), // First veld gateway (stale)
			LinkIndex: 10,                         // Different link
			Priority:  DefaultRouteMetric,
			Table:     unix.RT_TABLE_MAIN,
		},
	}
	h.mu.Unlock()

	if err := m.Add(prefix, via2); err != nil {
		t.Fatalf("Second Add: %v", err)
	}

	m.mu.Lock()
	displacedAfterSecond := m.displaced[prefix]
	m.mu.Unlock()

	// The displaced route should still be the VPN route (10.198.18.2),
	// NOT the first veld route (10.198.18.3).
	if displacedAfterSecond == nil {
		t.Fatal("displaced route not remembered after second Add")
	}
	if displacedAfterSecond.Gw == nil {
		t.Fatal("displaced route after second Add has no gateway")
	}
	if displacedAfterSecond.Gw.Equal(net.ParseIP("10.198.18.3")) {
		t.Errorf("BUG: Second Add remembered OLD veld route (10.198.18.3) as displaced instead of VPN route!")
	}
	if !displacedAfterSecond.Gw.Equal(net.ParseIP("10.198.18.2")) {
		t.Errorf("displaced after second Add: Gw = %v, want VPN 10.198.18.2", displacedAfterSecond.Gw)
	}
}

// TestRemoveRestoresDisplacedRoute verifies that Remove re-adds the
// displaced route via RouteAdd.
func TestRemoveRestoresDisplacedRoute(t *testing.T) {
	h := &recordingHandle{
		listFiltered: []*netlink.Route{
			{
				Dst:       parseIPNet("10.99.77.0/24"),
				Gw:        net.ParseIP("10.198.18.2"),
				LinkIndex: 5,
				Priority:  DefaultRouteMetric,
				Table:     unix.RT_TABLE_MAIN,
			},
		},
	}
	m := newTestManager(h)

	prefix := netip.MustParsePrefix("10.99.77.0/24")
	via := netip.MustParseAddr("10.198.18.3")
	if err := m.Add(prefix, via); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := m.Remove(prefix); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.added) != 1 {
		t.Fatalf("expected 1 RouteAdd call for restoration, got %d", len(h.added))
	}
	r := h.added[0]
	if r.Dst == nil || r.Dst.String() != "10.99.77.0/24" {
		t.Errorf("restored route Dst = %v, want 10.99.77.0/24", r.Dst)
	}
	if r.Gw == nil || !r.Gw.Equal(net.ParseIP("10.198.18.2")) {
		t.Errorf("restored route Gw = %v, want 10.198.18.2", r.Gw)
	}
	if r.LinkIndex != 5 {
		t.Errorf("restored route LinkIndex = %d, want 5", r.LinkIndex)
	}
	if r.Priority != DefaultRouteMetric {
		t.Errorf("restored route Priority = %d, want %d", r.Priority, DefaultRouteMetric)
	}
}

// TestRemoveRestoresDisplacedRouteLogsOnError verifies that Remove logs and
// continues if restoring the displaced route fails (e.g., EEXIST).
func TestRemoveRestoresDisplacedRouteLogsOnError(t *testing.T) {
	h := &recordingHandle{
		listFiltered: []*netlink.Route{
			{
				Dst:      parseIPNet("10.99.77.0/24"),
				Gw:       net.ParseIP("10.198.18.2"),
				Priority: DefaultRouteMetric,
				Table:    unix.RT_TABLE_MAIN,
			},
		},
		errAdd: errors.New("EEXIST"), // RouteAdd fails
	}
	m := newTestManager(h)

	prefix := netip.MustParsePrefix("10.99.77.0/24")
	via := netip.MustParseAddr("10.198.18.3")
	if err := m.Add(prefix, via); err != nil {
		t.Fatalf("Add: %v", err)
	}
	// Remove should not return an error even if restoration fails
	if err := m.Remove(prefix); err != nil {
		t.Fatalf("Remove should not error on restoration failure: %v", err)
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.added) != 1 {
		t.Fatalf("expected 1 RouteAdd call for restoration, got %d", len(h.added))
	}
}

// TestCloseRestoresDisplacedRoute verifies that Close restores all
// displaced routes.
func TestCloseRestoresDisplacedRoute(t *testing.T) {
	h := &recordingHandle{
		listFiltered: []*netlink.Route{
			{
				Dst:      parseIPNet("10.99.77.0/24"),
				Gw:       net.ParseIP("10.198.18.2"),
				Priority: DefaultRouteMetric,
				Table:    unix.RT_TABLE_MAIN,
			},
			{
				Dst:      parseIPNet("10.88.66.0/24"),
				Gw:       net.ParseIP("10.198.18.5"),
				Priority: DefaultRouteMetric,
				Table:    unix.RT_TABLE_MAIN,
			},
		},
	}
	m := newTestManager(h)

	prefixes := []netip.Prefix{
		netip.MustParsePrefix("10.99.77.0/24"),
		netip.MustParsePrefix("10.88.66.0/24"),
	}
	for _, p := range prefixes {
		if err := m.Add(p, netip.MustParseAddr("10.198.18.3")); err != nil {
			t.Fatalf("Add %s: %v", p, err)
		}
	}
	if err := m.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.added) != 2 {
		t.Fatalf("expected 2 RouteAdd calls for restoration, got %d", len(h.added))
	}
	restored := map[string]bool{}
	for _, r := range h.added {
		restored[r.Dst.String()] = true
	}
	for _, p := range prefixes {
		if !restored[p.String()] {
			t.Errorf("route %s not restored by Close", p)
		}
	}
}

func parseIPNet(s string) *net.IPNet {
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return ipnet
}

// ipNetEqual compares two IPNets for equality.
func ipNetEqual(a, b *net.IPNet) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.IP.Equal(b.IP) && a.Mask.String() == b.Mask.String()
}
