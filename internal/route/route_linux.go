// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
//go:build linux

package route

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// DefaultRouteMetric is the metric Veldmesh asks the kernel for on its
// routes: 0, the value the kernel would use for an unqualified route add,
// made explicit. A VPN route for the same prefix at a higher metric is not
// displaced; the kernel prefers the lowest metric, so veld's route wins while
// it is installed. (On IPv6 the kernel coerces metric 0 to 1024,
// IP6_RT_PRIO_USER, on install.)
const DefaultRouteMetric = 0

// routeHandle is the netlink write surface used by the manager. The seam
// exists so tests can verify exactly what veld asks the kernel to do.
type routeHandle interface {
	RouteReplace(route *netlink.Route) error
	RouteAdd(route *netlink.Route) error
	RouteDel(route *netlink.Route) error
	RouteListFiltered(family int, filter *netlink.Route, filterMask uint64) ([]netlink.Route, error)
}

// systemHandle routes operations to the real netlink API.
type systemHandle struct{}

func (systemHandle) RouteReplace(r *netlink.Route) error { return netlink.RouteReplace(r) }
func (systemHandle) RouteAdd(r *netlink.Route) error     { return netlink.RouteAdd(r) }
func (systemHandle) RouteDel(r *netlink.Route) error     { return netlink.RouteDel(r) }
func (systemHandle) RouteListFiltered(family int, filter *netlink.Route, filterMask uint64) ([]netlink.Route, error) {
	return netlink.RouteListFiltered(family, filter, filterMask)
}

// New returns a route manager backed by netlink on Linux.
func New() Manager {
	return newLinuxManager(systemHandle{})
}

func newLinuxManager(h routeHandle) *linuxManager {
	return &linuxManager{
		routes:    make(map[netip.Prefix]netip.Addr),
		displaced: make(map[netip.Prefix]*netlink.Route),
		h:         h,
	}
}

// ipForwardPath is a variable so tests can point it at a file.
var ipForwardPath = "/proc/sys/net/ipv4/ip_forward"

// EnableIPForward turns on IPv4 forwarding, which a node advertising subnet
// routes needs. It returns a function that restores the previous setting;
// forwarding is a host-wide switch, and leaving it on after veld stops would
// silently turn the host into a router for its other interfaces.
func EnableIPForward() (restore func() error, err error) {
	prev, err := os.ReadFile(ipForwardPath)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(string(prev)) == "1" {
		return func() error { return nil }, nil
	}
	if err := os.WriteFile(ipForwardPath, []byte("1\n"), 0644); err != nil {
		return nil, err
	}
	return func() error { return os.WriteFile(ipForwardPath, prev, 0644) }, nil
}

type linuxManager struct {
	mu        sync.Mutex
	routes    map[netip.Prefix]netip.Addr     // installed prefix -> gateway
	displaced map[netip.Prefix]*netlink.Route // prefix -> original route displaced by veld
	h         routeHandle
	tunLink   int // link index of veld's TUN interface (0 if unknown)
}

// SetTUNLink records the link index of veld's TUN interface. Device routes
// on this link are considered veld's own and will not be treated as displaced
// VPN routes. This is called after the TUN device is created.
func (m *linuxManager) SetTUNLink(linkIndex int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tunLink = linkIndex
}

func (m *linuxManager) Add(prefix netip.Prefix, via netip.Addr) error {
	dst := prefixToIPNet(prefix)
	gw := net.IP(via.AsSlice())

	// Before installing our route, look for an existing route with the same
	// destination, metric, and table (main) that is not veld's (different
	// gateway or device route on a different link). Remember it so we can
	// restore it on Close/Remove.
	//
	// If we already have a route for this prefix, pass the EXISTING gateway
	// so findDisplacedRoute can skip it (it's our stale route, not a VPN route).
	existingVia, haveRoute := m.getRouteGateway(prefix)
	displaced := m.findDisplacedRoute(dst, via, existingVia, haveRoute)

	// Replace, not add, so a stale route veld left at the same prefix and
	// metric is overwritten instead of failing with "file exists". The kernel
	// matches a replace on prefix, TOS and metric only: a VPN route at another
	// metric is left in place and outranked by this one, and is still there
	// after Close. A VPN route at the same metric is displaced, and is
	// restored on Close.
	if err := m.h.RouteReplace(&netlink.Route{Dst: dst, Gw: gw, Priority: DefaultRouteMetric}); err != nil {
		return fmt.Errorf("route replace %s via %s: %w", prefix, via, err)
	}

	// After successful install, store the displaced route if we found one.
	if displaced != nil {
		m.mu.Lock()
		m.displaced[prefix] = displaced
		m.mu.Unlock()
	}

	m.mu.Lock()
	m.routes[prefix] = via
	m.mu.Unlock()
	return nil
}

// getRouteGateway returns the currently tracked gateway for prefix and whether
// a route exists.
func (m *linuxManager) getRouteGateway(prefix netip.Prefix) (netip.Addr, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	via, ok := m.routes[prefix]
	return via, ok
}

// findDisplacedRoute looks for an existing route with the same destination,
// metric, and table (main) that is not veld's. Returns the route if found,
// nil otherwise.
//
// A route is considered "not veld's" if:
//   - It has a gateway and the gateway differs from veld's NEW gateway AND
//     (if we have an existing route) also differs from veld's EXISTING gateway,
//     AND its link index (if non-zero) is not veld's TUN link.
//   - It has no gateway (device route) and its link index differs from the
//     link index of veld's TUN interface (if known). If the TUN link is not
//     yet known, we remember any device route at this prefix/metric that has
//     a link index; the integration test uses a dummy link to simulate a VPN
//     tunnel, so this correctly identifies it as foreign.
//
// For IPv6, the kernel stores metric 0 as 1024 (IP6_RT_PRIO_USER), so we
// match that metric for IPv6 prefixes.
func (m *linuxManager) findDisplacedRoute(dst *net.IPNet, newVia, existingVia netip.Addr, haveExisting bool) *netlink.Route {
	family := netlink.FAMILY_V4
	metric := DefaultRouteMetric
	if dst.IP.To4() == nil {
		family = netlink.FAMILY_V6
		metric = 1024 // IP6_RT_PRIO_USER: kernel coercion of metric 0 for IPv6
	}

	filter := &netlink.Route{
		Dst:      dst,
		Priority: metric,
		Table:    unix.RT_TABLE_MAIN,
	}
	filterMask := netlink.RT_FILTER_DST | netlink.RT_FILTER_PRIORITY | netlink.RT_FILTER_TABLE

	routes, err := m.h.RouteListFiltered(family, filter, filterMask)
	if err != nil {
		// On error, proceed without restoring — the route will just be displaced.
		return nil
	}

	newGw := net.IP(newVia.AsSlice())
	var existingGw net.IP
	if haveExisting {
		existingGw = net.IP(existingVia.AsSlice())
	}

	m.mu.Lock()
	tunLink := m.tunLink
	m.mu.Unlock()

	for _, r := range routes {
		if r.Gw != nil {
			// Gateway route: foreign if gateway differs from both new and existing veld gateways,
			// AND (if tunLink is known) the route's link index is not veld's TUN link.
			if !r.Gw.Equal(newGw) && (!haveExisting || !r.Gw.Equal(existingGw)) {
				if tunLink != 0 && r.LinkIndex == tunLink {
					// Gateway route on veld's own TUN link — this is ours (stale from
					// a previous run or address change), don't remember it.
					continue
				}
				return &r
			}
			// Same gateway as new or existing — this is a veld route (stale or current), don't remember it.
			continue
		}
		// Device route (no gateway): foreign if it has a link index
		// that is not veld's TUN link.
		if r.LinkIndex != 0 && r.LinkIndex != tunLink {
			return &r
		}
		// Device route on veld's own TUN link — this is ours (stale from
		// a previous run), don't remember it.
	}
	return nil
}

func (m *linuxManager) Remove(prefix netip.Prefix) error {
	m.mu.Lock()
	via, ok := m.routes[prefix]
	displacedRoute := m.displaced[prefix]
	m.mu.Unlock()

	if !ok {
		return nil
	}

	// Match the gateway too, so a route someone else installed for the same
	// prefix after ours (a VPN reconnecting) is left alone.
	dst := prefixToIPNet(prefix)
	if err := m.h.RouteDel(&netlink.Route{Dst: dst, Gw: net.IP(via.AsSlice())}); err != nil && !isNotExist(err) {
		return fmt.Errorf("route del %s: %w", prefix, err)
	}

	// Restore the displaced route if we remembered one.
	if displacedRoute != nil {
		m.restoreDisplacedRoute(displacedRoute)
	}

	m.mu.Lock()
	delete(m.routes, prefix)
	delete(m.displaced, prefix)
	m.mu.Unlock()
	return nil
}

// restoreDisplacedRoute re-adds a route that was displaced by veld. Uses
// RouteAdd (not Replace) so we don't overwrite a route the other VPN may have
// already reinstalled. Logs and continues on failure (EEXIST is expected if
// the other VPN already put its route back).
func (m *linuxManager) restoreDisplacedRoute(r *netlink.Route) {
	// Clear fields that RouteAdd doesn't need or that would cause it to fail
	// if the kernel already has a matching route.
	clone := *r
	clone.Priority = DefaultRouteMetric // ensure metric is explicit
	if err := m.h.RouteAdd(&clone); err != nil {
		// EEXIST means the other VPN already reinstalled its route — that's fine.
		// Any other error is logged but not propagated; Close/Remove must not fail
		// just because restoration failed.
		log.Printf("route: failed to restore displaced route for %s: %v", r.Dst, err)
	}
}

func (m *linuxManager) Close() error {
	m.mu.Lock()
	prefixes := make([]netip.Prefix, 0, len(m.routes))
	for p := range m.routes {
		prefixes = append(prefixes, p)
	}
	m.mu.Unlock()

	var last error
	for _, p := range prefixes {
		if err := m.Remove(p); err != nil {
			last = err
		}
	}
	return last
}

func prefixToIPNet(p netip.Prefix) *net.IPNet {
	bits := p.Bits()
	addr := p.Masked().Addr()
	var ip net.IP
	if addr.Is4() {
		b4 := addr.As4()
		ip = b4[:]
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, 32)}
	}
	b16 := addr.As16()
	ip = b16[:]
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, 128)}
}

func isNotExist(err error) bool {
	return err != nil && err.Error() == "no such process"
}
