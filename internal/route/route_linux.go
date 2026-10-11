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
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// DefaultRouteMetric is the metric Veldmesh asks the kernel for on its
// routes. Linux prefers the lowest metric among distinct equal-prefix
// routes, so on IPv4 metric 0 keeps Veldmesh's mesh/subnet routes ahead of
// commercial VPN routes that carry a higher metric. IPv6 has no metric 0:
// the kernel coerces it to 1024 (IP6_RT_PRIO_USER) on install, so veld has
// no metric advantage there. Order-independence against a VPN claiming the
// same prefix comes from the replace-on-conflict install in Add, not from
// this metric.
const DefaultRouteMetric = 0

// healInterval is how often the background goroutine checks whether
// Veldmesh routes are still present and correct. If a commercial VPN
// displaces a route (e.g. on VPN reconnect), the next heal cycle will
// reinstall it.
const healInterval = 30 * time.Second

// routeHandle is the netlink write surface used by the manager. The seam
// exists so tests can verify exactly what veld asks the kernel to do.
type routeHandle interface {
	RouteReplace(route *netlink.Route) error
	RouteDel(route *netlink.Route) error
	RouteList(link netlink.Link, family int) ([]netlink.Route, error)
	RouteListFiltered(family int, filter *netlink.Route, filterMask uint64) ([]netlink.Route, error)
}

// systemHandle routes operations to the real netlink API.
type systemHandle struct{}

func (systemHandle) RouteReplace(r *netlink.Route) error { return netlink.RouteReplace(r) }
func (systemHandle) RouteDel(r *netlink.Route) error     { return netlink.RouteDel(r) }
func (systemHandle) RouteList(link netlink.Link, family int) ([]netlink.Route, error) {
	return netlink.RouteList(link, family)
}
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
		h:         h,
		healStop:  make(chan struct{}),
		healStart: sync.Once{},
	}
}

// EnableIPForward writes "1" to /proc/sys/net/ipv4/ip_forward.
// Should be called when this node is advertising subnet routes.
func EnableIPForward() error {
	return os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0644)
}

type linuxManager struct {
	mu        sync.Mutex
	routes    map[netip.Prefix]netip.Addr // prefix -> expected gateway
	h         routeHandle
	healStop  chan struct{}
	healStart sync.Once
}

func (m *linuxManager) Add(prefix netip.Prefix, via netip.Addr) error {
	dst := prefixToIPNet(prefix)
	gw := net.IP(via.AsSlice())

	// Replace, not add: if a commercial VPN already installed a route for
	// this prefix (VPN connected first), veld takes the prefix over; if the
	// VPN displaced veld's route later (veld connected first), the next
	// Add — a peer rejoin or daemon restart — heals it. That
	// replace-on-conflict is what makes the install order-independent.
	// When both sides instead hold routes with different metrics, the lower
	// metric wins — on IPv4 that is veld's metric-0 route.
	if err := m.h.RouteReplace(&netlink.Route{Dst: dst, Gw: gw, Priority: DefaultRouteMetric}); err != nil {
		return fmt.Errorf("route replace %s via %s: %w", prefix, via, err)
	}

	m.mu.Lock()
	m.routes[prefix] = via
	m.mu.Unlock()

	// Start the background heal loop on the first route added.
	m.healStart.Do(m.startHeal)
	return nil
}

func (m *linuxManager) Remove(prefix netip.Prefix) error {
	dst := prefixToIPNet(prefix)
	if err := m.h.RouteDel(&netlink.Route{Dst: dst}); err != nil && !isNotExist(err) {
		return fmt.Errorf("route del %s: %w", prefix, err)
	}

	m.mu.Lock()
	delete(m.routes, prefix)
	m.mu.Unlock()
	return nil
}

func (m *linuxManager) Close() error {
	// Stop the heal loop.
	close(m.healStop)

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

// startHeal launches the background goroutine that periodically verifies
// Veldmesh routes are still present with the correct gateway and metric.
func (m *linuxManager) startHeal() {
	go m.healLoop()
}

func (m *linuxManager) healLoop() {
	ticker := time.NewTicker(healInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.healStop:
			return
		case <-ticker.C:
			m.heal()
		}
	}
}

// heal checks all tracked routes against the kernel's routing table and
// reinstalls any that are missing or have the wrong gateway/metric.
// It checks both IPv4 and IPv6 routes from ALL routing tables (like Observe does),
// not just the main table, because VPNs like wg-quick, Mullvad, NordLynx,
// and Tailscale install routes in dedicated policy tables.
func (m *linuxManager) heal() {
	m.mu.Lock()
	// Snapshot the current tracked routes.
	tracked := make(map[netip.Prefix]netip.Addr, len(m.routes))
	for p, gw := range m.routes {
		tracked[p] = gw
	}
	m.mu.Unlock()

	if len(tracked) == 0 {
		return
	}

	// Get all routes from all tables for both IPv4 and IPv6.
	// Use RT_TABLE_UNSPEC to dump every table (not just main).
	filter := &netlink.Route{Table: unix.RT_TABLE_UNSPEC}
	routesV4, err := m.h.RouteListFiltered(netlink.FAMILY_V4, filter, netlink.RT_FILTER_TABLE)
	if err != nil {
		log.Printf("veld: route heal: failed to list IPv4 routes: %v", err)
		return
	}
	routesV6, err := m.h.RouteListFiltered(netlink.FAMILY_V6, filter, netlink.RT_FILTER_TABLE)
	if err != nil {
		log.Printf("veld: route heal: failed to list IPv6 routes: %v", err)
		return
	}
	routes := append(routesV4, routesV6...)

	// Build a map of kernel routes by destination prefix.
	kernelRoutes := make(map[string]*netlink.Route)
	for i := range routes {
		if routes[i].Dst != nil {
			kernelRoutes[routes[i].Dst.String()] = &routes[i]
		}
	}

	// Check each tracked route.
	for prefix, expectedGw := range tracked {
		dstStr := prefix.String()
		kr, ok := kernelRoutes[dstStr]
		if !ok {
			// Route is missing entirely — reinstall.
			m.reinstall(prefix, expectedGw)
			continue
		}
		// Route exists; verify gateway and metric.
		if !kr.Gw.Equal(expectedGw.AsSlice()) || kr.Priority != DefaultRouteMetric {
			m.reinstall(prefix, expectedGw)
		}
	}
}

func (m *linuxManager) reinstall(prefix netip.Prefix, via netip.Addr) {
	dst := prefixToIPNet(prefix)
	gw := net.IP(via.AsSlice())
	if err := m.h.RouteReplace(&netlink.Route{Dst: dst, Gw: gw, Priority: DefaultRouteMetric}); err != nil {
		log.Printf("veld: route heal: failed to reinstall %s via %s: %v", prefix, via, err)
		return
	}
	log.Printf("veld: coexist: healed route %s (was displaced by VPN)", prefix)
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
