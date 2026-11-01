// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
//go:build linux

package route

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"

	"github.com/vishvananda/netlink"
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
	RouteDel(route *netlink.Route) error
}

// systemHandle routes operations to the real netlink API.
type systemHandle struct{}

func (systemHandle) RouteReplace(r *netlink.Route) error { return netlink.RouteReplace(r) }
func (systemHandle) RouteDel(r *netlink.Route) error     { return netlink.RouteDel(r) }

// New returns a route manager backed by netlink on Linux.
func New() Manager {
	return newLinuxManager(systemHandle{})
}

func newLinuxManager(h routeHandle) *linuxManager {
	return &linuxManager{routes: make(map[netip.Prefix]netip.Addr), h: h}
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
	mu     sync.Mutex
	routes map[netip.Prefix]netip.Addr // installed prefix -> gateway
	h      routeHandle
}

func (m *linuxManager) Add(prefix netip.Prefix, via netip.Addr) error {
	dst := prefixToIPNet(prefix)
	gw := net.IP(via.AsSlice())

	// Replace, not add, so a stale route veld left at the same prefix and
	// metric is overwritten instead of failing with "file exists". The kernel
	// matches a replace on prefix, TOS and metric only: a VPN route at another
	// metric is left in place and outranked by this one, and is still there
	// after Close. A VPN route at the same metric is displaced, and is not
	// restored on Close. There is no background route watcher; restart veld if
	// peers become unreachable after a VPN reconnects.
	if err := m.h.RouteReplace(&netlink.Route{Dst: dst, Gw: gw, Priority: DefaultRouteMetric}); err != nil {
		return fmt.Errorf("route replace %s via %s: %w", prefix, via, err)
	}

	m.mu.Lock()
	m.routes[prefix] = via
	m.mu.Unlock()
	return nil
}

func (m *linuxManager) Remove(prefix netip.Prefix) error {
	m.mu.Lock()
	via, ok := m.routes[prefix]
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

	m.mu.Lock()
	delete(m.routes, prefix)
	m.mu.Unlock()
	return nil
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
