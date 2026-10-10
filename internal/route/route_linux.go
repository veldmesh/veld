// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
//go:build linux

package route

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"

	"github.com/vishvananda/netlink"
)

// DefaultRouteMetric is the kernel route metric Veldmesh installs on its
// routes. Linux breaks equal-prefix ties by preferring the lowest metric, so
// 0 keeps Veldmesh's mesh/subnet routes ahead of commercial VPN routes that
// carry a higher metric — regardless of which side connected first.
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
	return &linuxManager{routes: make(map[netip.Prefix]struct{}), h: h}
}

// EnableIPForward writes "1" to /proc/sys/net/ipv4/ip_forward.
// Should be called when this node is advertising subnet routes.
func EnableIPForward() error {
	return os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0644)
}

type linuxManager struct {
	mu     sync.Mutex
	routes map[netip.Prefix]struct{}
	h      routeHandle
}

func (m *linuxManager) Add(prefix netip.Prefix, via netip.Addr) error {
	dst := prefixToIPNet(prefix)
	gw := net.IP(via.AsSlice())

	// Replace, not add: if a commercial VPN already installed a route for
	// this prefix (VPN connected first), veld takes the prefix over; if the
	// VPN displaced veld's route later (veld connected first), a re-add
	// heals it. The low metric wins equal-prefix ties in both directions.
	if err := m.h.RouteReplace(&netlink.Route{Dst: dst, Gw: gw, Priority: DefaultRouteMetric}); err != nil {
		return fmt.Errorf("route replace %s via %s: %w", prefix, via, err)
	}

	m.mu.Lock()
	m.routes[prefix] = struct{}{}
	m.mu.Unlock()
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
