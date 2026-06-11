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

// New returns a route manager backed by netlink on Linux.
func New() Manager {
	return &linuxManager{routes: make(map[netip.Prefix]struct{})}
}

// EnableIPForward writes "1" to /proc/sys/net/ipv4/ip_forward.
// Should be called when this node is advertising subnet routes.
func EnableIPForward() error {
	return os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0644)
}

type linuxManager struct {
	mu     sync.Mutex
	routes map[netip.Prefix]struct{}
}

func (m *linuxManager) Add(prefix netip.Prefix, via netip.Addr) error {
	dst := prefixToIPNet(prefix)
	gw := net.IP(via.AsSlice())

	if err := netlink.RouteAdd(&netlink.Route{Dst: dst, Gw: gw}); err != nil {
		// EEXIST is benign: route already present (e.g., from a previous run).
		if isExist(err) {
			// Replace the existing route to update the gateway.
			if rerr := netlink.RouteReplace(&netlink.Route{Dst: dst, Gw: gw}); rerr != nil {
				return fmt.Errorf("route replace %s via %s: %w", prefix, via, rerr)
			}
		} else {
			return fmt.Errorf("route add %s via %s: %w", prefix, via, err)
		}
	}

	m.mu.Lock()
	m.routes[prefix] = struct{}{}
	m.mu.Unlock()
	return nil
}

func (m *linuxManager) Remove(prefix netip.Prefix) error {
	dst := prefixToIPNet(prefix)
	if err := netlink.RouteDel(&netlink.Route{Dst: dst}); err != nil && !isNotExist(err) {
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

func isExist(err error) bool {
	return err != nil && err.Error() == "file exists"
}

func isNotExist(err error) bool {
	return err != nil && err.Error() == "no such process"
}
