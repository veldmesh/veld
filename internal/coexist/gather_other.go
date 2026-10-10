// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT

//go:build !linux

package coexist

import (
	"fmt"
	"net"
	"net/netip"
)

// Observe gathers the host's network interfaces. On non-Linux platforms
// there is no portable routing-table API inside the Go standard library, so
// only interface names and addresses are collected; VPN detection by
// interface name (nordlynx, mullvad, utun*, wg*, ...) still works, and
// collision detection reports nothing rather than guessing.
func Observe() (Snapshot, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return Snapshot{}, fmt.Errorf("list interfaces: %w", err)
	}

	links := make([]Link, 0, len(ifaces))
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			// A single unreadable interface must not abort the snapshot.
			continue
		}
		pfxs := make([]netip.Prefix, 0, len(addrs))
		for _, a := range addrs {
			var ipnet *net.IPNet
			switch v := a.(type) {
			case *net.IPNet:
				ipnet = v
			case *net.IPAddr:
				ipnet = &net.IPNet{IP: v.IP, Mask: net.CIDRMask(maskBits(v.IP), maskBits(v.IP))}
			}
			if p, ok := ipNetToPrefix(ipnet); ok {
				pfxs = append(pfxs, p)
			}
		}
		links = append(links, Link{Name: i.Name, Addrs: pfxs})
	}

	return Snapshot{Links: links}, nil
}

// maskBits returns the bit length of an IP (32 for IPv4, 128 for IPv6).
func maskBits(ip net.IP) int {
	if ip.To4() != nil {
		return 32
	}
	return 128
}

// ipNetToPrefix converts a net.IPNet to a netip.Prefix.
func ipNetToPrefix(n *net.IPNet) (netip.Prefix, bool) {
	if n == nil || n.IP == nil || n.Mask == nil {
		return netip.Prefix{}, false
	}
	ones, _ := n.Mask.Size()
	ip := n.IP.To4()
	if ip == nil {
		ip = n.IP
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok || !addr.IsValid() {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(addr, ones), true
}
