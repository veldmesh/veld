// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT

//go:build linux

package coexist

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
)

// Observe gathers links and main-table routes via netlink. Both are
// read-only dumps and work unprivileged.
func Observe() (Snapshot, error) {
	nlLinks, err := netlink.LinkList()
	if err != nil {
		return Snapshot{}, fmt.Errorf("list links: %w", err)
	}

	links := make([]Link, 0, len(nlLinks))
	idx := make(map[int]string, len(nlLinks))
	for _, l := range nlLinks {
		attrs := l.Attrs()
		idx[attrs.Index] = attrs.Name

		addrs, err := netlink.AddrList(l, netlink.FAMILY_ALL)
		if err != nil {
			// A single unlistable interface must not abort the snapshot.
			continue
		}
		pfxs := make([]netip.Prefix, 0, len(addrs))
		for _, a := range addrs {
			if p, ok := ipNetToPrefix(a.IPNet); ok {
				pfxs = append(pfxs, p)
			}
		}
		links = append(links, Link{Name: attrs.Name, Kind: l.Type(), Addrs: pfxs})
	}

	nlRoutes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return Snapshot{Links: links}, fmt.Errorf("list routes: %w", err)
	}
	routes := make([]RouteEntry, 0, len(nlRoutes))
	for _, r := range nlRoutes {
		var dst netip.Prefix
		if r.Dst != nil {
			p, ok := ipNetToPrefix(r.Dst)
			if !ok {
				continue
			}
			dst = p
		} else if r.Gw != nil && r.Gw.To4() == nil {
			// No destination with an IPv6 gateway: the IPv6 default route.
			dst = netip.MustParsePrefix("::/0")
		} else {
			dst = netip.MustParsePrefix("0.0.0.0/0")
		}

		var gw netip.Addr
		if r.Gw != nil {
			gw, _ = netip.AddrFromSlice(r.Gw)
		}

		routes = append(routes, RouteEntry{
			Dst:    dst,
			Gw:     gw,
			Iface:  idx[r.LinkIndex],
			Metric: r.Priority,
		})
	}

	return Snapshot{Links: links, Routes: routes}, nil
}

// ipNetToPrefix converts a netlink IPNet to a netip.Prefix.
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
