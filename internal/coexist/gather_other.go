// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT

//go:build !linux && !windows && !darwin

package coexist

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
)

// Observe gathers the host's network interfaces and routes. On non-Linux,
// non-Windows, non-macOS platforms (e.g. the BSDs, Solaris) the stdlib
// enumerates interfaces and `netstat -rn` provides routes. The netstat
// column layout differs across these systems (OpenBSD appends Refs/Use/
// Mtu/Prio columns; the BSDs put a sometimes-empty Expire last), so routes
// are parsed by field position for destination/gateway and the egress
// interface is identified by matching a known link name anywhere in the
// line — the one token whose format every variant shares.
func Observe() (Snapshot, error) {
	links, err := gatherLinks()
	if err != nil {
		return Snapshot{}, fmt.Errorf("list interfaces: %w", err)
	}

	routes, err := gatherRoutes(links)
	if err != nil {
		// Route gathering is best-effort; continue with links only so
		// interface-name VPN detection still works.
		return Snapshot{Links: links}, fmt.Errorf("list routes: %w", err)
	}

	return Snapshot{Links: links, Routes: routes}, nil
}

// gatherLinks enumerates network interfaces via net.Interfaces (stdlib).
func gatherLinks() ([]Link, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
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
			if ipnet, ok := a.(*net.IPNet); ok {
				if p, ok := ipNetToPrefix(ipnet); ok {
					pfxs = append(pfxs, p)
				}
			}
		}
		links = append(links, Link{Name: i.Name, Addrs: pfxs})
	}
	return links, nil
}

// gatherRoutes parses `netstat -rn` output. Sample (FreeBSD):
//
//	Routing tables
//
//	Internet:
//	Destination        Gateway            Flags     Netif Expire
//	default            192.168.1.1        UGS         em0
//	10.100.0.0/24      10.100.0.1         UGS        tun0
//
//	Internet6:
//	Destination        Gateway            Flags     Netif Expire
//	default            fe80::1%em0        UGS         em0
//	fd00::/8           link#2             UGS        tun0
func gatherRoutes(links []Link) ([]RouteEntry, error) {
	cmd := exec.Command("netstat", "-rn")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("netstat -rn: %w", err)
	}

	// Known interface names, longest first so e.g. "em0" is preferred over
	// a shorter name that also appears in the line.
	names := make([]string, 0, len(links))
	for _, l := range links {
		if l.Name != "" {
			names = append(names, l.Name)
		}
	}
	sortStringsByLenDesc(names)

	var routes []RouteEntry
	famIPv6 := false

	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "Internet:"):
			famIPv6 = false
			continue
		case strings.HasPrefix(line, "Internet6:"):
			famIPv6 = true
			continue
		case line == "" || strings.HasPrefix(line, "Routing") || strings.HasPrefix(line, "Destination"):
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		dst, err := ParseNetstatDst(fields[0], famIPv6)
		if err != nil {
			continue
		}

		// The gateway is always the second field. Link-level gateways
		// ("link#2") and interface references are not next hops.
		var gw netip.Addr
		if !strings.HasPrefix(fields[1], "link#") && fields[1] != "iface" {
			if addr, err := netip.ParseAddr(strings.SplitN(fields[1], "%", 2)[0]); err == nil {
				gw = addr
			}
		}

		// The egress interface is the known link name present in the line;
		// no netstat variant puts a routable value in a fixed column that
		// also works on the others. These systems do not expose a route
		// metric in netstat output, so the field stays zero.
		routes = append(routes, RouteEntry{
			Dst:   dst,
			Gw:    gw,
			Iface: matchIfaceName(line, names),
			Table: 254,
		})
	}

	return routes, nil
}

// matchIfaceName returns the first known interface name that occurs as a
// standalone token in the netstat line, or "" when none matches.
func matchIfaceName(line string, sortedNames []string) string {
	for _, name := range sortedNames {
		for _, f := range strings.Fields(line) {
			if f == name {
				return name
			}
		}
	}
	return ""
}

// sortStringsByLenDesc sorts names longest-first in place with a simple
// insertion sort — the lists are tiny (interface counts).
func sortStringsByLenDesc(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && len(s[j]) > len(s[j-1]); j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
