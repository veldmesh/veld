// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT

//go:build darwin

package coexist

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"
)

// Observe gathers links and routes on macOS by combining net.Interfaces
// (for link names and addresses) with `netstat -rn` parsing (for routes).
// This enables VPN detection and CIDR collision checks on macOS.
func Observe() (Snapshot, error) {
	links, err := gatherLinks()
	if err != nil {
		return Snapshot{}, fmt.Errorf("list interfaces: %w", err)
	}

	routes, err := gatherRoutes()
	if err != nil {
		// Route gathering is best-effort; log and continue with links only.
		return Snapshot{Links: links}, fmt.Errorf("list routes: %w", err)
	}

	return Snapshot{Links: links, Routes: routes}, nil
}

// gatherLinks enumerates network interfaces via net.Interfaces (stdlib).
// On macOS, this returns names like "en0", "utun0", "wg0", etc.
func gatherLinks() ([]Link, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	links := make([]Link, 0, len(ifaces))
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
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

// gatherRoutes parses `netstat -rn` output for both IPv4 and IPv6.
// Sample output:
//
//	Routing tables
//
//	Internet:
//	Destination        Gateway            Flags        Netif Expire
//	default            192.168.1.1        UGSc           en0
//	10.100.0/24        10.100.0.1         UGSc          utun0
//	127                127.0.0.1          UCS            lo0
//
//	Internet6:
//	Destination        Gateway            Flags         Netif Expire
//	default            fe80::1%en0         UGcI           en0
//	fd00::/8           fd00::1             UGcI          utun0
func gatherRoutes() ([]RouteEntry, error) {
	cmd := exec.Command("netstat", "-rn")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("netstat -rn: %w", err)
	}

	routes, err := parseDarwinNetstat(string(out))
	if err != nil {
		return nil, fmt.Errorf("parse netstat: %w", err)
	}

	return routes, nil
}
