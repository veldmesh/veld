// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT

//go:build windows

package coexist

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
)

// Observe gathers links and routes on Windows by parsing `netsh` output.
// This enables VPN detection and CIDR collision checks on Windows.
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
// On Windows, this returns friendly names like "Ethernet", "Wi-Fi",
// and adapter names like "Wintun", "NordLynx", etc.
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

// gatherRoutes parses `netsh interface ip show route` for IPv4 and
// `netsh interface ipv6 show route` for IPv6.
// Real output format (IPv4):
//
//	Publish  Type       Met   Prefix                    Idx   Gateway/Interface Name
//	-------  --------   ----  ------------------------  ---   ------------------------
//	   No    System     256   0.0.0.0/0                  14   192.168.1.1
//	   No    System     256   10.100.0.0/24              14   Ethernet
//	   No    System     256   127.0.0.0/8                 1   Loopback Pseudo-Interface 1
func gatherRoutes() ([]RouteEntry, error) {
	var routes []RouteEntry

	// IPv4 routes
	v4Routes, err := gatherRoutesForFamily("ip")
	if err != nil {
		return nil, err
	}
	routes = append(routes, v4Routes...)

	// IPv6 routes
	v6Routes, err := gatherRoutesForFamily("ipv6")
	if err != nil {
		return nil, err
	}
	routes = append(routes, v6Routes...)

	// Remap temporary "if<idx>" names to real interface names using ifIndex map
	ifIndexToName := buildIfIndexToName()
	for i := range routes {
		if name := ifIndexToName[strings.TrimPrefix(routes[i].Iface, "if")]; name != "" {
			routes[i].Iface = name
		}
	}

	return routes, nil
}

// gatherRoutesForFamily runs `netsh interface <family> show route` and parses the output.
func gatherRoutesForFamily(family string) ([]RouteEntry, error) {
	cmd := exec.Command("netsh", "interface", family, "show", "route")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("netsh interface %s show route: %w", family, err)
	}

	routes, err := parseNetshRoutes(string(out))
	if err != nil {
		return nil, fmt.Errorf("parse netsh %s routes: %w", family, err)
	}

	return routes, nil
}

// buildIfIndexToName maps netsh ifIndex to interface name by running
// `netsh interface ipv4 show interfaces` (and ipv6).
// Real output format:
//
//	Idx     Met         MTU          State                Name
//	---  ----------  ----------  ------------  -------------------------
//	  1          75  4294967295  connected       Loopback Pseudo-Interface 1
//	 14          25        1500  connected       Ethernet
func buildIfIndexToName() map[string]string {
	m := make(map[string]string)

	// IPv4 interfaces
	if v4Map, err := getInterfaceMap("ipv4"); err == nil {
		for k, v := range v4Map {
			m[k] = v
		}
	}

	// IPv6 interfaces (same indices, merge any missing)
	if v6Map, err := getInterfaceMap("ipv6"); err == nil {
		for k, v := range v6Map {
			if _, exists := m[k]; !exists {
				m[k] = v
			}
		}
	}

	return m
}

func getInterfaceMap(family string) (map[string]string, error) {
	cmd := exec.Command("netsh", "interface", family, "show", "interfaces")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("netsh interface %s show interfaces: %w", family, err)
	}

	return parseNetshInterfaces(string(out)), nil
}
