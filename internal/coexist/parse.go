// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT

package coexist

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// parseDarwinNetstat parses the output of `netstat -rn` on macOS.
// The Flags column uses mixed-case letters (e.g., UGSc, UGcI, UHLWIi),
// so the regex must accept lowercase letters and digits.
func parseDarwinNetstat(out string) ([]RouteEntry, error) {
	var routes []RouteEntry

	// Data rows: destination, gateway, flags, interface.
	// Flags are mixed-case letters/digits (U=up, G=gateway, H=host, c=clone, ...).
	re := regexp.MustCompile(`^(\S+)\s+(\S+)\s+[A-Za-z0-9]+\s+(\S+)`)

	// Track which address family the parser is in, so "default" can be
	// resolved to the right 0/0 prefix.
	const (
		famNone = iota
		famIPv4
		famIPv6
	)
	fam := famNone

	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "Internet:"):
			fam = famIPv4
			continue
		case strings.HasPrefix(line, "Internet6:"):
			fam = famIPv6
			continue
		case line == "" || strings.HasPrefix(line, "Routing") || strings.HasPrefix(line, "Destination"):
			continue
		}
		if fam == famNone {
			continue
		}

		m := re.FindStringSubmatch(line)
		if m == nil {
			continue
		}

		dstStr := m[1]
		gwStr := m[2]
		iface := m[3]

		dst, err := ParseNetstatDst(dstStr, fam == famIPv6)
		if err != nil {
			continue
		}

		// Parse gateway (next hop). Link-local gateways and interface
		// references are not routable next hops for our purposes.
		var gw netip.Addr
		if !strings.HasPrefix(gwStr, "link#") && gwStr != "iface" {
			if addr, err := netip.ParseAddr(strings.SplitN(gwStr, "%", 2)[0]); err == nil {
				gw = addr
			}
		}

		// macOS manages route priority internally and does not expose a
		// metric in netstat output; the field stays zero.
		routes = append(routes, RouteEntry{
			Dst:   dst,
			Gw:    gw,
			Iface: iface,
			Table: 254, // macOS has a single routing table for our purposes
		})
	}

	return routes, nil
}

// ParseDarwinNetstatForTest exposes parseDarwinNetstat for external tests.
func ParseDarwinNetstatForTest(out string) ([]RouteEntry, error) {
	return parseDarwinNetstat(out)
}

// parseNetshRoutes parses the output of `netsh interface ip show route`
// or `netsh interface ipv6 show route` on Windows.
//
// Real output format (IPv4 example):
//
//	Publish  Type       Met   Prefix                    Idx   Gateway/Interface Name
//	-------  --------   ----  ------------------------  ---   ------------------------
//	   No    System     256   0.0.0.0/0                  14   192.168.1.1
//	   No    System     256   10.100.0.0/24              14   Ethernet
//	   No    System     256   127.0.0.0/8                 1   Loopback Pseudo-Interface 1
func parseNetshRoutes(out string) ([]RouteEntry, error) {
	var routes []RouteEntry

	// Data rows: Publish(No/Yes), Type(word), Met(digits), Prefix(CIDR), Idx(digits), Gateway/Interface Name(rest)
	// Header and separator lines won't match because Met is not digits there.
	re := regexp.MustCompile(`^\s*(\S+)\s+(\S+)\s+(\d+)\s+(\S+)\s+(\d+)\s+(.+)$`)

	for _, line := range strings.Split(out, "\n") {
		m := re.FindStringSubmatch(line)
		if m == nil {
			continue
		}

		// m[1] = Publish (No/Yes), m[2] = Type, m[3] = Metric, m[4] = Prefix, m[5] = Idx, m[6] = Gateway/Interface Name
		metricStr := m[3]
		dstStr := m[4]
		ifIndex := m[5]
		gwOrName := strings.TrimSpace(m[6])

		dst, err := netip.ParsePrefix(dstStr)
		if err != nil {
			continue
		}

		var metric int
		_, _ = fmt.Sscanf(metricStr, "%d", &metric)

		// Determine gateway vs interface name in the last column.
		// If it parses as an IP address, it's a gateway; otherwise it's
		// an interface name (we'll map IfIndex separately).
		var gw netip.Addr
		if addr, err := netip.ParseAddr(gwOrName); err == nil {
			gw = addr
		}

		routes = append(routes, RouteEntry{
			Dst:    dst,
			Gw:     gw,
			Iface:  "if" + ifIndex, // temporary; will be remapped by caller via buildIfIndexToName
			Metric: metric,
			Table:  254, // Windows effectively has one main table for our purposes
		})
	}

	return routes, nil
}

// ParseNetshRoutesForTest exposes parseNetshRoutes for external tests.
func ParseNetshRoutesForTest(out string) ([]RouteEntry, error) {
	return parseNetshRoutes(out)
}

// parseNetshInterfaces parses the output of `netsh interface ipv4 show interfaces`
// or `netsh interface ipv6 show interfaces` and returns a map from ifIndex to name.
//
// Real output format:
//
//	Idx     Met         MTU          State                Name
//	---  ----------  ----------  ------------  -------------------------
//	  1          75  4294967295  connected       Loopback Pseudo-Interface 1
//	 14          25        1500  connected       Ethernet
func parseNetshInterfaces(out string) map[string]string {
	// Data rows: Idx(digits), Met(digits), MTU(digits), State(word), Name(rest)
	re := regexp.MustCompile(`^\s*(\d+)\s+\d+\s+\d+\s+\S+\s+(.+)$`)
	m := make(map[string]string)
	for _, line := range strings.Split(out, "\n") {
		matches := re.FindStringSubmatch(line)
		if matches != nil {
			m[matches[1]] = strings.TrimSpace(matches[2])
		}
	}
	return m
}

// ParseNetshInterfacesForTest exposes parseNetshInterfaces for external tests.
func ParseNetshInterfacesForTest(out string) map[string]string {
	return parseNetshInterfaces(out)
}
