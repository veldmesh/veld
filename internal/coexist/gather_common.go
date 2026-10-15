// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT

package coexist

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

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

// ParseNetstatDst converts a netstat destination field to a prefix.
// "default" resolves to 0.0.0.0/0 or ::/0 depending on the address family
// of the section it appeared in. Bare addresses become host routes, and
// IPv4 shorthand like "127/8", "127", "10.100.0/24", "192.168/16" expands
// to the full prefix with natural mask based on dot count.
func ParseNetstatDst(s string, ipv6 bool) (netip.Prefix, error) {
	if s == "default" {
		if ipv6 {
			return netip.MustParsePrefix("::/0"), nil
		}
		return netip.MustParsePrefix("0.0.0.0/0"), nil
	}

	// IPv4 or IPv6 prefix with explicit prefix length (e.g. "10.100.0/24", "fd00::/8").
	if strings.Contains(s, "/") {
		if !strings.Contains(s, ":") {
			// IPv4 prefix — the address part may be shorthand with <3 dots
			// (e.g. "127/8", "10.100.0/24", "192.168/16"). Pad to 4 octets.
			addrStr := s[:strings.Index(s, "/")]
			dotCount := strings.Count(addrStr, ".")
			if dotCount < 3 {
				addrStr = addrStr + strings.Repeat(".0", 3-dotCount)
			}
			addr, err := netip.ParseAddr(addrStr)
			if err != nil {
				return netip.Prefix{}, err
			}
			var bits int
			if _, err := fmt.Sscanf(s[strings.Index(s, "/")+1:], "%d", &bits); err != nil {
				return netip.Prefix{}, err
			}
			return netip.PrefixFrom(addr, bits), nil
		}
		return netip.ParsePrefix(s)
	}

	// Bare address or IPv4 shorthand without prefix length (e.g. "127", "10.100.0").
	if !strings.Contains(s, ":") {
		dotCount := strings.Count(s, ".")
		if dotCount < 3 {
			// IPv4 shorthand: pad to 4 octets and infer natural prefix length.
			// 0 dots ("127") -> X.0.0.0/8
			// 1 dot  ("192.168") -> X.Y.0.0/16
			// 2 dots ("10.100.0") -> X.Y.Z.0/24
			addrStr := s + strings.Repeat(".0", 3-dotCount)
			addr, err := netip.ParseAddr(addrStr)
			if err != nil {
				return netip.Prefix{}, err
			}
			// Natural classful mask based on dot count.
			var bits int
			switch dotCount {
			case 0:
				bits = 8
			case 1:
				bits = 16
			case 2:
				bits = 24
			}
			return netip.PrefixFrom(addr, bits), nil
		}
		// 3 dots: full IPv4 address -> host route /32
	}

	// Bare address: a host route (IPv4 with 3 dots, or IPv6).
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	if addr.Is4() {
		return netip.PrefixFrom(addr, 32), nil
	}
	return netip.PrefixFrom(addr, 128), nil
}