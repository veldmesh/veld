// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT

// Package logsafe provides helpers for keeping operational logs free of
// client-identifying information.
package logsafe

import (
	"fmt"
	"net"
	"net/netip"
)

// TruncIP returns a privacy-safe, truncated form of an IP address string:
// the first three octets of an IPv4 address ("a.b.c.x", a /24) or the first
// 48 bits of an IPv6 address ("2001:db8:1234::x"). A trailing port (and the
// brackets around an IPv6 literal) is discarded, so the String() form of a
// net.Addr can be passed as-is; IPv6 zones are dropped too.
//
// It returns "" when s is not a parsable IP address. Callers must then omit
// the field from the log line entirely — never log the raw input.
func TruncIP(s string) string {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		host, _, serr := net.SplitHostPort(s)
		if serr != nil {
			return ""
		}
		if addr, err = netip.ParseAddr(host); err != nil {
			return ""
		}
	}
	addr = addr.Unmap()
	if addr.Is4() {
		o := addr.As4()
		return fmt.Sprintf("%d.%d.%d.x", o[0], o[1], o[2])
	}
	return netip.PrefixFrom(addr.WithZone(""), 48).Masked().Addr().String() + "x"
}
