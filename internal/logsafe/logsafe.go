// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT

// Package logsafe provides helpers for keeping operational logs free of
// client-identifying information.
package logsafe

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strings"
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

// ipPortRe matches IPv4 literals and bracketed IPv6 literals — each with an
// optional trailing port — wherever they appear in free text, so addresses
// embedded in error messages can be truncated (and their ports dropped).
// Text that does not parse as an address is left untouched.
var ipPortRe = regexp.MustCompile(`(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?|\[[0-9A-Fa-f:.%]+\](?::\d+)?`)

// ScrubErr returns a log-safe rendering of err. Errors returned by net.Conn
// reads and writes (*net.OpError) embed both endpoints' full ip:port in
// their text ("read tcp 192.0.2.1:5->198.51.100.7:9: connection reset by
// peer"); ScrubErr re-renders them without addresses, keeping only the
// operation and the underlying cause. Any IP literal still present in the
// result — e.g. one embedded in a custom error message — is truncated like
// TruncIP. It returns "" for nil.
//
// Log the result with %s; never log the raw error, which can carry
// connection details.
func ScrubErr(err error) string {
	if err == nil {
		return ""
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		cause := opErr.Err
		if cause == nil {
			cause = errors.New("network error")
		}
		// Re-render without Source/Addr: "read tcp: connection reset by peer".
		err = &net.OpError{Op: opErr.Op, Net: opErr.Net, Err: cause}
	}
	return ipPortRe.ReplaceAllStringFunc(err.Error(), func(m string) string {
		host := m
		if host[0] == '[' {
			if end := strings.IndexByte(host, ']'); end > 0 {
				host = host[1:end]
			}
		}
		if trunc := TruncIP(host); trunc != "" {
			return trunc
		}
		return m
	})
}
