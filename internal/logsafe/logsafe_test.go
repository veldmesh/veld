// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT

package logsafe

import "testing"

func TestTruncIPv4(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"bare", "203.0.113.7", "203.0.113.x"},
		{"private", "192.168.1.100", "192.168.1.x"},
		{"zero", "0.0.0.0", "0.0.0.x"},
		{"broadcast", "255.255.255.255", "255.255.255.x"},
		{"with port", "203.0.113.7:443", "203.0.113.x"},
		{"v4-mapped v6", "::ffff:203.0.113.7", "203.0.113.x"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := TruncIP(c.in); got != c.want {
				t.Errorf("TruncIP(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestTruncIPv6(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"full", "2001:db8:1234:5678:9abc:def0:1234:5678", "2001:db8:1234::x"},
		{"compressed", "2607:f8b0:4006:81a::200e", "2607:f8b0:4006::x"},
		{"link-local", "fe80::1", "fe80::x"},
		{"loopback", "::1", "::x"},
		{"already 48 bits", "2001:db8::", "2001:db8::x"},
		{"with port", "[2001:db8:1234:5678::1]:9999", "2001:db8:1234::x"},
		{"zone dropped", "fe80::1%eth0", "fe80::x"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := TruncIP(c.in); got != c.want {
				t.Errorf("TruncIP(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestTruncIPInvalid(t *testing.T) {
	for _, in := range []string{
		"",
		"not-an-ip",
		"example.com",
		"example.com:80",
		"999.999.999.999",
		"1.2.3",
		"203.0.113.",
		"::ffff:999.1.1.1",
	} {
		t.Run(in, func(t *testing.T) {
			if got := TruncIP(in); got != "" {
				t.Errorf("TruncIP(%q) = %q, want \"\" (unparsable input must not be echoed)", in, got)
			}
		})
	}
}

func TestTruncIPDropsHostBits(t *testing.T) {
	// The host part of the address must never survive truncation.
	if got := TruncIP("203.0.113.42"); got != "203.0.113.x" {
		t.Errorf("v4 host bits leaked: %q", got)
	}
	if got := TruncIP("2001:db8:1234:5678::9"); got != "2001:db8:1234::x" {
		t.Errorf("v6 host bits leaked: %q", got)
	}
}
