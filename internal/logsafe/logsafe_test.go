// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT

package logsafe

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
)

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

func TestScrubErrNil(t *testing.T) {
	if got := ScrubErr(nil); got != "" {
		t.Errorf("ScrubErr(nil) = %q, want \"\"", got)
	}
}

// opErr builds a *net.OpError exactly as net.Conn reads and writes do:
// Source and Addr carry both endpoints' full ip:port, and its Error()
// text embeds them.
func opErr(op, network, srcIP string, srcPort, dstPort int, cause error) *net.OpError {
	return &net.OpError{
		Op:     op,
		Net:    network,
		Source: &net.TCPAddr{IP: net.ParseIP(srcIP), Port: srcPort},
		Addr:   &net.TCPAddr{IP: net.ParseIP("192.0.2.100"), Port: dstPort},
		Err:    cause,
	}
}

func TestScrubErrDropsNetworkErrorEndpoints(t *testing.T) {
	err := opErr("read", "tcp", "127.0.0.1", 49207, 54321, os.NewSyscallError("read", syscall.ECONNRESET))
	got := ScrubErr(err)
	for _, leak := range []string{"127.0.0.1", "192.0.2.100", "49207", "54321"} {
		if strings.Contains(got, leak) {
			t.Errorf("ScrubErr leaked %q: %q", leak, got)
		}
	}
	if !strings.Contains(got, "read tcp") {
		t.Errorf("operation and cause must survive scrubbing, got %q", got)
	}
}

func TestScrubErrDropsWrappedNetworkErrorEndpoints(t *testing.T) {
	inner := &net.OpError{
		Op:     "write",
		Net:    "tcp",
		Source: &net.TCPAddr{IP: net.ParseIP("2001:db8:1234:5678::9"), Port: 1},
		Addr:   &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 2},
		Err:    os.NewSyscallError("write", os.ErrDeadlineExceeded),
	}
	got := ScrubErr(fmt.Errorf("splice: %w", inner))
	for _, leak := range []string{"2001:db8", "203.0.113.7"} {
		if strings.Contains(got, leak) {
			t.Errorf("ScrubErr leaked %q: %q", leak, got)
		}
	}
	if !strings.Contains(got, "i/o timeout") {
		t.Errorf("underlying cause must survive scrubbing, got %q", got)
	}
}

func TestScrubErrTruncatesAddressesInCustomErrors(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		notWant string
	}{
		{"ipv4 with port", "dial 203.0.113.42:54321 failed", "203.0.113.x", "54321"},
		{"bracketed ipv6 with port", "connect [2001:db8:1234:5678::9]:443 failed", "2001:db8:1234::x", ":443"},
		{"non-address text untouched", "handshake failed after 3 attempts", "handshake failed after 3 attempts", ""},
		{"invalid ip-looking text untouched", "got 999.1.1.1 in reply", "999.1.1.1", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ScrubErr(errors.New(c.in))
			if !strings.Contains(got, c.want) {
				t.Errorf("ScrubErr should contain %q, got %q", c.want, got)
			}
			if c.notWant != "" && strings.Contains(got, c.notWant) {
				t.Errorf("ScrubErr leaked %q: %q", c.notWant, got)
			}
		})
	}
}
