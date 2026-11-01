// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
)

func TestProxyProtocolPolicy_Empty(t *testing.T) {
	for _, s := range []string{"", "   "} {
		policy, err := ProxyProtocolPolicy(s)
		if err != nil {
			t.Fatalf("ProxyProtocolPolicy(%q): unexpected error: %v", s, err)
		}
		if policy != nil {
			t.Errorf("ProxyProtocolPolicy(%q) returned a policy, want nil (disabled)", s)
		}
	}
}

func TestProxyProtocolPolicy_BadCIDR(t *testing.T) {
	for _, s := range []string{"10.0.0.1", "10.0.0.0/33", "not-a-cidr", "10.0.0.0/8,", "10.0.0.0/8,,192.168.0.0/16"} {
		if _, err := ProxyProtocolPolicy(s); err == nil {
			t.Errorf("ProxyProtocolPolicy(%q): expected error", s)
		}
	}
}

func TestProxyProtocolPolicy_Decisions(t *testing.T) {
	policy, err := ProxyProtocolPolicy("10.0.0.0/8, 192.168.0.0/16")
	if err != nil {
		t.Fatalf("ProxyProtocolPolicy: %v", err)
	}
	tests := []struct {
		name     string
		upstream string
		want     proxyproto.Policy
	}{
		{"trusted first range", "10.1.2.3:40000", proxyproto.REQUIRE},
		{"trusted second range", "192.168.5.5:40000", proxyproto.REQUIRE},
		{"untrusted public", "203.0.113.7:40000", proxyproto.REJECT},
		{"untrusted loopback", "127.0.0.1:40000", proxyproto.REJECT},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			addr, err := net.ResolveTCPAddr("tcp", tc.upstream)
			if err != nil {
				t.Fatal(err)
			}
			got, err := policy(proxyproto.ConnPolicyOptions{Upstream: addr})
			if err != nil {
				t.Fatalf("policy: unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("policy(%s) = %v, want %v", tc.upstream, got, tc.want)
			}
		})
	}
}

// acceptProxyConn accepts one connection from ln, failing the test if none
// arrives in time.
func acceptProxyConn(t *testing.T, ln net.Listener) net.Conn {
	t.Helper()
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := ln.Accept()
		ch <- result{c, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("Accept: %v", r.err)
		}
		t.Cleanup(func() { _ = r.conn.Close() })
		_ = r.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		return r.conn
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Accept")
		return nil
	}
}

func listenProxy(t *testing.T, cidrs string) net.Listener {
	t.Helper()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := WrapProxyProtocolListener(raw, cidrs)
	if err != nil {
		_ = raw.Close()
		t.Fatalf("WrapProxyProtocolListener: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

func dialProxy(t *testing.T, ln net.Listener, payload string) {
	t.Helper()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if _, err := c.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
}

func TestProxyProtocolListener_TrustedSourceUsesHeaderAddress(t *testing.T) {
	ln := listenProxy(t, "127.0.0.0/8")
	dialProxy(t, ln, "PROXY TCP4 203.0.113.7 127.0.0.1 40000 50051\r\nping")

	conn := acceptProxyConn(t, ln)
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read payload: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("payload = %q, want %q", buf, "ping")
	}
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	if host != "203.0.113.7" {
		t.Errorf("RemoteAddr host = %s, want 203.0.113.7", host)
	}
}

func TestProxyProtocolListener_UntrustedSourceHeaderRejected(t *testing.T) {
	ln := listenProxy(t, "10.0.0.0/8")
	dialProxy(t, ln, "PROXY TCP4 203.0.113.7 127.0.0.1 40000 50051\r\nping")

	conn := acceptProxyConn(t, ln)
	buf := make([]byte, 4)
	_, err := io.ReadFull(conn, buf)
	if !errors.Is(err, proxyproto.ErrSuperfluousProxyHeader) {
		t.Fatalf("read error = %v, want ErrSuperfluousProxyHeader", err)
	}
	host, _, splitErr := net.SplitHostPort(conn.RemoteAddr().String())
	if splitErr != nil {
		t.Fatal(splitErr)
	}
	if host == "203.0.113.7" {
		t.Errorf("RemoteAddr host = %s: header address was accepted from an untrusted peer", host)
	}
}

func TestProxyProtocolListener_UntrustedSourceWithoutHeaderServedDirectly(t *testing.T) {
	ln := listenProxy(t, "10.0.0.0/8")
	dialProxy(t, ln, "ping")

	conn := acceptProxyConn(t, ln)
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read payload: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("payload = %q, want %q", buf, "ping")
	}
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	if host != "127.0.0.1" {
		t.Errorf("RemoteAddr host = %s, want the direct peer 127.0.0.1", host)
	}
}

func TestProxyProtocolListener_TrustedSourceWithoutHeaderRejected(t *testing.T) {
	ln := listenProxy(t, "127.0.0.0/8")
	dialProxy(t, ln, "ping")

	conn := acceptProxyConn(t, ln)
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); !errors.Is(err, proxyproto.ErrNoProxyProtocol) {
		t.Fatalf("read error = %v, want ErrNoProxyProtocol", err)
	}
}

func TestProxyProtocolListener_DisabledIsPassthrough(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := WrapProxyProtocolListener(raw, "")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	if ln != raw {
		t.Error("empty CIDRs should return the listener unchanged")
	}
}
