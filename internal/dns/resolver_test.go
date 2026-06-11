// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package dns

import (
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

var testPeers = map[string]netip.Addr{
	"server1": netip.MustParseAddr("10.0.0.2"),
	"gateway": netip.MustParseAddr("10.0.0.1"),
}

func testLookup(name string) (netip.Addr, bool) {
	addr, ok := testPeers[strings.ToLower(name)]
	return addr, ok
}

func startTestResolver(t *testing.T) *Resolver {
	t.Helper()
	r := New("veld", testLookup)
	if err := r.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(r.Stop)
	return r
}

func TestResolver_AQuery_KnownPeer(t *testing.T) {
	r := startTestResolver(t)

	resp := mustQuery(t, r.ListenAddr(), buildQuery(1, "server1.veld.", dnsTypeA))

	if resp[2]>>7 != 1 {
		t.Error("QR bit not set in response")
	}
	if rcode := resp[3] & 0x0F; rcode != 0 {
		t.Errorf("RCODE = %d, want 0 (NOERROR)", rcode)
	}
	if ancount := binary.BigEndian.Uint16(resp[6:8]); ancount != 1 {
		t.Errorf("ANCOUNT = %d, want 1", ancount)
	}

	// Last 4 bytes of response are the IPv4 address in the A record.
	got := net.IP(resp[len(resp)-4:]).String()
	want := "10.0.0.2"
	if got != want {
		t.Errorf("A record IP = %s, want %s", got, want)
	}
}

func TestResolver_AQuery_UnknownPeer(t *testing.T) {
	r := startTestResolver(t)

	resp := mustQuery(t, r.ListenAddr(), buildQuery(2, "unknown.veld.", dnsTypeA))

	if rcode := resp[3] & 0x0F; rcode != 3 {
		t.Errorf("RCODE = %d, want 3 (NXDOMAIN)", rcode)
	}
}

func TestResolver_AQuery_WrongDomain(t *testing.T) {
	r := startTestResolver(t)

	resp := mustQuery(t, r.ListenAddr(), buildQuery(3, "server1.example.com.", dnsTypeA))

	if rcode := resp[3] & 0x0F; rcode != 3 {
		t.Errorf("RCODE = %d, want 3 (NXDOMAIN)", rcode)
	}
}

func TestResolver_AAAA_KnownPeer(t *testing.T) {
	r := startTestResolver(t)

	// AAAA query for a peer that only has IPv4 → NOERROR, 0 answers.
	resp := mustQuery(t, r.ListenAddr(), buildQuery(4, "server1.veld.", dnsTypeAAAA))

	if rcode := resp[3] & 0x0F; rcode != 0 {
		t.Errorf("RCODE = %d, want 0 (NOERROR)", rcode)
	}
	if ancount := binary.BigEndian.Uint16(resp[6:8]); ancount != 0 {
		t.Errorf("ANCOUNT = %d, want 0", ancount)
	}
}

func TestResolver_Static(t *testing.T) {
	r := New("veld", func(string) (netip.Addr, bool) { return netip.Addr{}, false })
	r.AddStatic("myhost", netip.MustParseAddr("10.0.0.100"))
	if err := r.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(r.Stop)

	resp := mustQuery(t, r.ListenAddr(), buildQuery(5, "myhost.veld.", dnsTypeA))

	if rcode := resp[3] & 0x0F; rcode != 0 {
		t.Errorf("RCODE = %d, want 0", rcode)
	}
	if ancount := binary.BigEndian.Uint16(resp[6:8]); ancount != 1 {
		t.Errorf("ANCOUNT = %d, want 1", ancount)
	}
	got := net.IP(resp[len(resp)-4:]).String()
	if got != "10.0.0.100" {
		t.Errorf("A record IP = %s, want 10.0.0.100", got)
	}
}

func TestResolver_StaticTakesPrecedenceOverLookup(t *testing.T) {
	lookup := func(name string) (netip.Addr, bool) {
		if name == "server1" {
			return netip.MustParseAddr("10.0.0.99"), true
		}
		return netip.Addr{}, false
	}
	r := New("veld", lookup)
	r.AddStatic("server1", netip.MustParseAddr("10.0.0.2"))
	if err := r.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(r.Stop)

	resp := mustQuery(t, r.ListenAddr(), buildQuery(6, "server1.veld.", dnsTypeA))

	got := net.IP(resp[len(resp)-4:]).String()
	if got != "10.0.0.2" {
		t.Errorf("A record IP = %s, want 10.0.0.2 (static takes precedence)", got)
	}
}

func TestResolver_CaseInsensitive(t *testing.T) {
	r := startTestResolver(t)

	// Uppercase query — should resolve identically.
	resp := mustQuery(t, r.ListenAddr(), buildQuery(7, "SERVER1.VELD.", dnsTypeA))

	if rcode := resp[3] & 0x0F; rcode != 0 {
		t.Errorf("RCODE = %d, want 0", rcode)
	}
	got := net.IP(resp[len(resp)-4:]).String()
	if got != "10.0.0.2" {
		t.Errorf("A record IP = %s, want 10.0.0.2", got)
	}
}

// buildQuery constructs a raw DNS query message.
func buildQuery(id uint16, qname string, qtype uint16) []byte {
	buf := []byte{
		byte(id >> 8), byte(id),
		0x01, 0x00, // flags: RD=1
		0x00, 0x01, // QDCOUNT=1
		0x00, 0x00, // ANCOUNT=0
		0x00, 0x00, // NSCOUNT=0
		0x00, 0x00, // ARCOUNT=0
	}
	for _, label := range strings.Split(strings.TrimSuffix(qname, "."), ".") {
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	buf = append(buf, 0)                        // root label
	buf = append(buf, byte(qtype>>8), byte(qtype)) // QTYPE
	buf = append(buf, 0x00, 0x01)              // QCLASS=IN
	return buf
}

// mustQuery sends a DNS query and returns the raw response.
func mustQuery(t *testing.T, addr string, query []byte) []byte {
	t.Helper()
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	if _, err := conn.Write(query); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return buf[:n]
}
