// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package mdns

import (
	"encoding/base64"
	"net"
	"net/netip"
	"testing"

	hashmDNS "github.com/hashicorp/mdns"

	"github.com/veldmesh/veld/internal/crypto"
	"github.com/veldmesh/veld/internal/peer"
)

func makeServiceEntry(id *crypto.Identity, name, vpn string, ipv4 net.IP, port int) *hashmDNS.ServiceEntry {
	return &hashmDNS.ServiceEntry{
		Name:   name,
		AddrV4: ipv4,
		Port:   port,
		InfoFields: []string{
			"ed25519=" + base64.RawURLEncoding.EncodeToString(id.Ed25519Public),
			"x25519=" + base64.RawURLEncoding.EncodeToString(id.X25519Public[:]),
			"vpn=" + vpn,
		},
	}
}

func TestParsePeerEntry_Valid(t *testing.T) {
	id, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}

	e := makeServiceEntry(id, "node1", "10.0.0.1", net.ParseIP("192.168.1.100"), 51820)

	pe, ep, ok := parsePeerEntry(e)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if pe.Name != "node1" {
		t.Errorf("Name: got %q, want %q", pe.Name, "node1")
	}
	if pe.VPNAddr.String() != "10.0.0.1" {
		t.Errorf("VPNAddr: got %s, want 10.0.0.1", pe.VPNAddr)
	}

	wantEP := netip.MustParseAddrPort("192.168.1.100:51820")
	if ep != wantEP {
		t.Errorf("endpoint: got %v, want %v", ep, wantEP)
	}

	var wantID [32]byte
	copy(wantID[:], id.Ed25519Public)
	if pe.ID != wantID {
		t.Error("peer ID (Ed25519 key) mismatch")
	}
	if pe.X25519Pub != id.X25519Public {
		t.Error("X25519 key mismatch")
	}
}

func TestParsePeerEntry_MissingFields(t *testing.T) {
	id, _ := crypto.Generate()
	ed25519B64 := base64.RawURLEncoding.EncodeToString(id.Ed25519Public)
	x25519B64 := base64.RawURLEncoding.EncodeToString(id.X25519Public[:])

	cases := []struct {
		name   string
		fields []string
	}{
		{"no_ed25519", []string{"x25519=" + x25519B64, "vpn=10.0.0.1"}},
		{"no_x25519", []string{"ed25519=" + ed25519B64, "vpn=10.0.0.1"}},
		{"no_vpn", []string{"ed25519=" + ed25519B64, "x25519=" + x25519B64}},
		{"empty", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := &hashmDNS.ServiceEntry{InfoFields: c.fields}
			_, _, ok := parsePeerEntry(e)
			if ok {
				t.Error("expected ok=false for missing fields")
			}
		})
	}
}

func TestParsePeerEntry_BadBase64(t *testing.T) {
	id, _ := crypto.Generate()
	x25519B64 := base64.RawURLEncoding.EncodeToString(id.X25519Public[:])

	e := &hashmDNS.ServiceEntry{
		InfoFields: []string{
			"ed25519=!!!notbase64!!!",
			"x25519=" + x25519B64,
			"vpn=10.0.0.1",
		},
	}
	_, _, ok := parsePeerEntry(e)
	if ok {
		t.Error("expected ok=false for bad base64")
	}
}

func TestParsePeerEntry_WrongKeyLength(t *testing.T) {
	e := &hashmDNS.ServiceEntry{
		InfoFields: []string{
			"ed25519=" + base64.RawURLEncoding.EncodeToString([]byte("tooshort")),
			"x25519=" + base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
			"vpn=10.0.0.1",
		},
	}
	_, _, ok := parsePeerEntry(e)
	if ok {
		t.Error("expected ok=false for wrong key length")
	}
}

func TestParsePeerEntry_BadVPNAddr(t *testing.T) {
	id, _ := crypto.Generate()
	e := &hashmDNS.ServiceEntry{
		InfoFields: []string{
			"ed25519=" + base64.RawURLEncoding.EncodeToString(id.Ed25519Public),
			"x25519=" + base64.RawURLEncoding.EncodeToString(id.X25519Public[:]),
			"vpn=not-an-ip",
		},
	}
	_, _, ok := parsePeerEntry(e)
	if ok {
		t.Error("expected ok=false for bad VPN addr")
	}
}

func TestParsePeerEntry_IPv6(t *testing.T) {
	id, _ := crypto.Generate()
	e := &hashmDNS.ServiceEntry{
		Name:   "ipv6node",
		AddrV6: net.ParseIP("fe80::1"),
		Port:   51820,
		InfoFields: []string{
			"ed25519=" + base64.RawURLEncoding.EncodeToString(id.Ed25519Public),
			"x25519=" + base64.RawURLEncoding.EncodeToString(id.X25519Public[:]),
			"vpn=10.0.0.2",
		},
	}
	_, ep, ok := parsePeerEntry(e)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if ep.Port() != 51820 {
		t.Errorf("port: got %d, want 51820", ep.Port())
	}
}

func TestParsePeerEntry_NoAddr(t *testing.T) {
	id, _ := crypto.Generate()
	e := &hashmDNS.ServiceEntry{
		Name: "noaddr",
		Port: 51820,
		InfoFields: []string{
			"ed25519=" + base64.RawURLEncoding.EncodeToString(id.Ed25519Public),
			"x25519=" + base64.RawURLEncoding.EncodeToString(id.X25519Public[:]),
			"vpn=10.0.0.3",
		},
	}
	pe, ep, ok := parsePeerEntry(e)
	if !ok {
		t.Fatal("expected ok=true (no addr is valid; endpoint will be zero)")
	}
	if ep.IsValid() {
		t.Error("expected zero endpoint when no address is present")
	}
	if pe.VPNAddr.String() != "10.0.0.3" {
		t.Errorf("VPNAddr: got %s", pe.VPNAddr)
	}
}

// TestSelfSkip verifies that a discovered entry matching our own Ed25519 key
// does not trigger the onPeer callback.
func TestSelfSkip(t *testing.T) {
	id, _ := crypto.Generate()

	var selfID [32]byte
	copy(selfID[:], id.Ed25519Public)

	called := false
	d := &Discovery{
		selfID: selfID,
		onPeer: func(e *peer.Entry, ep netip.AddrPort) { called = true },
	}

	e := makeServiceEntry(id, "self", "10.0.0.1", net.ParseIP("127.0.0.1"), 51820)
	d.handleEntry(e)

	if called {
		t.Error("onPeer must not be called when the discovered entry is ourselves")
	}
}

// TestDifferentPeerNotSkipped verifies that a different peer's entry does
// trigger the callback.
func TestDifferentPeerNotSkipped(t *testing.T) {
	selfID, _ := crypto.Generate()
	peerID, _ := crypto.Generate()

	var self [32]byte
	copy(self[:], selfID.Ed25519Public)

	called := false
	d := &Discovery{
		selfID: self,
		onPeer: func(e *peer.Entry, ep netip.AddrPort) { called = true },
	}

	e := makeServiceEntry(peerID, "other", "10.0.0.2", net.ParseIP("192.168.1.50"), 51820)
	d.handleEntry(e)

	if !called {
		t.Error("onPeer must be called for a peer that is not ourselves")
	}
}
