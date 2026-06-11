// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package nat_test

import (
	"context"
	"encoding/hex"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/veldmesh/veld/internal/crypto"
	"github.com/veldmesh/veld/internal/nat"
	"github.com/veldmesh/veld/internal/peer"
)

// makeIdentity is a helper that generates a fresh identity or fatals.
func makeIdentity(t *testing.T) *crypto.Identity {
	t.Helper()
	id, err := crypto.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return id
}

// makeUDPConn opens a UDP listener on a random loopback port.
func makeUDPConn(t *testing.T) (net.PacketConn, uint16) {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	port := conn.LocalAddr().(*net.UDPAddr).Port
	return conn, uint16(port)
}

// pumpProbes reads from conn and forwards TypeNATProbe packets to the manager.
// Runs until conn is closed.
func pumpProbes(conn net.PacketConn, mgr *nat.Manager) {
	buf := make([]byte, 64)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		if n < 4 {
			continue
		}
		// Check packet type (first 4 bytes big-endian)
		pktType := uint32(buf[0])<<24 | uint32(buf[1])<<16 | uint32(buf[2])<<8 | uint32(buf[3])
		if pktType == 0x05 {
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			mgr.HandleProbe(pkt, addr)
		}
	}
}

// TestNATManager_TwoPeersDiscover verifies that two Manager instances running
// on loopback can discover each other's endpoint via the probe protocol.
func TestNATManager_TwoPeersDiscover(t *testing.T) {
	idA := makeIdentity(t)
	idB := makeIdentity(t)

	connA, portA := makeUDPConn(t)
	connB, portB := makeUDPConn(t)

	mgrA := nat.New(connA, portA, "" /*no STUN*/, idA)
	mgrB := nat.New(connB, portB, "" /*no STUN*/, idB)

	discoveredByA := make(chan netip.AddrPort, 1)
	discoveredByB := make(chan netip.AddrPort, 1)

	mgrA.OnEndpointDiscovered = func(_ [32]byte, ep netip.AddrPort) {
		select {
		case discoveredByA <- ep:
		default:
		}
	}
	mgrB.OnEndpointDiscovered = func(_ [32]byte, ep netip.AddrPort) {
		select {
		case discoveredByB <- ep:
		default:
		}
	}

	// Run probe pumpers in the background.
	go pumpProbes(connA, mgrA)
	go pumpProbes(connB, mgrB)

	// Build peer.Entry stubs. Only ID and X25519Pub are needed by the manager.
	entryA := &peer.Entry{ID: [32]byte(idA.Ed25519Public[:32]), X25519Pub: idA.X25519Public}
	entryB := &peer.Entry{ID: [32]byte(idB.Ed25519Public[:32]), X25519Pub: idB.X25519Public}
	// Set dummy VPN addrs so Upsert works (peer.Entry requires a valid VPNAddr).
	entryA.VPNAddr = netip.MustParseAddr("10.0.0.1")
	entryB.VPNAddr = netip.MustParseAddr("10.0.0.2")

	// Wire signal delivery: what A sends goes directly to B's manager, and vice versa.
	// In production this round-trips through the coord server.
	peerIDofA := hex.EncodeToString(idA.Ed25519Public[:32])
	peerIDofB := hex.EncodeToString(idB.Ed25519Public[:32])

	sendAtoB := func(payload []byte) error {
		mgrB.DeliverSignal(peerIDofA, payload)
		return nil
	}
	sendBtoA := func(payload []byte) error {
		mgrA.DeliverSignal(peerIDofB, payload)
		return nil
	}

	ctx := context.Background()

	// A discovers B, B discovers A.
	mgrA.Start(ctx, entryB, sendAtoB)
	mgrB.Start(ctx, entryA, sendBtoA)

	timeout := time.After(5 * time.Second)

	var epAtA, epAtB netip.AddrPort
	remaining := 2
	for remaining > 0 {
		select {
		case ep := <-discoveredByA:
			epAtA = ep
			remaining--
		case ep := <-discoveredByB:
			epAtB = ep
			remaining--
		case <-timeout:
			t.Fatalf("timeout: A discovered=%v B discovered=%v", epAtA.IsValid(), epAtB.IsValid())
		}
	}

	if !epAtA.IsValid() {
		t.Error("A did not discover B's endpoint")
	}
	if !epAtB.IsValid() {
		t.Error("B did not discover A's endpoint")
	}

	// Each side should see the other's loopback port.
	if epAtA.Port() != portB {
		t.Errorf("A sees B at port %d, want %d", epAtA.Port(), portB)
	}
	if epAtB.Port() != portA {
		t.Errorf("B sees A at port %d, want %d", epAtB.Port(), portA)
	}
}

// TestNATManager_SignalEncryption verifies that signals are opaque to a
// third party and can only be decrypted by the intended recipient.
func TestNATManager_SignalEncryption(t *testing.T) {
	idA := makeIdentity(t)
	idB := makeIdentity(t)
	idEve := makeIdentity(t)

	connA, portA := makeUDPConn(t)
	mgrA := nat.New(connA, portA, "", idA)

	entryB := &peer.Entry{ID: [32]byte(idB.Ed25519Public[:32]), X25519Pub: idB.X25519Public}
	entryB.VPNAddr = netip.MustParseAddr("10.0.0.2")

	var captured []byte
	_ = mgrA // silence unused warning; we test signal encryption directly

	// encryptSignal + decryptSignal: only B can decrypt, Eve cannot.
	plain := []byte(`{"probe_nonce":"aabbccdd11223344","candidates":["127.0.0.1:51234"]}`)

	encrypted, err := nat.EncryptSignalFor(plain, idB.X25519Public)
	if err != nil {
		t.Fatalf("EncryptSignalFor: %v", err)
	}
	captured = encrypted

	// B can decrypt.
	decrypted, err := nat.DecryptSignalWith(captured, idB.X25519Private)
	if err != nil {
		t.Fatalf("DecryptSignalWith (B): %v", err)
	}
	if string(decrypted) != string(plain) {
		t.Errorf("decrypted mismatch: got %q, want %q", decrypted, plain)
	}

	// Eve cannot decrypt (wrong private key).
	_, err = nat.DecryptSignalWith(captured, idEve.X25519Private)
	if err == nil {
		t.Error("Eve decrypted a signal not addressed to her")
	}

	_ = entryB
}

// TestNATManager_DuplicateStart verifies that calling Start twice for the
// same peer is a no-op (the second call is silently ignored).
func TestNATManager_DuplicateStart(t *testing.T) {
	idA := makeIdentity(t)
	idB := makeIdentity(t)

	connA, portA := makeUDPConn(t)
	connB, portB := makeUDPConn(t)

	mgrA := nat.New(connA, portA, "", idA)
	mgrB := nat.New(connB, portB, "", idB)
	go pumpProbes(connA, mgrA)
	go pumpProbes(connB, mgrB)

	discovered := make(chan netip.AddrPort, 4)
	mgrA.OnEndpointDiscovered = func(_ [32]byte, ep netip.AddrPort) {
		select {
		case discovered <- ep:
		default:
		}
	}

	peerIDofA := hex.EncodeToString(idA.Ed25519Public[:32])
	entryB := &peer.Entry{ID: [32]byte(idB.Ed25519Public[:32]), X25519Pub: idB.X25519Public}
	entryB.VPNAddr = netip.MustParseAddr("10.0.0.2")
	entryA := &peer.Entry{ID: [32]byte(idA.Ed25519Public[:32]), X25519Pub: idA.X25519Public}
	entryA.VPNAddr = netip.MustParseAddr("10.0.0.1")

	peerIDofB := hex.EncodeToString(idB.Ed25519Public[:32])
	sendAtoB := func(payload []byte) error { mgrB.DeliverSignal(peerIDofA, payload); return nil }
	sendBtoA := func(payload []byte) error { mgrA.DeliverSignal(peerIDofB, payload); return nil }

	ctx := context.Background()
	mgrA.Start(ctx, entryB, sendAtoB)
	mgrA.Start(ctx, entryB, sendAtoB) // duplicate — should be ignored
	mgrB.Start(ctx, entryA, sendBtoA)

	select {
	case ep := <-discovered:
		if ep.Port() != portB {
			t.Errorf("discovered wrong port: got %d, want %d", ep.Port(), portB)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout: A did not discover B")
	}

	// Ensure we only got one discovery event (not two from the duplicate Start).
	time.Sleep(200 * time.Millisecond)
	if len(discovered) > 0 {
		t.Errorf("got extra discovery events from duplicate Start: %d extra", len(discovered))
	}
}
