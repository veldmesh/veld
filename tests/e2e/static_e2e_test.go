// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package e2e_test

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/veldmesh/veld/internal/crypto"
	"github.com/veldmesh/veld/internal/daemon"
	"github.com/veldmesh/veld/internal/peer"
	"github.com/veldmesh/veld/internal/tun"
)

func makeEntry(id *crypto.Identity, vpn string, ep netip.AddrPort) *peer.Entry {
	var peerID [32]byte
	copy(peerID[:], id.Ed25519Public)
	e := &peer.Entry{
		ID:        peerID,
		X25519Pub: id.X25519Public,
		VPNAddr:   netip.MustParseAddr(vpn),
	}
	if ep.IsValid() {
		e.SetEndpoint(ep)
	}
	return e
}

func makeIPv4Packet(src, dst [4]byte, payload []byte) []byte {
	total := 20 + len(payload)
	pkt := make([]byte, total)
	pkt[0] = 0x45
	pkt[2] = byte(total >> 8)
	pkt[3] = byte(total)
	pkt[8] = 64
	pkt[9] = 17
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])
	copy(pkt[20:], payload)
	return pkt
}

// TestStaticConfig_TwoPeers_Exchange verifies that two daemons connect via static
// config and exchange packets end-to-end, including the initial Noise IK handshake.
func TestStaticConfig_TwoPeers_Exchange(t *testing.T) {
	idA, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate idA: %v", err)
	}
	idB, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate idB: %v", err)
	}

	var networkID [16]byte
	networkID[0] = 0xAB

	// Create real UDP sockets on random localhost ports.
	connA, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen A: %v", err)
	}
	defer connA.Close()
	connB, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen B: %v", err)
	}
	defer connB.Close()

	epA, _ := netip.ParseAddrPort(connA.LocalAddr().String())
	epB, _ := netip.ParseAddrPort(connB.LocalAddr().String())

	// Build peer tables.
	tblA := peer.New()
	tblA.Upsert(makeEntry(idB, "10.100.0.2", epB))

	tblB := peer.New()
	tblB.Upsert(makeEntry(idA, "10.100.0.1", epA))

	tunA := tun.NewMemTUN("tunA", netip.MustParsePrefix("10.100.0.1/24"), 1420)
	tunB := tun.NewMemTUN("tunB", netip.MustParsePrefix("10.100.0.2/24"), 1420)

	dA := daemon.New(idA, networkID, tunA, connA, tblA)
	dB := daemon.New(idB, networkID, tunB, connB, tblB)
	dA.Start()
	dB.Start()
	defer func() {
		dA.Stop(); dB.Stop()
		dA.Wait(); dB.Wait()
	}()

	// Inject a packet into tunA destined for 10.100.0.2.
	// The dispatcher will enqueue it and trigger a handshake.
	// After handshake completes, FlushHoldQueue sends it encrypted.
	// B decrypts and writes to tunB.
	want := makeIPv4Packet([4]byte{10, 100, 0, 1}, [4]byte{10, 100, 0, 2}, []byte("hello from A"))
	if _, err := tunA.Inject(want); err != nil {
		t.Fatalf("tunA.Inject: %v", err)
	}

	buf := make([]byte, 1500)
	done := make(chan []byte, 1)
	go func() {
		n, err := tunB.ReadDelivered(buf)
		if err == nil {
			out := make([]byte, n)
			copy(out, buf[:n])
			done <- out
		}
	}()

	select {
	case got := <-done:
		if string(got) != string(want) {
			t.Errorf("packet mismatch: got %d bytes, want %d bytes", len(got), len(want))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout: A→B packet did not arrive at tunB after handshake")
	}
}

// TestStaticConfig_BidirectionalExchange verifies packets flow A→B and B→A.
func TestStaticConfig_BidirectionalExchange(t *testing.T) {
	idA, _ := crypto.Generate()
	idB, _ := crypto.Generate()
	var networkID [16]byte

	connA, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen A: %v", err)
	}
	defer connA.Close()
	connB, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen B: %v", err)
	}
	defer connB.Close()

	epA, _ := netip.ParseAddrPort(connA.LocalAddr().String())
	epB, _ := netip.ParseAddrPort(connB.LocalAddr().String())

	tblA := peer.New()
	tblA.Upsert(makeEntry(idB, "10.100.0.2", epB))
	tblB := peer.New()
	tblB.Upsert(makeEntry(idA, "10.100.0.1", epA))

	tunA := tun.NewMemTUN("tunA", netip.MustParsePrefix("10.100.0.1/24"), 1420)
	tunB := tun.NewMemTUN("tunB", netip.MustParsePrefix("10.100.0.2/24"), 1420)

	dA := daemon.New(idA, networkID, tunA, connA, tblA)
	dB := daemon.New(idB, networkID, tunB, connB, tblB)
	dA.Start()
	dB.Start()
	defer func() { dA.Stop(); dB.Stop(); dA.Wait(); dB.Wait() }()

	// A→B: send "ping"
	ping := makeIPv4Packet([4]byte{10, 100, 0, 1}, [4]byte{10, 100, 0, 2}, []byte("ping"))
	tunA.Inject(ping)

	bufB := make([]byte, 1500)
	doneB := make(chan []byte, 1)
	go func() {
		n, err := tunB.ReadDelivered(bufB)
		if err == nil {
			out := make([]byte, n)
			copy(out, bufB[:n])
			doneB <- out
		}
	}()

	select {
	case got := <-doneB:
		if string(got) != string(ping) {
			t.Errorf("A→B: payload mismatch")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout: A→B ping did not arrive")
	}

	// B→A: send "pong"
	pong := makeIPv4Packet([4]byte{10, 100, 0, 2}, [4]byte{10, 100, 0, 1}, []byte("pong"))
	tunB.Inject(pong)

	bufA := make([]byte, 1500)
	doneA := make(chan []byte, 1)
	go func() {
		n, err := tunA.ReadDelivered(bufA)
		if err == nil {
			out := make([]byte, n)
			copy(out, bufA[:n])
			doneA <- out
		}
	}()

	select {
	case got := <-doneA:
		if string(got) != string(pong) {
			t.Errorf("B→A: payload mismatch")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout: B→A pong did not arrive")
	}
}
