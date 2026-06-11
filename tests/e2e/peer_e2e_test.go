// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package e2e_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/veldmesh/veld/internal/crypto"
	"github.com/veldmesh/veld/internal/peer"
	"github.com/veldmesh/veld/internal/session"
)

// TestPeerTable_EndToEnd builds a peer table, runs a full Noise handshake using
// the table's PeerLookupFn, updates the session, and verifies hold queue drain.
func TestPeerTable_EndToEnd(t *testing.T) {
	idA, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate idA: %v", err)
	}
	idB, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate idB: %v", err)
	}

	// Build B's peer table — B knows A.
	tbl := peer.New()
	var aID [32]byte
	copy(aID[:], idA.Ed25519Public)
	eA := &peer.Entry{
		ID:        aID,
		X25519Pub: idA.X25519Public,
		VPNAddr:   netip.MustParseAddr("10.100.0.1"),
	}
	tbl.Upsert(eA)

	// Enqueue some hold packets before the session is ready.
	holdPkt := []byte{0x45, 0x00, 0x00, 0x14}
	for i := 0; i < 3; i++ {
		if !eA.Enqueue(holdPkt) {
			t.Fatalf("Enqueue %d failed", i)
		}
	}

	// Run the Noise IK handshake using the table's PeerLookupFn as B's responder lookup.
	initiatorHS, err := crypto.NewInitiatorHS(idA, idB.X25519Public, [16]byte{})
	if err != nil {
		t.Fatalf("NewInitiatorHS: %v", err)
	}
	responderHS, err := crypto.NewResponderHS(idB, tbl.PeerLookupFn())
	if err != nil {
		t.Fatalf("NewResponderHS: %v", err)
	}

	now := time.Now().Unix()
	msg1, err := initiatorHS.BuildMessage1(now)
	if err != nil {
		t.Fatalf("BuildMessage1: %v", err)
	}
	if err := responderHS.ProcessMessage1(msg1, now); err != nil {
		t.Fatalf("ProcessMessage1: %v", err)
	}
	msg2, respResult, err := responderHS.BuildMessage2(now)
	if err != nil {
		t.Fatalf("BuildMessage2: %v", err)
	}
	initResult, err := initiatorHS.ProcessMessage2(msg2, now)
	if err != nil {
		t.Fatalf("ProcessMessage2: %v", err)
	}

	// Store session on A's entry in B's table and drain the hold queue.
	sessA := session.New(respResult)
	eA.SetSession(sessA)
	if eA.GetState() != peer.StateConnected {
		t.Errorf("state: got %d, want StateConnected", eA.GetState())
	}

	held := eA.DrainQueue()
	if len(held) != 3 {
		t.Errorf("DrainQueue: got %d packets, want 3", len(held))
	}
	// Verify hold queue is now empty.
	if q := eA.DrainQueue(); q != nil {
		t.Error("second DrainQueue should return nil")
	}

	// Verify the session works: A sends with initResult, B decrypts with sessA (respResult).
	sessInit := session.New(initResult)
	nonce, ct, err := sessInit.Encrypt([]byte("hello"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	plain, err := sessA.Decrypt(nonce, ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(plain) != "hello" {
		t.Errorf("Decrypt: got %q, want %q", plain, "hello")
	}

	// Lookup by VPN addr works.
	got, ok := tbl.LookupByVPN(netip.MustParseAddr("10.100.0.1"))
	if !ok || got != eA {
		t.Error("LookupByVPN failed after session setup")
	}
}

// TestPeerTable_HoldQueue_Overflow verifies the max-64 drop policy.
func TestPeerTable_HoldQueue_Overflow(t *testing.T) {
	e := &peer.Entry{}
	pkt := []byte{0x45}

	var accepted int
	for i := 0; i < peer.HoldQueueMax+10; i++ {
		if e.Enqueue(pkt) {
			accepted++
		}
	}
	if accepted != peer.HoldQueueMax {
		t.Errorf("accepted %d packets, want %d", accepted, peer.HoldQueueMax)
	}

	q := e.DrainQueue()
	if len(q) != peer.HoldQueueMax {
		t.Errorf("drained %d packets, want %d", len(q), peer.HoldQueueMax)
	}
}
