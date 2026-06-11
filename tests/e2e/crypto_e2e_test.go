// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package e2e_test

import (
	"testing"
	"time"

	"github.com/veldmesh/veld/internal/crypto"
)

func TestFullHandshakeSimulation(t *testing.T) {
	// Generate two identities
	idA, err := crypto.Generate()
	if err != nil {
		t.Fatalf("failed to generate identity A: %v", err)
	}

	idB, err := crypto.Generate()
	if err != nil {
		t.Fatalf("failed to generate identity B: %v", err)
	}

	// Assert A and B have different fingerprints
	fpA := idA.Fingerprint()
	fpB := idB.Fingerprint()
	if fpA == fpB {
		t.Error("two different identities should have different fingerprints")
	}

	// A signs for B at current time
	now := time.Now().Unix()
	sigAforB, err := idA.SignForPeer(idB.X25519Public, now)
	if err != nil {
		t.Fatalf("A failed to sign for B: %v", err)
	}

	// B verifies A's signature
	err = crypto.VerifyPeerSig(idA.Ed25519Public, idA.X25519Public, idB.X25519Public, sigAforB, now)
	if err != nil {
		t.Fatalf("B failed to verify A's signature: %v", err)
	}

	// B signs for A at current time
	sigBforA, err := idB.SignForPeer(idA.X25519Public, now)
	if err != nil {
		t.Fatalf("B failed to sign for A: %v", err)
	}

	// A verifies B's signature
	err = crypto.VerifyPeerSig(idB.Ed25519Public, idB.X25519Public, idA.X25519Public, sigBforA, now)
	if err != nil {
		t.Fatalf("A failed to verify B's signature: %v", err)
	}

	// Verify A's fingerprint is stable across multiple calls (deterministic)
	fpA2 := idA.Fingerprint()
	fpA3 := idA.Fingerprint()
	if fpA != fpA2 {
		t.Errorf("fingerprint not stable: first call %s != second call %s", fpA, fpA2)
	}
	if fpA2 != fpA3 {
		t.Errorf("fingerprint not stable: second call %s != third call %s", fpA2, fpA3)
	}
}

func TestNoiseHandshake_EndToEnd(t *testing.T) {
	idA, err := crypto.Generate()
	if err != nil {
		t.Fatalf("failed to generate identity A: %v", err)
	}

	idB, err := crypto.Generate()
	if err != nil {
		t.Fatalf("failed to generate identity B: %v", err)
	}

	var networkID [16]byte
	copy(networkID[:], []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})

	initiator, err := crypto.NewInitiatorHS(idA, idB.X25519Public, networkID)
	if err != nil {
		t.Fatalf("failed to create initiator: %v", err)
	}

	responder, err := crypto.NewResponderHS(idB, func(ed25519Pub []byte) ([32]byte, bool) {
		if string(ed25519Pub) == string(idA.Ed25519Public) {
			return idA.X25519Public, true
		}
		return [32]byte{}, false
	})
	if err != nil {
		t.Fatalf("failed to create responder: %v", err)
	}

	now := time.Now().Unix()

	msg1, err := initiator.BuildMessage1(now)
	if err != nil {
		t.Fatalf("failed to build message 1: %v", err)
	}

	err = responder.ProcessMessage1(msg1, now)
	if err != nil {
		t.Fatalf("failed to process message 1: %v", err)
	}

	msg2, responderResult, err := responder.BuildMessage2(now)
	if err != nil {
		t.Fatalf("failed to build message 2: %v", err)
	}

	initiatorResult, err := initiator.ProcessMessage2(msg2, now)
	if err != nil {
		t.Fatalf("failed to process message 2: %v", err)
	}

	if initiatorResult.NetworkID != networkID {
		t.Errorf("network ID not propagated to initiator: got %v, want %v", initiatorResult.NetworkID, networkID)
	}

	if responderResult.NetworkID != networkID {
		t.Errorf("network ID not propagated to responder: got %v, want %v", responderResult.NetworkID, networkID)
	}

	var emptySessionID [8]byte
	if initiatorResult.SessionID == emptySessionID {
		t.Error("initiator's session ID is zero")
	}

	if responderResult.SessionID == emptySessionID {
		t.Error("responder's session ID is zero")
	}

	if initiatorResult.SessionID != responderResult.SessionID {
		t.Errorf("session IDs don't match: initiator %v != responder %v", initiatorResult.SessionID, responderResult.SessionID)
	}

	if string(initiatorResult.PeerEd25519Public) != string(idB.Ed25519Public) {
		t.Error("initiator's peer Ed25519 fingerprint doesn't match B's public key")
	}

	if string(responderResult.PeerEd25519Public) != string(idA.Ed25519Public) {
		t.Error("responder's peer Ed25519 fingerprint doesn't match A's public key")
	}
}
