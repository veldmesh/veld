// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package crypto

import (
	"errors"
	"testing"
	"time"
)

func testHandshake(t *testing.T, idA, idB *Identity, networkID [16]byte) (*HandshakeResult, *HandshakeResult) {
	t.Helper()

	initiator, err := NewInitiatorHS(idA, idB.X25519Public, networkID)
	if err != nil {
		t.Fatalf("failed to create initiator: %v", err)
	}

	responder, err := NewResponderHS(idB, func(ed25519Pub []byte) ([32]byte, bool) {
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

	return initiatorResult, responderResult
}

func TestNoiseHandshake_HappyPath(t *testing.T) {
	idA, err := Generate()
	if err != nil {
		t.Fatalf("failed to generate identity A: %v", err)
	}

	idB, err := Generate()
	if err != nil {
		t.Fatalf("failed to generate identity B: %v", err)
	}

	var networkID [16]byte
	copy(networkID[:], []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})

	initiatorResult, responderResult := testHandshake(t, idA, idB, networkID)

	if initiatorResult.SessionID != responderResult.SessionID {
		t.Errorf("session IDs don't match: initiator %v != responder %v", initiatorResult.SessionID, responderResult.SessionID)
	}

	if string(initiatorResult.PeerEd25519Public) != string(idB.Ed25519Public) {
		t.Error("initiator's peer Ed25519 public key doesn't match B's public key")
	}

	if string(responderResult.PeerEd25519Public) != string(idA.Ed25519Public) {
		t.Error("responder's peer Ed25519 public key doesn't match A's public key")
	}

	if initiatorResult.NetworkID != networkID {
		t.Errorf("initiator's network ID doesn't match: got %v, want %v", initiatorResult.NetworkID, networkID)
	}

	if responderResult.NetworkID != networkID {
		t.Errorf("responder's network ID doesn't match: got %v, want %v", responderResult.NetworkID, networkID)
	}

	if initiatorResult.SendCS == nil || initiatorResult.RecvCS == nil {
		t.Error("initiator's cipher states are nil")
	}

	if responderResult.SendCS == nil || responderResult.RecvCS == nil {
		t.Error("responder's cipher states are nil")
	}
}

func TestNoiseHandshake_UnknownInitiator(t *testing.T) {
	idA, err := Generate()
	if err != nil {
		t.Fatalf("failed to generate identity A: %v", err)
	}

	idB, err := Generate()
	if err != nil {
		t.Fatalf("failed to generate identity B: %v", err)
	}

	var networkID [16]byte

	initiator, err := NewInitiatorHS(idA, idB.X25519Public, networkID)
	if err != nil {
		t.Fatalf("failed to create initiator: %v", err)
	}

	responder, err := NewResponderHS(idB, func(ed25519Pub []byte) ([32]byte, bool) {
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
	if !errors.Is(err, ErrHandshakeDrop) {
		t.Errorf("expected ErrHandshakeDrop, got %v", err)
	}
}

func TestNoiseHandshake_TamperedMessage1(t *testing.T) {
	idA, err := Generate()
	if err != nil {
		t.Fatalf("failed to generate identity A: %v", err)
	}

	idB, err := Generate()
	if err != nil {
		t.Fatalf("failed to generate identity B: %v", err)
	}

	var networkID [16]byte

	initiator, err := NewInitiatorHS(idA, idB.X25519Public, networkID)
	if err != nil {
		t.Fatalf("failed to create initiator: %v", err)
	}

	responder, err := NewResponderHS(idB, func(ed25519Pub []byte) ([32]byte, bool) {
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

	msg1[len(msg1)/2] ^= 0xFF

	err = responder.ProcessMessage1(msg1, now)
	if !errors.Is(err, ErrHandshakeDrop) {
		t.Errorf("expected ErrHandshakeDrop, got %v", err)
	}
}

func TestNoiseHandshake_TamperedMessage2(t *testing.T) {
	idA, err := Generate()
	if err != nil {
		t.Fatalf("failed to generate identity A: %v", err)
	}

	idB, err := Generate()
	if err != nil {
		t.Fatalf("failed to generate identity B: %v", err)
	}

	var networkID [16]byte

	initiator, err := NewInitiatorHS(idA, idB.X25519Public, networkID)
	if err != nil {
		t.Fatalf("failed to create initiator: %v", err)
	}

	responder, err := NewResponderHS(idB, func(ed25519Pub []byte) ([32]byte, bool) {
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

	msg2, _, err := responder.BuildMessage2(now)
	if err != nil {
		t.Fatalf("failed to build message 2: %v", err)
	}

	msg2[len(msg2)/2] ^= 0xFF

	_, err = initiator.ProcessMessage2(msg2, now)
	if !errors.Is(err, ErrHandshakeDrop) {
		t.Errorf("expected ErrHandshakeDrop, got %v", err)
	}
}

func TestNoiseHandshake_TimestampTooOld(t *testing.T) {
	idA, err := Generate()
	if err != nil {
		t.Fatalf("failed to generate identity A: %v", err)
	}

	idB, err := Generate()
	if err != nil {
		t.Fatalf("failed to generate identity B: %v", err)
	}

	var networkID [16]byte

	initiator, err := NewInitiatorHS(idA, idB.X25519Public, networkID)
	if err != nil {
		t.Fatalf("failed to create initiator: %v", err)
	}

	responder, err := NewResponderHS(idB, func(ed25519Pub []byte) ([32]byte, bool) {
		if string(ed25519Pub) == string(idA.Ed25519Public) {
			return idA.X25519Public, true
		}
		return [32]byte{}, false
	})
	if err != nil {
		t.Fatalf("failed to create responder: %v", err)
	}

	oldTime := time.Now().Unix() - 31
	newTime := time.Now().Unix()

	msg1, err := initiator.BuildMessage1(oldTime)
	if err != nil {
		t.Fatalf("failed to build message 1: %v", err)
	}

	err = responder.ProcessMessage1(msg1, newTime)
	if !errors.Is(err, ErrHandshakeDrop) {
		t.Errorf("expected ErrHandshakeDrop, got %v", err)
	}
}

func TestNoiseHandshake_TimestampTooNew(t *testing.T) {
	idA, err := Generate()
	if err != nil {
		t.Fatalf("failed to generate identity A: %v", err)
	}

	idB, err := Generate()
	if err != nil {
		t.Fatalf("failed to generate identity B: %v", err)
	}

	var networkID [16]byte

	initiator, err := NewInitiatorHS(idA, idB.X25519Public, networkID)
	if err != nil {
		t.Fatalf("failed to create initiator: %v", err)
	}

	responder, err := NewResponderHS(idB, func(ed25519Pub []byte) ([32]byte, bool) {
		if string(ed25519Pub) == string(idA.Ed25519Public) {
			return idA.X25519Public, true
		}
		return [32]byte{}, false
	})
	if err != nil {
		t.Fatalf("failed to create responder: %v", err)
	}

	newTime := time.Now().Unix()
	futureTime := newTime + 31

	msg1, err := initiator.BuildMessage1(futureTime)
	if err != nil {
		t.Fatalf("failed to build message 1: %v", err)
	}

	err = responder.ProcessMessage1(msg1, newTime)
	if !errors.Is(err, ErrHandshakeDrop) {
		t.Errorf("expected ErrHandshakeDrop, got %v", err)
	}
}

func TestNoiseHandshake_WrongPeerX25519(t *testing.T) {
	idA, err := Generate()
	if err != nil {
		t.Fatalf("failed to generate identity A: %v", err)
	}

	idB, err := Generate()
	if err != nil {
		t.Fatalf("failed to generate identity B: %v", err)
	}

	idC, err := Generate()
	if err != nil {
		t.Fatalf("failed to generate identity C: %v", err)
	}

	var networkID [16]byte

	initiator, err := NewInitiatorHS(idA, idC.X25519Public, networkID)
	if err != nil {
		t.Fatalf("failed to create initiator: %v", err)
	}

	responder, err := NewResponderHS(idB, func(ed25519Pub []byte) ([32]byte, bool) {
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
	if !errors.Is(err, ErrHandshakeDrop) {
		t.Errorf("expected ErrHandshakeDrop, got %v", err)
	}
}

func TestNoiseHandshake_NetworkIDPropagated(t *testing.T) {
	idA, err := Generate()
	if err != nil {
		t.Fatalf("failed to generate identity A: %v", err)
	}

	idB, err := Generate()
	if err != nil {
		t.Fatalf("failed to generate identity B: %v", err)
	}

	var networkID [16]byte
	copy(networkID[:], []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})

	initiatorResult, responderResult := testHandshake(t, idA, idB, networkID)

	if initiatorResult.NetworkID != networkID {
		t.Errorf("initiator's network ID doesn't match: got %v, want %v", initiatorResult.NetworkID, networkID)
	}

	if responderResult.NetworkID != networkID {
		t.Errorf("responder's network ID doesn't match: got %v, want %v", responderResult.NetworkID, networkID)
	}
}
