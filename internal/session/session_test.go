// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package session

import (
	"errors"
	"testing"
	"time"

	"github.com/veldmesh/veld/internal/crypto"
)

func newTestSessionPair(t *testing.T) (initiator *Session, responder *Session) {
	t.Helper()

	idA, err := crypto.Generate()
	if err != nil {
		t.Fatalf("failed to generate identity A: %v", err)
	}

	idB, err := crypto.Generate()
	if err != nil {
		t.Fatalf("failed to generate identity B: %v", err)
	}

	var networkID [16]byte

	initiatorHS, err := crypto.NewInitiatorHS(idA, idB.X25519Public, networkID)
	if err != nil {
		t.Fatalf("failed to create initiator handshake: %v", err)
	}

	responderHS, err := crypto.NewResponderHS(idB, func(ed25519Pub []byte) ([32]byte, bool) {
		if string(ed25519Pub) == string(idA.Ed25519Public) {
			return idA.X25519Public, true
		}
		return [32]byte{}, false
	})
	if err != nil {
		t.Fatalf("failed to create responder handshake: %v", err)
	}

	now := time.Now().Unix()

	msg1, err := initiatorHS.BuildMessage1(now)
	if err != nil {
		t.Fatalf("failed to build message 1: %v", err)
	}

	err = responderHS.ProcessMessage1(msg1, now)
	if err != nil {
		t.Fatalf("failed to process message 1: %v", err)
	}

	msg2, respResult, err := responderHS.BuildMessage2(now)
	if err != nil {
		t.Fatalf("failed to build message 2: %v", err)
	}

	initResult, err := initiatorHS.ProcessMessage2(msg2, now)
	if err != nil {
		t.Fatalf("failed to process message 2: %v", err)
	}

	return New(initResult), New(respResult)
}

func TestSession_EncryptDecryptRoundTrip(t *testing.T) {
	sA, sB := newTestSessionPair(t)

	plaintext := []byte("hello veld")
	nonce, ct, err := sA.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}
	if ct == nil {
		t.Fatal("ciphertext is nil")
	}

	decrypted, err := sB.Decrypt(nonce, ct)
	if err != nil {
		t.Fatalf("failed to decrypt: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Errorf("decrypted plaintext doesn't match: got %q, want %q", decrypted, plaintext)
	}
}

func TestSession_NonceMonotonicity(t *testing.T) {
	sA, _ := newTestSessionPair(t)

	nonce0, _, err := sA.Encrypt([]byte("msg1"))
	if err != nil {
		t.Fatalf("first encrypt failed: %v", err)
	}

	nonce1, _, err := sA.Encrypt([]byte("msg2"))
	if err != nil {
		t.Fatalf("second encrypt failed: %v", err)
	}

	nonce2, _, err := sA.Encrypt([]byte("msg3"))
	if err != nil {
		t.Fatalf("third encrypt failed: %v", err)
	}

	if nonce0 != 0 {
		t.Errorf("first nonce should be 0, got %d", nonce0)
	}
	if nonce1 != 1 {
		t.Errorf("second nonce should be 1, got %d", nonce1)
	}
	if nonce2 != 2 {
		t.Errorf("third nonce should be 2, got %d", nonce2)
	}
}

func TestSession_ReplayRejection_Duplicate(t *testing.T) {
	sA, sB := newTestSessionPair(t)

	nonce, ct, err := sA.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	plaintext, err := sB.Decrypt(nonce, ct)
	if err != nil {
		t.Fatalf("first decrypt failed: %v", err)
	}
	if plaintext == nil {
		t.Fatal("first decrypt returned nil plaintext")
	}

	plaintext2, err := sB.Decrypt(nonce, ct)
	if plaintext2 != nil || err != nil {
		t.Errorf("second decrypt should return (nil, nil) for replay, got (%v, %v)", plaintext2, err)
	}
}

func TestSession_AuthFailure_SilentDrop(t *testing.T) {
	sA, sB := newTestSessionPair(t)

	nonce, ct, err := sA.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	tampered := make([]byte, len(ct))
	copy(tampered, ct)
	tampered[0] ^= 0xFF

	result, err := sB.Decrypt(nonce, tampered)
	if result != nil || err != nil {
		t.Errorf("decrypt of tampered ciphertext should return (nil, nil), got (%v, %v)", result, err)
	}
}

func TestSession_RekeyThreshold(t *testing.T) {
	sA, _ := newTestSessionPair(t)

	sA.sendNonce = RekeyThreshold

	_, _, err := sA.Encrypt([]byte("x"))
	if !errors.Is(err, ErrRekeyRequired) {
		t.Errorf("expected ErrRekeyRequired, got %v", err)
	}
}

func TestSession_ID(t *testing.T) {
	sA, sB := newTestSessionPair(t)

	idA := sA.ID()
	idB := sB.ID()

	// SessionIDs are randomly assigned [8]byte values; zero is astronomically
	// unlikely but not impossible — log rather than fail hard.
	var zero [8]byte
	if idA == zero {
		t.Log("warning: session A ID is zero (possible but very unlikely)")
	}
	if idB == zero {
		t.Log("warning: session B ID is zero (possible but very unlikely)")
	}

	// The initiator and responder must share the same session ID (derived from
	// the noise handshake).
	if idA != idB {
		t.Errorf("session IDs don't match: initiator %v, responder %v", idA, idB)
	}
}
