// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package e2e_test

import (
	"testing"
	"time"

	"github.com/veldmesh/veld/internal/crypto"
	"github.com/veldmesh/veld/internal/session"
)

func runHandshake(t *testing.T, idA, idB *crypto.Identity) (*crypto.HandshakeResult, *crypto.HandshakeResult) {
	t.Helper()
	var networkID [16]byte
	initiatorHS, err := crypto.NewInitiatorHS(idA, idB.X25519Public, networkID)
	if err != nil {
		t.Fatalf("failed to create initiator handshake: %v", err)
	}
	responderHS, err := crypto.NewResponderHS(idB, func(pub []byte) ([32]byte, bool) {
		if string(pub) == string(idA.Ed25519Public) {
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
	return initResult, respResult
}

func TestSession_EndToEnd(t *testing.T) {
	idA, err := crypto.Generate()
	if err != nil {
		t.Fatalf("failed to generate identity A: %v", err)
	}

	idB, err := crypto.Generate()
	if err != nil {
		t.Fatalf("failed to generate identity B: %v", err)
	}

	initResult, respResult := runHandshake(t, idA, idB)
	sessionA := session.New(initResult)
	sessionB := session.New(respResult)

	nonce, ct, err := sessionA.Encrypt([]byte("ping"))
	if err != nil {
		t.Fatalf("A->B encrypt failed: %v", err)
	}

	plaintext, err := sessionB.Decrypt(nonce, ct)
	if err != nil {
		t.Fatalf("A->B decrypt failed: %v", err)
	}
	if string(plaintext) != "ping" {
		t.Errorf("A->B message mismatch: got %q, want %q", plaintext, "ping")
	}

	nonce2, ct2, err := sessionB.Encrypt([]byte("pong"))
	if err != nil {
		t.Fatalf("B->A encrypt failed: %v", err)
	}

	plaintext2, err := sessionA.Decrypt(nonce2, ct2)
	if err != nil {
		t.Fatalf("B->A decrypt failed: %v", err)
	}
	if string(plaintext2) != "pong" {
		t.Errorf("B->A message mismatch: got %q, want %q", plaintext2, "pong")
	}

	result, err := sessionB.Decrypt(nonce, ct)
	if result != nil || err != nil {
		t.Errorf("replay should return (nil, nil), got (%v, %v)", result, err)
	}

	if sessionA.ID() != sessionB.ID() {
		t.Errorf("session IDs don't match: A %v != B %v", sessionA.ID(), sessionB.ID())
	}
}
