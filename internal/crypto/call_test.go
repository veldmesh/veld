// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package crypto

import (
	"encoding/hex"
	"testing"
)

func TestCallSignature(t *testing.T) {
	id, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	other, _ := Generate()
	peerID := hex.EncodeToString(id.Ed25519Public)
	now := int64(1_800_000_000)

	claims := SendSignalClaims(peerID, "bb", []byte("payload"), now)
	sig := SignCall(id.Ed25519Private, claims)
	if err := VerifyCallSignature(id.Ed25519Public, sig, claims, now+5); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}

	bad := []struct {
		name   string
		pub    []byte
		claims CallClaims
		now    int64
	}{
		{"other key", other.Ed25519Public, claims, now},
		{"other payload", id.Ed25519Public, SendSignalClaims(peerID, "bb", []byte("other"), now), now},
		{"other recipient", id.Ed25519Public, SendSignalClaims(peerID, "cc", []byte("payload"), now), now},
		{"other method", id.Ed25519Public, CallClaims{Method: CallLeave, PeerID: peerID, Args: claims.Args, TimestampUnix: now}, now},
		{"stale", id.Ed25519Public, claims, now + CallTimestampWindow + 1},
	}
	for _, b := range bad {
		if err := VerifyCallSignature(b.pub, sig, b.claims, b.now); err == nil {
			t.Errorf("%s: signature accepted", b.name)
		}
	}
	if err := VerifyCallSignature(id.Ed25519Public, nil, claims, now); err == nil {
		t.Error("missing signature accepted")
	}
}

// A Register signature must never verify as a call signature.
func TestCallSignatureDomainSeparated(t *testing.T) {
	id, _ := Generate()
	claims := LeaveClaims(hex.EncodeToString(id.Ed25519Public), 1)
	regSig := SignRegister(id.Ed25519Private, RegisterClaims{TimestampUnix: 1})
	if err := VerifyCallSignature(id.Ed25519Public, regSig, claims, 1); err == nil {
		t.Error("register signature accepted for a call")
	}
}
