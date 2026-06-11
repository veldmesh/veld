// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package crypto

import (
	"crypto/ed25519"
	"testing"
	"time"
)

func TestGenerateAndFingerprint(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "first identity"},
		{name: "second identity"},
	}

	var id1, id2 *Identity

	for i, tt := range tests {
		id, err := Generate()
		if err != nil {
			t.Fatalf("%s: failed to generate identity: %v", tt.name, err)
		}

		fp := id.Fingerprint()

		// Assert fingerprint is 64 hex chars (SHA-256 = 32 bytes = 64 hex chars)
		if len(fp) != 64 {
			t.Errorf("%s: fingerprint has wrong length: got %d, want 64", tt.name, len(fp))
		}

		// Verify all characters are valid hex
		for _, ch := range fp {
			if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) {
				t.Errorf("%s: fingerprint contains non-hex character: %c", tt.name, ch)
			}
		}

		// Store for comparison
		if i == 0 {
			id1 = id
		} else {
			id2 = id
		}
	}

	// Assert fingerprints differ
	if id1.Fingerprint() == id2.Fingerprint() {
		t.Error("two different identities should have different fingerprints")
	}
}

func TestSignForPeerAndVerify(t *testing.T) {
	// Generate two identities
	idA, err := Generate()
	if err != nil {
		t.Fatalf("failed to generate identity A: %v", err)
	}

	idB, err := Generate()
	if err != nil {
		t.Fatalf("failed to generate identity B: %v", err)
	}

	// A signs for B with current timestamp
	now := time.Now().Unix()
	sig, err := idA.SignForPeer(idB.X25519Public, now)
	if err != nil {
		t.Fatalf("failed to sign for peer: %v", err)
	}

	// Verify signature succeeds
	err = VerifyPeerSig(idA.Ed25519Public, idA.X25519Public, idB.X25519Public, sig, now)
	if err != nil {
		t.Fatalf("verification failed: %v", err)
	}

	// Mutate timestamp by 31 seconds (outside the ±30s window)
	oldTimestamp := now
	badTimestamp := now + 31

	sig2, err := idA.SignForPeer(idB.X25519Public, badTimestamp)
	if err != nil {
		t.Fatalf("failed to sign for peer with bad timestamp: %v", err)
	}

	// Verify should fail with the old timestamp
	err = VerifyPeerSig(idA.Ed25519Public, idA.X25519Public, idB.X25519Public, sig2, oldTimestamp)
	if err == nil {
		t.Error("verification should have failed with out-of-window timestamp")
	}

	// Also test with timestamp 31s in the past
	pastTimestamp := now - 31
	sig3, err := idA.SignForPeer(idB.X25519Public, pastTimestamp)
	if err != nil {
		t.Fatalf("failed to sign for peer with past timestamp: %v", err)
	}

	err = VerifyPeerSig(idA.Ed25519Public, idA.X25519Public, idB.X25519Public, sig3, pastTimestamp)
	if err == nil {
		t.Error("verification should have failed with past timestamp outside window")
	}
}

func TestX25519Clamping(t *testing.T) {
	id, err := Generate()
	if err != nil {
		t.Fatalf("failed to generate identity: %v", err)
	}

	// Verify RFC 7748 clamping: bits 0,1,2 of byte[0] are cleared
	if id.X25519Private[0]&0b00000111 != 0 {
		t.Errorf("bits 0,1,2 of X25519Private[0] not cleared: got %08b, want bits 0-2 to be 0", id.X25519Private[0])
	}

	// Verify bit 7 of byte[31] is cleared
	if id.X25519Private[31]&0b10000000 != 0 {
		t.Errorf("bit 7 of X25519Private[31] not cleared: got %08b, want bit 7 to be 0", id.X25519Private[31])
	}

	// Verify bit 6 of byte[31] is set
	if id.X25519Private[31]&0b01000000 == 0 {
		t.Errorf("bit 6 of X25519Private[31] not set: got %08b, want bit 6 to be 1", id.X25519Private[31])
	}
}

func TestVerifyPeerSig_WrongEd25519Key(t *testing.T) {
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

	// A signs for B
	now := time.Now().Unix()
	sig, err := idA.SignForPeer(idB.X25519Public, now)
	if err != nil {
		t.Fatalf("failed to sign for peer: %v", err)
	}

	// Verify with C's Ed25519 public key should fail
	err = VerifyPeerSig(idC.Ed25519Public, idA.X25519Public, idB.X25519Public, sig, now)
	if err == nil {
		t.Error("verification should have failed with wrong Ed25519 key")
	}
}

func TestVerifyPeerSig_TamperedSig(t *testing.T) {
	idA, err := Generate()
	if err != nil {
		t.Fatalf("failed to generate identity A: %v", err)
	}

	idB, err := Generate()
	if err != nil {
		t.Fatalf("failed to generate identity B: %v", err)
	}

	// A signs for B
	now := time.Now().Unix()
	sig, err := idA.SignForPeer(idB.X25519Public, now)
	if err != nil {
		t.Fatalf("failed to sign for peer: %v", err)
	}

	// Tamper with the signature by flipping all bits in byte 0
	sig[0] ^= 0xFF

	// Verify should fail
	err = VerifyPeerSig(idA.Ed25519Public, idA.X25519Public, idB.X25519Public, sig, now)
	if err == nil {
		t.Error("verification should have failed with tampered signature")
	}
}

func TestVerifyPeerSig_SwappedKeys(t *testing.T) {
	idA, err := Generate()
	if err != nil {
		t.Fatalf("failed to generate identity A: %v", err)
	}

	idB, err := Generate()
	if err != nil {
		t.Fatalf("failed to generate identity B: %v", err)
	}

	// A signs for B with proper order (A_x25519 || B_x25519 || ts)
	now := time.Now().Unix()
	sig, err := idA.SignForPeer(idB.X25519Public, now)
	if err != nil {
		t.Fatalf("failed to sign for peer: %v", err)
	}

	// Verify with swapped keys (B_x25519 || A_x25519 || ts) should fail
	err = VerifyPeerSig(idA.Ed25519Public, idB.X25519Public, idA.X25519Public, sig, now)
	if err == nil {
		t.Error("verification should have failed with swapped X25519 keys")
	}
}

func TestX25519SigBinding(t *testing.T) {
	id, err := Generate()
	if err != nil {
		t.Fatalf("failed to generate identity: %v", err)
	}

	// Verify that X25519Sig is a valid Ed25519 signature over X25519Public
	if !ed25519.Verify(id.Ed25519Public, id.X25519Public[:], id.X25519Sig[:]) {
		t.Error("X25519Sig is not a valid Ed25519 signature over X25519Public")
	}
}

