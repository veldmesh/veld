// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"golang.org/x/crypto/curve25519"
)

// Identity holds the permanent peer identity.
type Identity struct {
	Ed25519Private ed25519.PrivateKey // 64 bytes
	Ed25519Public  ed25519.PublicKey  // 32 bytes
	X25519Private  [32]byte           // 32 bytes
	X25519Public   [32]byte           // 32 bytes
	X25519Sig      [64]byte           // Ed25519 sig over X25519Public
}

// Generate creates a fresh Identity with new Ed25519 and X25519 keypairs.
func Generate() (*Identity, error) {
	// Generate Ed25519 keypair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 keypair: %w", err)
	}

	// Generate X25519 keypair
	var x25519Priv [32]byte
	_, err = rand.Read(x25519Priv[:])
	if err != nil {
		return nil, fmt.Errorf("failed to generate random bytes for X25519 private key: %w", err)
	}

	// Clamp X25519 private key according to RFC 7748
	x25519Priv[0] &= 248   // clear bits 0, 1, 2 of byte[0]
	x25519Priv[31] &= 127  // clear bit 7 of byte[31]
	x25519Priv[31] |= 64   // set bit 6 of byte[31]

	// Derive X25519 public key
	x25519Pub, err := curve25519.X25519(x25519Priv[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("failed to derive X25519 public key: %w", err)
	}

	var x25519PubArray [32]byte
	copy(x25519PubArray[:], x25519Pub)

	// Create X25519 signature: Ed25519 signature over X25519 public key bytes
	x25519Sig := ed25519.Sign(priv, x25519PubArray[:])

	var sigArray [64]byte
	copy(sigArray[:], x25519Sig)

	id := &Identity{
		Ed25519Private: priv,
		Ed25519Public:  pub,
		X25519Private:  x25519Priv,
		X25519Public:   x25519PubArray,
		X25519Sig:      sigArray,
	}

	// Self-test: verify the generated identity is internally consistent
	if err := id.selfTest(); err != nil {
		return nil, fmt.Errorf("identity self-test failed: %w", err)
	}

	return id, nil
}

// selfTest validates the generated identity is internally consistent.
// This mirrors the checks in config.Load() and catches any RNG or logic bugs.
func (id *Identity) selfTest() error {
	// 1. Ed25519 private key must be the correct size
	if len(id.Ed25519Private) != ed25519.PrivateKeySize {
		return fmt.Errorf("Ed25519 private key size mismatch: got %d, want %d", len(id.Ed25519Private), ed25519.PrivateKeySize)
	}

	// 2. Ed25519 public key must match the private key
	if !id.Ed25519Public.Equal(id.Ed25519Private.Public().(ed25519.PublicKey)) {
		return fmt.Errorf("Ed25519 public key does not match private key")
	}

	// 3. Ed25519 sign/verify self-test
	testMsg := []byte("veld-keystore-self-test")
	sig := ed25519.Sign(id.Ed25519Private, testMsg)
	if !ed25519.Verify(id.Ed25519Public, testMsg, sig) {
		return fmt.Errorf("Ed25519 sign/verify self-test failed")
	}

	// 4. X25519 private key must not be all zeros
	allZero := true
	for _, b := range id.X25519Private {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return fmt.Errorf("X25519 private key is all zeros")
	}

	// 5. X25519 public key must derive correctly from private key
	derivedPub, err := curve25519.X25519(id.X25519Private[:], curve25519.Basepoint)
	if err != nil {
		return fmt.Errorf("failed to derive X25519 public key: %w", err)
	}
	var derivedPubArray [32]byte
	copy(derivedPubArray[:], derivedPub)
	if derivedPubArray != id.X25519Public {
		return fmt.Errorf("X25519 public key does not match private key derivation")
	}

	// 6. X25519Sig must be a valid Ed25519 signature over X25519Public
	if !ed25519.Verify(id.Ed25519Public, id.X25519Public[:], id.X25519Sig[:]) {
		return fmt.Errorf("X25519Sig is not a valid Ed25519 signature over X25519Public")
	}

	return nil
}

// Fingerprint returns a hex-encoded SHA-256 of the Ed25519 public key.
func (id *Identity) Fingerprint() string {
	hash := sha256.Sum256(id.Ed25519Public)
	return hex.EncodeToString(hash[:])
}

// SignForPeer returns an Ed25519 signature over (ourX25519Public || theirX25519Public || unixTimestampSeconds).
// Used in the Noise IK handshake payload.
func (id *Identity) SignForPeer(theirX25519Public [32]byte, timestampSec int64) ([64]byte, error) {
	// Construct message: ourX25519Public || theirX25519Public || timestampSec (big-endian int64)
	message := make([]byte, 32+32+8)
	copy(message[0:32], id.X25519Public[:])
	copy(message[32:64], theirX25519Public[:])

	// Encode timestamp as big-endian int64
	for i := 0; i < 8; i++ {
		message[64+i] = byte((timestampSec >> (56 - 8*i)) & 0xFF)
	}

	sig := ed25519.Sign(id.Ed25519Private, message)

	var sigArray [64]byte
	copy(sigArray[:], sig)
	return sigArray, nil
}

// VerifyPeerSig verifies the signature a remote peer included in their handshake message.
// peerEd25519Public: their permanent Ed25519 public key
// peerX25519Public:  their X25519 static key (from handshake)
// ourX25519Public:   our X25519 static key
// sig:               the signature to verify
// timestampSec:      timestamp from the handshake; must be within ±30s of now
func VerifyPeerSig(peerEd25519Public ed25519.PublicKey, peerX25519Public, ourX25519Public [32]byte, sig [64]byte, timestampSec int64) error {
	// Check timestamp is within ±30s of now
	now := time.Now().Unix()
	if diff := now - timestampSec; diff < -30 || diff > 30 {
		return fmt.Errorf("timestamp out of window: peer timestamp %d, now %d (diff %d seconds, max ±30s)", timestampSec, now, diff)
	}

	// Construct message: peerX25519Public || ourX25519Public || timestampSec (big-endian int64)
	message := make([]byte, 32+32+8)
	copy(message[0:32], peerX25519Public[:])
	copy(message[32:64], ourX25519Public[:])

	// Encode timestamp as big-endian int64
	for i := 0; i < 8; i++ {
		message[64+i] = byte((timestampSec >> (56 - 8*i)) & 0xFF)
	}

	// Verify signature
	if !ed25519.Verify(peerEd25519Public, message, sig[:]) {
		return fmt.Errorf("invalid peer signature")
	}

	return nil
}