// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package nat

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// encryptSignal encrypts payload for the recipient's X25519 public key.
// Wire format: [32 ephemeral X25519 pubkey][12 nonce][ciphertext+16 tag]
// The coord server relays these bytes opaquely — it cannot read the contents.
func encryptSignal(payload []byte, recipientX25519 [32]byte) ([]byte, error) {
	var ephPriv [32]byte
	if _, err := io.ReadFull(rand.Reader, ephPriv[:]); err != nil {
		return nil, err
	}
	// Clamp per RFC 7748
	ephPriv[0] &= 248
	ephPriv[31] &= 127
	ephPriv[31] |= 64

	ephPubSlice, err := curve25519.X25519(ephPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	var ephPub [32]byte
	copy(ephPub[:], ephPubSlice)

	shared, err := curve25519.X25519(ephPriv[:], recipientX25519[:])
	if err != nil {
		return nil, err
	}

	key := deriveKey(shared)

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	var nonce [12]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, err
	}

	ct := aead.Seal(nil, nonce[:], payload, nil)

	out := make([]byte, 32+12+len(ct))
	copy(out[0:32], ephPub[:])
	copy(out[32:44], nonce[:])
	copy(out[44:], ct)
	return out, nil
}

// decryptSignal decrypts a signal produced by encryptSignal.
func decryptSignal(data []byte, recipientX25519Private [32]byte) ([]byte, error) {
	if len(data) < 32+12+16 {
		return nil, errors.New("signal payload too short")
	}

	var ephPub [32]byte
	copy(ephPub[:], data[0:32])
	nonce := data[32:44]
	ct := data[44:]

	shared, err := curve25519.X25519(recipientX25519Private[:], ephPub[:])
	if err != nil {
		return nil, errors.New("signal DH failed")
	}

	key := deriveKey(shared)

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	plain, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, errors.New("signal authentication failed")
	}
	return plain, nil
}

// EncryptSignalFor is the exported wrapper for encryptSignal, used in tests.
func EncryptSignalFor(payload []byte, recipientX25519 [32]byte) ([]byte, error) {
	return encryptSignal(payload, recipientX25519)
}

// DecryptSignalWith is the exported wrapper for decryptSignal, used in tests.
func DecryptSignalWith(data []byte, recipientX25519Private [32]byte) ([]byte, error) {
	return decryptSignal(data, recipientX25519Private)
}

// deriveKey produces a 32-byte ChaCha20-Poly1305 key from a raw DH shared secret.
func deriveKey(shared []byte) []byte {
	r := hkdf.New(sha256.New, shared, nil, []byte("veld-nat-signal-v1"))
	key := make([]byte, 32)
	io.ReadFull(r, key) //nolint:errcheck — hkdf never returns an error for standard inputs
	return key
}
