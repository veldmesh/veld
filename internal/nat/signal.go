// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package nat

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// NAT signal wire format, version 1:
//
//	[1]byte   version (signalVersion)
//	[8]byte   unix timestamp, big-endian seconds
//	[64]byte  Ed25519 signature by the sender's identity key
//	[N]byte   encrypted blob: [32 ephemeral X25519 pubkey][12 nonce][ciphertext+16 tag]
//
// The signature covers the domain-separated message:
//
//	"veld-nat-signal-v1" || fromPeerID (32) || toPeerID (32) || timestamp (8) || encrypted blob
//
// where the peer IDs are the raw Ed25519 public keys exactly as registered
// with coord. The recipient verifies the signature against the sender's
// Ed25519 public key from its peer table, so a signal is only accepted if it
// really comes from a peer of the same network. Signals in any earlier,
// unsigned format (which start directly with the ephemeral key) are
// rejected — pre-1.0, no compatibility.
const (
	// signalVersion is the wire version byte of authenticated NAT signals.
	signalVersion = 1

	// signalDomain prefixes the signed message, keeping NAT signal
	// signatures distinct from every other Ed25519 use in the protocol.
	signalDomain = "veld-nat-signal-v1"

	// ed25519SignatureSize and ed25519PublicKeySize are the signature and
	// public key sizes the wire format above is pinned to. They are
	// defined locally instead of referencing crypto/ed25519's values so
	// the wire format stays explicit and can never silently shift if the
	// stdlib constants ever change.
	ed25519SignatureSize = 64
	ed25519PublicKeySize = 32

	// signalMaxAgeSec is how old a signal may be before it is rejected,
	// and signalMaxSkewSec how far in the future its timestamp may be.
	// Together they form the anti-replay window. The window is a fixed
	// protocol constant, deliberately NOT configurable: sender and
	// recipient must agree on it, and widening it per deployment would
	// weaken the replay bound the signature timestamp provides.
	//
	// DEPLOYMENT CONSTRAINT: peers must keep their clocks synchronized
	// (NTP or equivalent) to well within this window. Hosts whose clocks
	// drift more than ~60 s apart (unsynced embedded devices/VMs) have
	// their signals rejected, so hole punching fails and connections
	// fall back to the relay path. This adds no new requirement: the
	// Noise handshake already rejects peers whose clocks are more than
	// ±30 s apart (crypto.VerifyPeerSig), so any deployment that can run
	// Veld at all already satisfies the signal window.
	signalMaxAgeSec  = 60
	signalMaxSkewSec = 60

	// signalHeaderLen is the fixed part before the encrypted blob:
	// version byte + timestamp + signature.
	signalHeaderLen = 1 + 8 + ed25519SignatureSize

	// signalMinLen is the smallest well-formed envelope: header plus the
	// 32-byte ephemeral X25519 key, 12-byte nonce and 16-byte AEAD tag.
	signalMinLen = signalHeaderLen + 32 + 12 + 16

	// signalMaxLen bounds how large an accepted envelope may be. A real
	// signal is a small JSON candidate list (well under 2 KiB); anything
	// larger is abusive. This caps the memory a single in-flight or held
	// signal can consume — held buffers bound the entry count, this
	// bounds each entry.
	signalMaxLen = 16 << 10
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

// signalSignedMessage builds the domain-separated message covered by the
// sender's Ed25519 signature.
func signalSignedMessage(from, to [32]byte, ts int64, encrypted []byte) []byte {
	msg := make([]byte, 0, len(signalDomain)+64+8+len(encrypted))
	msg = append(msg, signalDomain...)
	msg = append(msg, from[:]...)
	msg = append(msg, to[:]...)
	var tsB [8]byte
	binary.BigEndian.PutUint64(tsB[:], uint64(ts))
	msg = append(msg, tsB[:]...)
	msg = append(msg, encrypted...)
	return msg
}

// sealSignal authenticates an encrypted signal blob with the sender's
// Ed25519 identity key and returns the version-1 envelope.
func sealSignal(encrypted []byte, from, to [32]byte, signer ed25519.PrivateKey, ts int64) []byte {
	msg := signalSignedMessage(from, to, ts, encrypted)
	sig := ed25519.Sign(signer, msg)

	out := make([]byte, signalHeaderLen+len(encrypted))
	out[0] = signalVersion
	binary.BigEndian.PutUint64(out[1:9], uint64(ts))
	copy(out[9:signalHeaderLen], sig)
	copy(out[signalHeaderLen:], encrypted)
	return out
}

// openSignal validates a sealed signal envelope: it must carry the explicit
// wire version, a timestamp within the replay window, and a valid signature
// by the sender's registered Ed25519 key, which must match the claimed
// sender. Returns the encrypted blob on success.
func openSignal(envelope []byte, from, to [32]byte, senderKey ed25519.PublicKey, nowSec int64) ([]byte, error) {
	if len(envelope) < signalMinLen {
		return nil, errors.New("signal envelope too short")
	}
	if len(envelope) > signalMaxLen {
		return nil, errors.New("signal envelope too large")
	}
	if envelope[0] != signalVersion {
		return nil, errors.New("unsupported signal version")
	}
	if len(senderKey) != ed25519PublicKeySize {
		return nil, errors.New("invalid sender key")
	}
	// The claimed sender must be exactly the peer the key was registered for.
	if !bytes.Equal(senderKey, from[:]) {
		return nil, errors.New("sender key does not match claimed peer")
	}

	ts := int64(binary.BigEndian.Uint64(envelope[1:9]))
	if age := nowSec - ts; age > signalMaxAgeSec {
		return nil, errors.New("signal expired")
	}
	if skew := ts - nowSec; skew > signalMaxSkewSec {
		return nil, errors.New("signal timestamp too far in the future")
	}

	sig := envelope[9 : 9+ed25519SignatureSize]
	encrypted := envelope[signalHeaderLen:]
	if !ed25519.Verify(senderKey, signalSignedMessage(from, to, ts, encrypted), sig) {
		return nil, errors.New("invalid signal signature")
	}
	return encrypted, nil
}

// holdableSignal reports whether a sealed envelope is worth buffering for
// later authentication, which happens when Start consumes it once the
// sender's session exists. It is a cheap pre-filter on the parts of the
// header that need no sender key — size, version byte, and replay window —
// so garbage (replays, old-format bytes, oversized blobs) is never held.
// Everything it rejects would also fail openSignal later; it only prunes
// early to keep the bounded hold buffer free of dead weight.
func holdableSignal(envelope []byte, nowSec int64) bool {
	if len(envelope) < signalMinLen || len(envelope) > signalMaxLen {
		return false
	}
	if envelope[0] != signalVersion {
		return false
	}
	ts := int64(binary.BigEndian.Uint64(envelope[1:9]))
	return ts >= nowSec-signalMaxAgeSec && ts <= nowSec+signalMaxSkewSec
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
