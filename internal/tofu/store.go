// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT

// Package tofu implements Trust-On-First-Use Ed25519 fingerprint pinning.
// On the first successful handshake with a peer, their Ed25519 fingerprint is
// saved to disk. Subsequent handshakes from a different key for the same peer
// are rejected — this catches a compromised coord server swapping pubkeys.
package tofu

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sync"
)

// ErrFingerprintMismatch is returned when a peer's Ed25519 fingerprint differs
// from the pinned value. The handshake MUST be silently dropped — do not
// downgrade to warn-only mode.
var ErrFingerprintMismatch = errors.New("TOFU: Ed25519 fingerprint mismatch — possible MITM; rejecting")

// Fingerprint computes the canonical SHA-256 fingerprint of an Ed25519 public key.
func Fingerprint(pub ed25519.PublicKey) [32]byte {
	return sha256.Sum256(pub)
}

// Store persists Ed25519 fingerprints keyed by a stable peer identifier
// (typically the peer's VPN IP address string). It is safe for concurrent use.
type Store struct {
	path string
	mu   sync.Mutex
	pins map[string][32]byte // peerKey → SHA-256(Ed25519 pubkey)
}

// New loads a Store from path, or creates a fresh one if the file does not exist.
func New(path string) (*Store, error) {
	s := &Store{
		path: path,
		pins: make(map[string][32]byte),
	}
	if err := s.load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return s, nil
}

// Check performs the TOFU check for peerKey against the Ed25519 key seen in
// this handshake.
//   - First time: pin the fingerprint, persist, return nil.
//   - Matching fingerprint: return nil.
//   - Mismatched fingerprint: return ErrFingerprintMismatch (caller must drop).
func (s *Store) Check(peerKey string, pub ed25519.PublicKey) error {
	fp := Fingerprint(pub)

	s.mu.Lock()
	defer s.mu.Unlock()

	if stored, ok := s.pins[peerKey]; ok {
		if stored != fp {
			return ErrFingerprintMismatch
		}
		return nil
	}

	// First connect — trust and persist.
	s.pins[peerKey] = fp
	return s.save()
}

// Forget removes the pinned fingerprint for peerKey.
// The next handshake will re-pin. Returns an error only if the save fails.
func (s *Store) Forget(peerKey string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pins, peerKey)
	return s.save()
}

// List returns a snapshot of all pinned fingerprints as a map from peerKey to
// hex-encoded SHA-256 fingerprint.
func (s *Store) List() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]string, len(s.pins))
	for k, v := range s.pins {
		out[k] = hex.EncodeToString(v[:])
	}
	return out
}

// -- persistence -------------------------------------------------------

type pinEntry struct {
	PeerKey     string `json:"peer_key"`
	Fingerprint string `json:"fingerprint"` // hex SHA-256
}

type storeFile struct {
	Version int        `json:"version"`
	Pins    []pinEntry `json:"pins"`
}

func (s *Store) load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	var f storeFile
	if err := json.Unmarshal(data, &f); err != nil {
		return err
	}
	for _, p := range f.Pins {
		b, err := hex.DecodeString(p.Fingerprint)
		if err != nil || len(b) != 32 {
			continue // skip malformed entries rather than aborting
		}
		var fp [32]byte
		copy(fp[:], b)
		s.pins[p.PeerKey] = fp
	}
	return nil
}

// save must be called with s.mu held.
func (s *Store) save() error {
	f := storeFile{Version: 1}
	for k, v := range s.pins {
		f.Pins = append(f.Pins, pinEntry{
			PeerKey:     k,
			Fingerprint: hex.EncodeToString(v[:]),
		})
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	// Write atomically: write to a temp file then rename.
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
