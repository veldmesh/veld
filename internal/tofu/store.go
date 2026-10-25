// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT

// Package tofu implements Trust-On-First-Use Ed25519 fingerprint pinning.
// On the first successful handshake with a peer, their Ed25519 fingerprint is
// saved to disk. Subsequent handshakes from a different key for the same peer
// (same VPN address) are rejected — this catches a compromised coord server
// swapping pubkeys.
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

// Store persists Ed25519 fingerprints keyed by VPN address.
// It is safe for concurrent use.
type Store struct {
	path string
	mu   sync.Mutex
	pins map[string][32]byte // vpnAddr → SHA-256(Ed25519 pubkey)
}

// New loads a Store from path, or creates a fresh one if the file does not exist.
// Migrates old VPN-address-keyed entries (version 1 format) to version 2 format.
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

// Check performs the TOFU check for the given VPN address and Ed25519 public key.
//   - First time for this VPN address: pin the fingerprint, persist, return nil.
//   - Same fingerprint: return nil.
//   - Different fingerprint: return ErrFingerprintMismatch (caller must drop).
func (s *Store) Check(vpnAddr string, pub ed25519.PublicKey) error {
	fp := Fingerprint(pub)

	s.mu.Lock()
	defer s.mu.Unlock()

	if stored, ok := s.pins[vpnAddr]; ok {
		if stored != fp {
			return ErrFingerprintMismatch
		}
		return nil
	}

	// First connect for this VPN — trust and persist.
	s.pins[vpnAddr] = fp
	return s.save()
}

// Forget removes the pinned fingerprint for the given VPN address.
// The next handshake will re-pin. Returns an error only if the save fails.
func (s *Store) Forget(vpnAddr string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pins, vpnAddr)
	return s.save()
}

// ForgetByVPNAddr is an alias for Forget, kept for API compatibility.
func (s *Store) ForgetByVPNAddr(vpnAddr string) error {
	return s.Forget(vpnAddr)
}

// List returns a snapshot of all pinned fingerprints as a map from
// VPN address to hex-encoded SHA-256 fingerprint.
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
	VPNAddr     string `json:"vpn_addr"`
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
		// Try old format (version 1, peer_key only)
		var oldFormat struct {
			Version int `json:"version"`
			Pins    []struct {
				PeerKey     string `json:"peer_key"`
				Fingerprint string `json:"fingerprint"`
			} `json:"pins"`
		}
		if err := json.Unmarshal(data, &oldFormat); err == nil && len(oldFormat.Pins) > 0 {
			// Old format detected: migrate by dropping (can't verify without pubkey).
			// The next handshake will re-pin with the Ed25519 pubkey.
			return s.save()
		}
		return err
	}

	// Version 1 with vpn_addr but no ed25519_pub: drop and re-pin.
	needsMigration := false
	for _, p := range f.Pins {
		if p.VPNAddr != "" && p.Fingerprint != "" {
			continue
		}
		needsMigration = true
		break
	}

	if needsMigration {
		return s.save()
	}

	for _, p := range f.Pins {
		b, err := hex.DecodeString(p.Fingerprint)
		if err != nil || len(b) != 32 {
			continue // skip malformed entries rather than aborting
		}
		var fp [32]byte
		copy(fp[:], b)
		s.pins[p.VPNAddr] = fp
	}
	return nil
}

// save must be called with s.mu held.
func (s *Store) save() error {
	f := storeFile{Version: 2}
	for k, v := range s.pins {
		f.Pins = append(f.Pins, pinEntry{
			VPNAddr:     k,
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