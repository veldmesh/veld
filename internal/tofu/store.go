// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT

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

var ErrFingerprintMismatch = errors.New("TOFU: Ed25519 fingerprint mismatch -- possible MITM; rejecting")

func Fingerprint(pub ed25519.PublicKey) [32]byte {
	return sha256.Sum256(pub)
}

func pubKeyString(pub ed25519.PublicKey) string {
	return hex.EncodeToString(pub)
}

type Store struct {
	path string
	mu   sync.Mutex
	// pins maps Ed25519 public key (hex) -> pinValue.
	// Primary key is Ed25519 pubkey so static config with reused VPN addresses
	// can distinguish different peers.
	pins map[string]pinValue
	// vpnToPub maps VPN address -> Ed25519 pubkey (hex) for TOFU enforcement.
	// Ensures a VPN address is only associated with one Ed25519 identity.
	vpnToPub map[string]string
}

type pinValue struct {
	Fingerprint [32]byte
	Ed25519Pub  string
	VPNAddr     string
	// PrevVPNAddrs are addresses this key was pinned at before it moved.
	// They stay reserved for the key: if moving released them, whoever
	// controls the peer list could move a peer away and then put a new key
	// at its old address.
	PrevVPNAddrs []string
}

// maxPrevVPNAddrs bounds how many old addresses one pin keeps reserved.
const maxPrevVPNAddrs = 16

func New(path string) (*Store, error) {
	s := &Store{
		path:     path,
		pins:     make(map[string]pinValue),
		vpnToPub: make(map[string]string),
	}
	if err := s.load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return s, nil
}

// Check verifies the peer's Ed25519 public key against the pinned fingerprint.
// The pin is keyed by Ed25519 pubkey, but TOFU enforcement ensures a VPN address
// is only ever associated with one Ed25519 identity.
// If the same pubkey appears at a different VPN address, the VPN address is
// updated and the old one stays reserved for that key.
// If a pubkey appears at a VPN address that is pinned (now or before) to a
// different pubkey, the check fails (TOFU violation / possible MITM).
func (s *Store) Check(vpnAddr string, pub ed25519.PublicKey) error {
	fp := Fingerprint(pub)
	pubStr := pubKeyString(pub)

	s.mu.Lock()
	defer s.mu.Unlock()

	// Case 1: This pubkey is already known.
	if stored, ok := s.pins[pubStr]; ok {
		if stored.Fingerprint != fp {
			return ErrFingerprintMismatch
		}
		// Update VPN address if changed (peer moved).
		if stored.VPNAddr != vpnAddr {
			if owner, ok := s.vpnToPub[vpnAddr]; ok && owner != pubStr {
				return ErrFingerprintMismatch
			}
			prev := []string{stored.VPNAddr}
			for _, a := range stored.PrevVPNAddrs {
				if a != vpnAddr && a != stored.VPNAddr {
					prev = append(prev, a)
				}
			}
			if len(prev) > maxPrevVPNAddrs {
				// Release the oldest reservations.
				for _, a := range prev[maxPrevVPNAddrs:] {
					delete(s.vpnToPub, a)
				}
				prev = prev[:maxPrevVPNAddrs]
			}
			stored.PrevVPNAddrs = prev
			stored.VPNAddr = vpnAddr
			s.vpnToPub[vpnAddr] = pubStr
			s.pins[pubStr] = stored
			return s.save()
		}
		return nil
	}

	// Case 2: New pubkey. Check if this VPN address is already pinned to a different pubkey.
	if existingPub, ok := s.vpnToPub[vpnAddr]; ok && existingPub != pubStr {
		// TOFU violation: different identity claiming same VPN address.
		return ErrFingerprintMismatch
	}

	// Case 3: New pubkey, VPN address not pinned (or pinned to same pubkey which is impossible here).
	s.pins[pubStr] = pinValue{
		Fingerprint: fp,
		Ed25519Pub:  pubStr,
		VPNAddr:     vpnAddr,
	}
	s.vpnToPub[vpnAddr] = pubStr
	return s.save()
}

// Forget removes the pin for the given Ed25519 public key.
func (s *Store) Forget(pub ed25519.PublicKey) error {
	pubStr := pubKeyString(pub)
	s.mu.Lock()
	defer s.mu.Unlock()
	if v, ok := s.pins[pubStr]; ok {
		s.unpin(v)
	}
	return s.save()
}

// unpin removes v and every address reserved for it. s.mu must be held.
func (s *Store) unpin(v pinValue) {
	for _, a := range append([]string{v.VPNAddr}, v.PrevVPNAddrs...) {
		if s.vpnToPub[a] == v.Ed25519Pub {
			delete(s.vpnToPub, a)
		}
	}
	delete(s.pins, v.Ed25519Pub)
}

// ForgetByVPNAddr removes the pin associated with a VPN address, current or
// previous, together with every address reserved for that key.
// Used by the CLI `veld tofu forget <vpn-addr>` command.
func (s *Store) ForgetByVPNAddr(vpnAddr string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if pubStr, ok := s.vpnToPub[vpnAddr]; ok {
		if v, ok := s.pins[pubStr]; ok {
			s.unpin(v)
		} else {
			delete(s.vpnToPub, vpnAddr)
		}
	}
	return s.save()
}

// List returns a map of VPN address -> fingerprint for display purposes.
func (s *Store) List() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]string, len(s.pins))
	for _, v := range s.pins {
		out[v.VPNAddr] = hex.EncodeToString(v.Fingerprint[:])
	}
	return out
}

type pinEntry struct {
	VPNAddr      string   `json:"vpn_addr"`
	Ed25519Pub   string   `json:"ed25519_pub"`
	Fingerprint  string   `json:"fingerprint"`
	PrevVPNAddrs []string `json:"prev_vpn_addrs,omitempty"`
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
	if err := json.Unmarshal(data, &f); err == nil {
		valid := false
		for _, p := range f.Pins {
			if p.Ed25519Pub != "" && p.Fingerprint != "" {
				valid = true
				break
			}
		}
		if valid {
			for _, p := range f.Pins {
				if p.Ed25519Pub == "" || p.Fingerprint == "" {
					continue
				}
				b, err := hex.DecodeString(p.Fingerprint)
				if err != nil || len(b) != 32 {
					continue
				}
				var fp [32]byte
				copy(fp[:], b)
				pubStr := p.Ed25519Pub
				s.pins[pubStr] = pinValue{
					Fingerprint:  fp,
					Ed25519Pub:   pubStr,
					VPNAddr:      p.VPNAddr,
					PrevVPNAddrs: p.PrevVPNAddrs,
				}
				s.vpnToPub[p.VPNAddr] = pubStr
				for _, a := range p.PrevVPNAddrs {
					if _, taken := s.vpnToPub[a]; !taken {
						s.vpnToPub[a] = pubStr
					}
				}
			}
			return nil
		}
	}

	// v1 format: peer_key (VPN address) + fingerprint, no ed25519_pub.
	// These cannot be migrated to v3 because we don't have the pubkey.
	// They will be dropped and re-pinned on next handshake.
	var oldFormat struct {
		Version int `json:"version"`
		Pins    []struct {
			PeerKey     string `json:"peer_key"`
			Fingerprint string `json:"fingerprint"`
		} `json:"pins"`
	}
	if err := json.Unmarshal(data, &oldFormat); err == nil && len(oldFormat.Pins) > 0 {
		// v1 entries have no pubkey -- drop them.
		return s.save()
	}

	return nil
}

func (s *Store) save() error {
	f := storeFile{Version: 3}
	for _, v := range s.pins {
		f.Pins = append(f.Pins, pinEntry{
			VPNAddr:      v.VPNAddr,
			Ed25519Pub:   v.Ed25519Pub,
			Fingerprint:  hex.EncodeToString(v.Fingerprint[:]),
			PrevVPNAddrs: v.PrevVPNAddrs,
		})
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}