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

type Store struct {
	path string
	mu   sync.Mutex
	pins map[string]pinValue
}

type pinValue struct {
	Fingerprint [32]byte
	Ed25519Pub  string
}

func New(path string) (*Store, error) {
	s := &Store{
		path: path,
		pins: make(map[string]pinValue),
	}
	if err := s.load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return s, nil
}

func (s *Store) Check(vpnAddr string, pub ed25519.PublicKey) error {
	fp := Fingerprint(pub)

	s.mu.Lock()
	defer s.mu.Unlock()

	if stored, ok := s.pins[vpnAddr]; ok {
		if stored.Fingerprint != fp {
			return ErrFingerprintMismatch
		}
		return nil
	}

	s.pins[vpnAddr] = pinValue{
		Fingerprint: fp,
		Ed25519Pub:  hex.EncodeToString(pub),
	}
	return s.save()
}

func (s *Store) Forget(vpnAddr string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pins, vpnAddr)
	return s.save()
}

func (s *Store) ForgetByVPNAddr(vpnAddr string) error {
	return s.Forget(vpnAddr)
}

func (s *Store) List() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]string, len(s.pins))
	for k, v := range s.pins {
		out[k] = hex.EncodeToString(v.Fingerprint[:])
	}
	return out
}

type pinEntry struct {
	VPNAddr     string `json:"vpn_addr"`
	Ed25519Pub  string `json:"ed25519_pub"`
	Fingerprint string `json:"fingerprint"`
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
			if p.VPNAddr != "" && p.Fingerprint != "" {
				valid = true
				break
			}
		}
		if valid {
			for _, p := range f.Pins {
				if p.VPNAddr == "" || p.Ed25519Pub == "" || p.Fingerprint == "" {
					continue
				}
				b, err := hex.DecodeString(p.Fingerprint)
				if err != nil || len(b) != 32 {
					continue
				}
				var fp [32]byte
				copy(fp[:], b)
				s.pins[p.VPNAddr] = pinValue{
					Fingerprint: fp,
					Ed25519Pub:  p.Ed25519Pub,
				}
			}
			return nil
		}
	}

	var oldFormat struct {
		Version int `json:"version"`
		Pins    []struct {
			PeerKey     string `json:"peer_key"`
			Fingerprint string `json:"fingerprint"`
		} `json:"pins"`
	}
	if err := json.Unmarshal(data, &oldFormat); err == nil && len(oldFormat.Pins) > 0 {
		return s.save()
	}

	return nil
}

func (s *Store) save() error {
	f := storeFile{Version: 2}
	for k, v := range s.pins {
		f.Pins = append(f.Pins, pinEntry{
			VPNAddr:     k,
			Ed25519Pub:  v.Ed25519Pub,
			Fingerprint: hex.EncodeToString(v.Fingerprint[:]),
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
