// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package config

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/veldmesh/veld/internal/crypto"
	"golang.org/x/crypto/curve25519"
)

// KeystoreFile represents the JSON schema for storing an identity.
type KeystoreFile struct {
	Version          int    `json:"version"`
	Ed25519Private   string `json:"ed25519_private"`
	X25519Private    string `json:"x25519_private"`
	X25519PubkeySig  string `json:"x25519_pubkey_sig"`
}

// LoadOrGenerate loads the identity from path, or generates and saves a new one if the file doesn't exist.
func LoadOrGenerate(path string) (*crypto.Identity, error) {
	// Try to load existing identity
	id, err := Load(path)
	if err == nil {
		return id, nil
	}

	// If file doesn't exist, generate a new identity
	if errors.Is(err, os.ErrNotExist) {
		id, err := crypto.Generate()
		if err != nil {
			return nil, fmt.Errorf("failed to generate new identity: %w", err)
		}

		// Save the new identity
		if err := Save(path, id); err != nil {
			return nil, fmt.Errorf("failed to save generated identity: %w", err)
		}

		return id, nil
	}

	// Other errors
	return nil, err
}

// Load reads and deserialises an identity from path.
func Load(path string) (*crypto.Identity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read keystore file: %w", err)
	}

	var ksf KeystoreFile
	if err := json.Unmarshal(data, &ksf); err != nil {
		return nil, fmt.Errorf("failed to unmarshal keystore: %w", err)
	}

	if ksf.Version != 1 {
		return nil, fmt.Errorf("unsupported keystore version: %d", ksf.Version)
	}

	// Decode Ed25519 private key
	ed25519PrivBytes, err := base64.StdEncoding.DecodeString(ksf.Ed25519Private)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Ed25519 private key: %w", err)
	}

	ed25519Priv := ed25519.PrivateKey(ed25519PrivBytes)
	ed25519Pub := ed25519Priv.Public().(ed25519.PublicKey)

	// Decode X25519 private key
	x25519PrivBytes, err := base64.StdEncoding.DecodeString(ksf.X25519Private)
	if err != nil {
		return nil, fmt.Errorf("failed to decode X25519 private key: %w", err)
	}

	if len(x25519PrivBytes) != 32 {
		return nil, fmt.Errorf("invalid X25519 private key length: %d", len(x25519PrivBytes))
	}

	var x25519Priv [32]byte
	copy(x25519Priv[:], x25519PrivBytes)

	// Derive X25519 public key
	x25519PubBytes, err := curve25519.X25519(x25519Priv[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("failed to derive X25519 public key: %w", err)
	}

	var x25519Pub [32]byte
	copy(x25519Pub[:], x25519PubBytes)

	// Recompute X25519 signature from the loaded keys (do not trust the stored sig)
	x25519Sig := ed25519.Sign(ed25519Priv, x25519Pub[:])

	var sigArray [64]byte
	copy(sigArray[:], x25519Sig)

	id := &crypto.Identity{
		Ed25519Private: ed25519Priv,
		Ed25519Public:  ed25519Pub,
		X25519Private:  x25519Priv,
		X25519Public:   x25519Pub,
		X25519Sig:      sigArray,
	}

	return id, nil
}

// Save serialises and writes an identity to path (creates parent dirs, mode 0600).
func Save(path string, id *crypto.Identity) error {
	// Create parent directories if needed
	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("failed to create parent directories: %w", err)
		}
	}

	// Create keystore file structure
	ksf := KeystoreFile{
		Version:         1,
		Ed25519Private:  base64.StdEncoding.EncodeToString(id.Ed25519Private),
		X25519Private:   base64.StdEncoding.EncodeToString(id.X25519Private[:]),
		X25519PubkeySig: base64.StdEncoding.EncodeToString(id.X25519Sig[:]),
	}

	// Marshal to JSON
	data, err := json.MarshalIndent(ksf, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal keystore: %w", err)
	}

	// Write to file with mode 0600
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write keystore file: %w", err)
	}

	return nil
}
