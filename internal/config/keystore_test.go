// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package config_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/veldmesh/veld/internal/config"
)

func TestKeystoreSaveAndLoad(t *testing.T) {
	tmpdir, err := os.MkdirTemp("", "keystore-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpdir)

	keyPath := filepath.Join(tmpdir, "identity.key")

	idOriginal, err := config.LoadOrGenerate(keyPath)
	if err != nil {
		t.Fatalf("LoadOrGenerate (new): %v", err)
	}

	// File must exist
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("keystore file not created: %v", err)
	}

	// Load it back
	idLoaded, err := config.Load(keyPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if idLoaded.Fingerprint() != idOriginal.Fingerprint() {
		t.Error("fingerprint mismatch after save/load")
	}
	if idLoaded.X25519Public != idOriginal.X25519Public {
		t.Error("X25519 public key mismatch after save/load")
	}

	// Second LoadOrGenerate must return the same identity
	idAgain, err := config.LoadOrGenerate(keyPath)
	if err != nil {
		t.Fatalf("LoadOrGenerate (existing): %v", err)
	}
	if idAgain.Fingerprint() != idOriginal.Fingerprint() {
		t.Error("LoadOrGenerate returned different identity on second call")
	}
}

func TestKeystorePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits not applicable on Windows")
	}
	tmpdir, err := os.MkdirTemp("", "keystore-perm-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpdir)

	keyPath := filepath.Join(tmpdir, "subdir", "identity.key")

	_, err = config.LoadOrGenerate(keyPath)
	if err != nil {
		t.Fatalf("LoadOrGenerate: %v", err)
	}

	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat keystore file: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("keystore file has wrong permissions: got %o, want 0600", info.Mode().Perm())
	}
}

func TestKeystoreInvalidJSON(t *testing.T) {
	tmpdir, err := os.MkdirTemp("", "keystore-invalid-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpdir)

	keyPath := filepath.Join(tmpdir, "invalid.key")

	// Write invalid JSON to the file
	if err := os.WriteFile(keyPath, []byte("{invalid json"), 0600); err != nil {
		t.Fatalf("failed to write invalid JSON file: %v", err)
	}

	// Load should fail
	_, err = config.Load(keyPath)
	if err == nil {
		t.Error("Load should have failed with invalid JSON")
	}
}

func TestKeystoreWrongVersion(t *testing.T) {
	tmpdir, err := os.MkdirTemp("", "keystore-version-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpdir)

	keyPath := filepath.Join(tmpdir, "wrong_version.key")

	// Write valid JSON with wrong version
	invalidContent := `{"version":99,"ed25519_private":"","x25519_private":"","x25519_pubkey_sig":""}`
	if err := os.WriteFile(keyPath, []byte(invalidContent), 0600); err != nil {
		t.Fatalf("failed to write keystore file: %v", err)
	}

	// Load should fail
	_, err = config.Load(keyPath)
	if err == nil {
		t.Error("Load should have failed with wrong version")
	}
}

func TestKeystoreLoadOrGenerate_IsIdempotent(t *testing.T) {
	tmpdir, err := os.MkdirTemp("", "keystore-idempotent-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpdir)

	keyPath := filepath.Join(tmpdir, "identity.key")

	// Call LoadOrGenerate three times on the same path
	id1, err := config.LoadOrGenerate(keyPath)
	if err != nil {
		t.Fatalf("first LoadOrGenerate: %v", err)
	}

	id2, err := config.LoadOrGenerate(keyPath)
	if err != nil {
		t.Fatalf("second LoadOrGenerate: %v", err)
	}

	id3, err := config.LoadOrGenerate(keyPath)
	if err != nil {
		t.Fatalf("third LoadOrGenerate: %v", err)
	}

	// All three fingerprints must be equal
	fp1 := id1.Fingerprint()
	fp2 := id2.Fingerprint()
	fp3 := id3.Fingerprint()

	if fp1 != fp2 {
		t.Errorf("fingerprint mismatch between first and second call: %s != %s", fp1, fp2)
	}

	if fp2 != fp3 {
		t.Errorf("fingerprint mismatch between second and third call: %s != %s", fp2, fp3)
	}
}
