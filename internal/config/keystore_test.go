// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package config_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/veldmesh/veld/internal/config"
	"golang.org/x/crypto/curve25519"
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

// TestKeystoreCorrupted tests loading of corrupted keystore files.
// Table-driven test for various corruption scenarios.
func TestKeystoreCorrupted(t *testing.T) {
	// Generate a valid identity to start from
	id, err := config.LoadOrGenerate("/tmp/valid_keystore_test.key")
	if err != nil {
		t.Fatalf("failed to generate valid identity: %v", err)
	}
	defer os.Remove("/tmp/valid_keystore_test.key")

	// Create a valid keystore file structure
	validKsf := map[string]interface{}{
		"version":            1,
		"ed25519_private":    base64.StdEncoding.EncodeToString(id.Ed25519Private),
		"x25519_private":     base64.StdEncoding.EncodeToString(id.X25519Private[:]),
		"x25519_pubkey_sig":  base64.StdEncoding.EncodeToString(id.X25519Sig[:]),
	}

	tests := []struct {
		name        string
		modify      func(map[string]interface{})
		wantErrMsg  string
	}{
		{
			name: "short Ed25519 private key (32 bytes instead of 64)",
			modify: func(ksf map[string]interface{}) {
				// Use only the seed (first 32 bytes)
				ksf["ed25519_private"] = base64.StdEncoding.EncodeToString(id.Ed25519Private[:32])
			},
			wantErrMsg: "invalid Ed25519 private key length",
		},
		{
			name: "long Ed25519 private key (72 bytes)",
			modify: func(ksf map[string]interface{}) {
				extra := make([]byte, 8)
				rand.Read(extra)
				ksf["ed25519_private"] = base64.StdEncoding.EncodeToString(append(id.Ed25519Private, extra...))
			},
			wantErrMsg: "invalid Ed25519 private key length",
		},
		{
			name: "Ed25519 seed/public mismatch",
			modify: func(ksf map[string]interface{}) {
				// Replace the public key portion (last 32 bytes) with random bytes
				corrupted := make([]byte, ed25519.PrivateKeySize)
				copy(corrupted[:32], id.Ed25519Private[:32]) // keep seed
				rand.Read(corrupted[32:])                    // corrupt public key
				ksf["ed25519_private"] = base64.StdEncoding.EncodeToString(corrupted)
			},
			wantErrMsg: "Ed25519 sign/verify self-test failed",
		},
		{
			name: "all-zero X25519 private key",
			modify: func(ksf map[string]interface{}) {
				ksf["x25519_private"] = base64.StdEncoding.EncodeToString(make([]byte, 32))
			},
			wantErrMsg: "X25519 private key is all zeros",
		},
		{
			name: "short X25519 private key (16 bytes)",
			modify: func(ksf map[string]interface{}) {
				ksf["x25519_private"] = base64.StdEncoding.EncodeToString(make([]byte, 16))
			},
			wantErrMsg: "invalid X25519 private key length",
		},
		{
			name: "long X25519 private key (48 bytes)",
			modify: func(ksf map[string]interface{}) {
				ksf["x25519_private"] = base64.StdEncoding.EncodeToString(make([]byte, 48))
			},
			wantErrMsg: "invalid X25519 private key length",
		},
		{
			name: "corrupted X25519 public key signature",
			modify: func(ksf map[string]interface{}) {
				ksf["x25519_pubkey_sig"] = base64.StdEncoding.EncodeToString(make([]byte, 64))
			},
			wantErrMsg: "", // Load recomputes the signature, so this should still load
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpdir, err := os.MkdirTemp("", "keystore-corrupt-")
			if err != nil {
				t.Fatalf("failed to create temp dir: %v", err)
			}
			defer os.RemoveAll(tmpdir)

			keyPath := filepath.Join(tmpdir, "corrupt.key")

			// Copy valid and apply modification
			ksf := make(map[string]interface{})
			for k, v := range validKsf {
				ksf[k] = v
			}
			tt.modify(ksf)

			data, err := json.MarshalIndent(ksf, "", "  ")
			if err != nil {
				t.Fatalf("failed to marshal keystore: %v", err)
			}

			if err := os.WriteFile(keyPath, data, 0600); err != nil {
				t.Fatalf("failed to write keystore file: %v", err)
			}

			_, err = config.Load(keyPath)
			if tt.wantErrMsg == "" {
				if err != nil {
					t.Errorf("Load should have succeeded but failed: %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("Load should have failed with %q but succeeded", tt.wantErrMsg)
				} else if !contains(err.Error(), tt.wantErrMsg) {
					t.Errorf("Load error %q does not contain expected %q", err.Error(), tt.wantErrMsg)
				}
			}
		})
	}
}

// TestKeystoreSelfTestGenerate verifies that Generate() produces an identity
// that passes the same self-test as Load().
func TestKeystoreSelfTestGenerate(t *testing.T) {
	id, err := config.LoadOrGenerate("/tmp/selftest_generate.key")
	if err != nil {
		t.Fatalf("LoadOrGenerate failed: %v", err)
	}
	defer os.Remove("/tmp/selftest_generate.key")

	// The identity should be valid and pass all internal checks
	if len(id.Ed25519Private) != ed25519.PrivateKeySize {
		t.Errorf("Ed25519 private key size: got %d, want %d", len(id.Ed25519Private), ed25519.PrivateKeySize)
	}

	// Verify Ed25519 public key matches
	if !id.Ed25519Public.Equal(id.Ed25519Private.Public().(ed25519.PublicKey)) {
		t.Error("Ed25519 public key does not match private key")
	}

	// Verify X25519 public key derives from private
	derivedPub, err := curve25519.X25519(id.X25519Private[:], curve25519.Basepoint)
	if err != nil {
		t.Fatalf("X25519 derivation failed: %v", err)
	}
	var derivedPubArray [32]byte
	copy(derivedPubArray[:], derivedPub)
	if derivedPubArray != id.X25519Public {
		t.Error("X25519 public key does not match derivation from private key")
	}

	// Verify X25519Sig is valid
	if !ed25519.Verify(id.Ed25519Public, id.X25519Public[:], id.X25519Sig[:]) {
		t.Error("X25519Sig is not a valid Ed25519 signature over X25519Public")
	}

	// Verify X25519 private key is not all zeros
	allZero := true
	for _, b := range id.X25519Private {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("X25519 private key is all zeros")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || contains(s[1:], substr)))
}