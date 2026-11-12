// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package acl

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestGenerateAdminKey(t *testing.T) {
	privKey, pubKey, err := GenerateAdminKey()
	if err != nil {
		t.Fatalf("GenerateAdminKey: %v", err)
	}
	if len(privKey) != ed25519.PrivateKeySize {
		t.Errorf("private key size: got %d, want %d", len(privKey), ed25519.PrivateKeySize)
	}
	if len(pubKey) != ed25519.PublicKeySize {
		t.Errorf("public key size: got %d, want %d", len(pubKey), ed25519.PublicKeySize)
	}
	// Verify the public key matches the private key
	if !pubKey.Equal(privKey.Public().(ed25519.PublicKey)) {
		t.Error("public key does not match private key")
	}
}

func TestWriteReadAdminKeyFile(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "admin.key")

	privKey, _, err := GenerateAdminKey()
	if err != nil {
		t.Fatalf("GenerateAdminKey: %v", err)
	}

	if err := WriteAdminKeyFile(keyPath, privKey); err != nil {
		t.Fatalf("WriteAdminKeyFile: %v", err)
	}

	// Check file permissions (0600) - skip on Windows
	if runtime.GOOS != "windows" {
		info, err := os.Stat(keyPath)
		if err != nil {
			t.Fatalf("stat key file: %v", err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("key file mode: got %o, want 0600", info.Mode().Perm())
		}
	}

	// Read back
	readKey, err := ReadAdminKeyFile(keyPath)
	if err != nil {
		t.Fatalf("ReadAdminKeyFile: %v", err)
	}

	if !readKey.Equal(privKey) {
		t.Error("read key does not match written key")
	}
}

func TestWriteAdminKeyFile_RefusesOverwrite(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "admin.key")

	privKey1, _, err := GenerateAdminKey()
	if err != nil {
		t.Fatalf("GenerateAdminKey: %v", err)
	}

	// Write first key
	if err := WriteAdminKeyFile(keyPath, privKey1); err != nil {
		t.Fatalf("WriteAdminKeyFile first: %v", err)
	}

	// Try to write a different key to the same path - should fail
	privKey2, _, err := GenerateAdminKey()
	if err != nil {
		t.Fatalf("GenerateAdminKey: %v", err)
	}
	err = WriteAdminKeyFile(keyPath, privKey2)
	if err == nil {
		t.Fatal("expected error for overwrite")
	}

	// Verify the original key is still there
	readKey, err := ReadAdminKeyFile(keyPath)
	if err != nil {
		t.Fatalf("ReadAdminKeyFile: %v", err)
	}
	if !readKey.Equal(privKey1) {
		t.Error("original key was overwritten")
	}
}

func TestParseAdminKeys(t *testing.T) {
	// Generate a test key pair
	_, pubKey, err := GenerateAdminKey()
	if err != nil {
		t.Fatalf("GenerateAdminKey: %v", err)
	}

	base64Key := "ed25519:" + base64.StdEncoding.EncodeToString(pubKey)
	hexKey := "ed25519:" + hex.EncodeToString(pubKey[:])

	keys := []string{base64Key, hexKey}
	parsed, err := ParseAdminKeys(keys)
	if err != nil {
		t.Fatalf("ParseAdminKeys: %v", err)
	}

	// Both encodings produce the same key bytes, so we get 1 unique key
	if len(parsed) != 1 {
		t.Fatalf("expected 1 parsed key (deduplicated), got %d", len(parsed))
	}

	var expectedKey [32]byte
	copy(expectedKey[:], pubKey)
	if _, ok := parsed[expectedKey]; !ok {
		t.Error("parsed key not found in result")
	}
}

func TestParseAdminKeys_InvalidFormat(t *testing.T) {
	_, err := ParseAdminKeys([]string{"invalid"})
	if err == nil {
		t.Fatal("expected error for invalid key format")
	}
	if err.Error() != `admin key must start with "ed25519:": "invalid"` {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestParseAdminKeys_InvalidEncoding(t *testing.T) {
	_, err := ParseAdminKeys([]string{"ed25519:not-base64-or-hex"})
	if err == nil {
		t.Fatal("expected error for invalid encoding")
	}
}

func TestParseAdminKeys_WrongLength(t *testing.T) {
	// 31 bytes when decoded (missing one byte)
	_, err := ParseAdminKeys([]string{"ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"})
	if err == nil {
		t.Fatal("expected error for wrong key length")
	}
}

func TestSignPolicy(t *testing.T) {
	policyTOML := `
version = 1
default = "deny"
[peers]
alice = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
bob   = "ed25519:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
[[rule]]
from = "alice"
to   = "bob"
ports = ["tcp/22"]
`

	privKey, _, err := GenerateAdminKey()
	if err != nil {
		t.Fatalf("GenerateAdminKey: %v", err)
	}

	envelope, err := SignPolicy(policyTOML, privKey)
	if err != nil {
		t.Fatalf("SignPolicy: %v", err)
	}

	if len(envelope) < networkPolicyHeaderSize {
		t.Errorf("envelope too small: %d bytes", len(envelope))
	}

	// Verify magic
	magic := binary.BigEndian.Uint32(envelope[0:4])
	if magic != networkPolicyMagic {
		t.Errorf("magic: got 0x%x, want 0x%x", magic, networkPolicyMagic)
	}

	// Verify format version
	formatVer := envelope[4]
	if formatVer != networkPolicyFormatVer {
		t.Errorf("format version: got %d, want %d", formatVer, networkPolicyFormatVer)
	}
}

func TestSignPolicy_InvalidPolicy(t *testing.T) {
	policyTOML := `
version = 1
# missing default
[peers]
alice = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
`

	privKey, _, err := GenerateAdminKey()
	if err != nil {
		t.Fatalf("GenerateAdminKey: %v", err)
	}

	_, err = SignPolicy(policyTOML, privKey)
	if err == nil {
		t.Fatal("expected error for invalid policy")
	}
}

func TestParseNetworkPolicyEnvelope(t *testing.T) {
	policyTOML := `
version = 1
default = "deny"
[peers]
alice = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
bob   = "ed25519:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
[[rule]]
from = "alice"
to   = "bob"
ports = ["tcp/22"]
`

	privKey, pubKey, err := GenerateAdminKey()
	if err != nil {
		t.Fatalf("GenerateAdminKey: %v", err)
	}

	envelope, err := SignPolicy(policyTOML, privKey)
	if err != nil {
		t.Fatalf("SignPolicy: %v", err)
	}

	// Parse with the correct admin key
	adminKeys := map[[32]byte]struct{}{}
	var pubKeyArr [32]byte
	copy(pubKeyArr[:], pubKey)
	adminKeys[pubKeyArr] = struct{}{}

	env, err := ParseNetworkPolicyEnvelope(envelope, adminKeys)
	if err != nil {
		t.Fatalf("ParseNetworkPolicyEnvelope: %v", err)
	}

	if env.Version != 1 {
		t.Errorf("version: got %d, want 1", env.Version)
	}
	if env.Policy.Default != DefaultDeny {
		t.Errorf("default: got %v, want deny", env.Policy.Default)
	}
	if len(env.Policy.Peers) != 2 {
		t.Errorf("peers: got %d, want 2", len(env.Policy.Peers))
	}
	if len(env.Policy.Rules) != 1 {
		t.Errorf("rules: got %d, want 1", len(env.Policy.Rules))
	}
	if env.SignerPubKey != pubKeyArr {
		t.Error("signer pubkey mismatch")
	}
}

func TestParseNetworkPolicyEnvelope_NoAdminKeys(t *testing.T) {
	policyTOML := `
version = 1
default = "deny"
[peers]
alice = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
`

	privKey, _, err := GenerateAdminKey()
	if err != nil {
		t.Fatalf("GenerateAdminKey: %v", err)
	}

	envelope, err := SignPolicy(policyTOML, privKey)
	if err != nil {
		t.Fatalf("SignPolicy: %v", err)
	}

	// Parse with empty admin keys (should fail)
	_, err = ParseNetworkPolicyEnvelope(envelope, map[[32]byte]struct{}{})
	if err == nil {
		t.Fatal("expected error for empty admin keys")
	}
	if err.Error() != "no admin keys pinned; network policies are ignored" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestParseNetworkPolicyEnvelope_UnpinnedSigner(t *testing.T) {
	policyTOML := `
version = 1
default = "deny"
[peers]
alice = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
`

	privKey1, _, err := GenerateAdminKey()
	if err != nil {
		t.Fatalf("GenerateAdminKey: %v", err)
	}
	_, pubKey2, err := GenerateAdminKey()
	if err != nil {
		t.Fatalf("GenerateAdminKey: %v", err)
	}

	envelope, err := SignPolicy(policyTOML, privKey1)
	if err != nil {
		t.Fatalf("SignPolicy: %v", err)
	}

	// Parse with a different admin key
	adminKeys := map[[32]byte]struct{}{}
	var pubKey2Arr [32]byte
	copy(pubKey2Arr[:], pubKey2)
	adminKeys[pubKey2Arr] = struct{}{}

	_, err = ParseNetworkPolicyEnvelope(envelope, adminKeys)
	if err == nil {
		t.Fatal("expected error for unpinned signer")
	}
}

func TestParseNetworkPolicyEnvelope_InvalidSignature(t *testing.T) {
	policyTOML := `
version = 1
default = "deny"
[peers]
alice = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
`

	privKey, pubKey, err := GenerateAdminKey()
	if err != nil {
		t.Fatalf("GenerateAdminKey: %v", err)
	}

	envelope, err := SignPolicy(policyTOML, privKey)
	if err != nil {
		t.Fatalf("SignPolicy: %v", err)
	}

	// Corrupt the signature
	envelope[len(envelope)-1] ^= 0xFF

	adminKeys := map[[32]byte]struct{}{}
	var pubKeyArr [32]byte
	copy(pubKeyArr[:], pubKey)
	adminKeys[pubKeyArr] = struct{}{}

	_, err = ParseNetworkPolicyEnvelope(envelope, adminKeys)
	if err == nil {
		t.Fatal("expected error for invalid signature")
	}
}

func TestParseNetworkPolicyEnvelope_Truncated(t *testing.T) {
	policyTOML := `
version = 1
default = "deny"
[peers]
alice = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
`

	privKey, _, err := GenerateAdminKey()
	if err != nil {
		t.Fatalf("GenerateAdminKey: %v", err)
	}

	envelope, err := SignPolicy(policyTOML, privKey)
	if err != nil {
		t.Fatalf("SignPolicy: %v", err)
	}

	// Truncate the envelope
	truncated := envelope[:len(envelope)/2]

	adminKeys := map[[32]byte]struct{}{}
	var pubKeyArr [32]byte
	copy(pubKeyArr[:], []byte{1}) // dummy key
	adminKeys[pubKeyArr] = struct{}{}

	_, err = ParseNetworkPolicyEnvelope(truncated, adminKeys)
	if err == nil {
		t.Fatal("expected error for truncated envelope")
	}
}

func TestParseNetworkPolicyEnvelope_InvalidMagic(t *testing.T) {
	policyTOML := `
version = 1
default = "deny"
[peers]
alice = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
`

	privKey, pubKey, err := GenerateAdminKey()
	if err != nil {
		t.Fatalf("GenerateAdminKey: %v", err)
	}

	envelope, err := SignPolicy(policyTOML, privKey)
	if err != nil {
		t.Fatalf("SignPolicy: %v", err)
	}

	// Corrupt the magic
	binary.BigEndian.PutUint32(envelope[0:4], 0xDEADBEEF)

	adminKeys := map[[32]byte]struct{}{}
	var pubKeyArr [32]byte
	copy(pubKeyArr[:], pubKey)
	adminKeys[pubKeyArr] = struct{}{}

	_, err = ParseNetworkPolicyEnvelope(envelope, adminKeys)
	if err == nil {
		t.Fatal("expected error for invalid magic")
	}
}

func TestParseNetworkPolicyEnvelope_HugePayloadLen(t *testing.T) {
	// Create a malformed envelope with a huge payloadLen that would wrap in uint32 arithmetic
	// The envelope should be rejected by the exact length check
	data := make([]byte, 200)
	binary.BigEndian.PutUint32(data[0:4], networkPolicyMagic)
	data[4] = networkPolicyFormatVer
	// Set payloadLen to a huge value (0xFFFFFFF0) that would wrap in old uint32 check
	binary.BigEndian.PutUint32(data[5:9], 0xFFFFFFF0)

	adminKeys := map[[32]byte]struct{}{}
	var pubKeyArr [32]byte
	copy(pubKeyArr[:], []byte{1})
	adminKeys[pubKeyArr] = struct{}{}

	_, err := ParseNetworkPolicyEnvelope(data, adminKeys)
	if err == nil {
		t.Fatal("expected error for huge payloadLen")
	}
}

func TestParseNetworkPolicyEnvelope_TrailingBytes(t *testing.T) {
	// Create a valid envelope
	policyTOML := `
version = 1
default = "deny"
[peers]
alice = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
`
	privKey, pubKey, err := GenerateAdminKey()
	if err != nil {
		t.Fatalf("GenerateAdminKey: %v", err)
	}

	envelope, err := SignPolicy(policyTOML, privKey)
	if err != nil {
		t.Fatalf("SignPolicy: %v", err)
	}

	// Add trailing bytes
	envelopeWithTrailing := append(envelope, []byte("trailing")...)

	adminKeys := map[[32]byte]struct{}{}
	var pubKeyArr [32]byte
	copy(pubKeyArr[:], pubKey)
	adminKeys[pubKeyArr] = struct{}{}

	_, err = ParseNetworkPolicyEnvelope(envelopeWithTrailing, adminKeys)
	if err == nil {
		t.Fatal("expected error for trailing bytes")
	}
}

func TestWriteNetworkPolicyFile(t *testing.T) {
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "policy.signed")

	policyTOML := `
version = 1
default = "deny"
[peers]
alice = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
bob   = "ed25519:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
[[rule]]
from = "alice"
to   = "bob"
ports = ["tcp/22"]
`

	privKey, _, err := GenerateAdminKey()
	if err != nil {
		t.Fatalf("GenerateAdminKey: %v", err)
	}

	envelope, err := SignPolicy(policyTOML, privKey)
	if err != nil {
		t.Fatalf("SignPolicy: %v", err)
	}

	// Write first time
	if err := WriteNetworkPolicyFile(policyPath, envelope, 1); err != nil {
		t.Fatalf("WriteNetworkPolicyFile: %v", err)
	}

	// Check file permissions (0600) - skip on Windows
	if runtime.GOOS != "windows" {
		info, err := os.Stat(policyPath)
		if err != nil {
			t.Fatalf("stat policy file: %v", err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("policy file mode: got %o, want 0600", info.Mode().Perm())
		}
	}

	// Try to write same version (should fail)
	if err := WriteNetworkPolicyFile(policyPath, envelope, 1); err == nil {
		t.Fatal("expected error for same version overwrite")
	}

	// Write higher version (should succeed)
	policyTOMLv2 := `
version = 2
default = "deny"
[peers]
alice = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
bob   = "ed25519:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
[[rule]]
from = "alice"
to   = "bob"
ports = ["tcp/22"]
`
	envelope2, err := SignPolicy(policyTOMLv2, privKey)
	if err != nil {
		t.Fatalf("SignPolicy v2: %v", err)
	}
	if err := WriteNetworkPolicyFile(policyPath, envelope2, 2); err != nil {
		t.Fatalf("WriteNetworkPolicyFile v2: %v", err)
	}
}

func TestNetworkPolicyStore(t *testing.T) {
	tmpDir := t.TempDir()
	identityPath := filepath.Join(tmpDir, "identity.json")
	// Create empty identity file
	if err := os.WriteFile(identityPath, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write identity: %v", err)
	}

	store := NewNetworkPolicyStore(identityPath)
	storePath := store.GetPath()

	// Store should not exist yet
	if _, err := os.Stat(storePath); !os.IsNotExist(err) {
		t.Error("store file should not exist initially")
	}

	policyTOML := `
version = 1
default = "deny"
[peers]
alice = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
`

	privKey, pubKey, err := GenerateAdminKey()
	if err != nil {
		t.Fatalf("GenerateAdminKey: %v", err)
	}

	envelope, err := SignPolicy(policyTOML, privKey)
	if err != nil {
		t.Fatalf("SignPolicy: %v", err)
	}

	// Parse to get envelope
	adminKeys := map[[32]byte]struct{}{}
	var pubKeyArr [32]byte
	copy(pubKeyArr[:], pubKey)
	adminKeys[pubKeyArr] = struct{}{}

	env, err := ParseNetworkPolicyEnvelope(envelope, adminKeys)
	if err != nil {
		t.Fatalf("ParseNetworkPolicyEnvelope: %v", err)
	}

	// Store the envelope
	stored, err := store.Store(env, adminKeys)
	if err != nil {
		t.Fatalf("store.Store: %v", err)
	}
	if !stored {
		t.Error("expected stored=true for first store")
	}

	// Store same version (should fail)
	stored, err = store.Store(env, adminKeys)
	if err == nil {
		t.Fatal("expected error for same version store")
	}
	if stored {
		t.Error("expected stored=false for same version")
	}

	// Load the stored policy
	loadedEnv, err := store.Load(adminKeys)
	if err != nil {
		t.Fatalf("store.Load: %v", err)
	}
	if loadedEnv == nil {
		t.Fatal("expected loaded envelope")
	}
	if loadedEnv.Version != 1 {
		t.Errorf("loaded version: got %d, want 1", loadedEnv.Version)
	}
}

func TestNetworkPolicyStore_RollbackProtection(t *testing.T) {
	tmpDir := t.TempDir()
	identityPath := filepath.Join(tmpDir, "identity.json")
	if err := os.WriteFile(identityPath, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write identity: %v", err)
	}

	store := NewNetworkPolicyStore(identityPath)

	privKey, pubKey, err := GenerateAdminKey()
	if err != nil {
		t.Fatalf("GenerateAdminKey: %v", err)
	}

	adminKeys := map[[32]byte]struct{}{}
	var pubKeyArr [32]byte
	copy(pubKeyArr[:], pubKey)
	adminKeys[pubKeyArr] = struct{}{}

	// Store version 2 first
	policyTOMLv2 := `
version = 2
default = "deny"
[peers]
alice = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
`
	envelope2, err := SignPolicy(policyTOMLv2, privKey)
	if err != nil {
		t.Fatalf("SignPolicy v2: %v", err)
	}
	env2, err := ParseNetworkPolicyEnvelope(envelope2, adminKeys)
	if err != nil {
		t.Fatalf("Parse v2: %v", err)
	}
	if _, err := store.Store(env2, adminKeys); err != nil {
		t.Fatalf("store v2: %v", err)
	}

	// Try to store version 1 (rollback) - should fail
	policyTOMLv1 := `
version = 1
default = "deny"
[peers]
alice = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
`
	envelope1, err := SignPolicy(policyTOMLv1, privKey)
	if err != nil {
		t.Fatalf("SignPolicy v1: %v", err)
	}
	env1, err := ParseNetworkPolicyEnvelope(envelope1, adminKeys)
	if err != nil {
		t.Fatalf("Parse v1: %v", err)
	}
	if _, err := store.Store(env1, adminKeys); err == nil {
		t.Fatal("expected error for rollback")
	}
}

func TestLoadNetworkPolicy(t *testing.T) {
	tmpDir := t.TempDir()
	identityPath := filepath.Join(tmpDir, "identity.json")
	if err := os.WriteFile(identityPath, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write identity: %v", err)
	}
	policyPath := filepath.Join(tmpDir, "policy.signed")

	privKey, pubKey, err := GenerateAdminKey()
	if err != nil {
		t.Fatalf("GenerateAdminKey: %v", err)
	}

	adminKeys := map[[32]byte]struct{}{}
	var pubKeyArr [32]byte
	copy(pubKeyArr[:], pubKey)
	adminKeys[pubKeyArr] = struct{}{}

	policyTOML := `
version = 1
default = "deny"
[peers]
alice = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
bob   = "ed25519:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
[[rule]]
from = "alice"
to   = "bob"
ports = ["tcp/22"]
`

	envelope, err := SignPolicy(policyTOML, privKey)
	if err != nil {
		t.Fatalf("SignPolicy: %v", err)
	}

	if err := WriteNetworkPolicyFile(policyPath, envelope, 1); err != nil {
		t.Fatalf("WriteNetworkPolicyFile: %v", err)
	}

	// Load the network policy
	loaded, stored, err := LoadNetworkPolicy(policyPath, identityPath, adminKeys)
	if err != nil {
		t.Fatalf("LoadNetworkPolicy: %v", err)
	}
	if !stored {
		t.Error("expected stored=true for first load")
	}
	if loaded == nil {
		t.Fatal("expected loaded policy")
	}
	if loaded.Envelope.Version != 1 {
		t.Errorf("version: got %d, want 1", loaded.Envelope.Version)
	}
	if loaded.Compiled == nil {
		t.Error("expected compiled policy")
	}
	if loaded.SignerStr != formatPeerKey(pubKeyArr) {
		t.Errorf("signer: got %q, want %q", loaded.SignerStr, formatPeerKey(pubKeyArr))
	}

	// Load again - should use stored version
	loaded2, stored2, err := LoadNetworkPolicy(policyPath, identityPath, adminKeys)
	if err != nil {
		t.Fatalf("LoadNetworkPolicy second: %v", err)
	}
	if stored2 {
		t.Error("expected stored=false for second load")
	}
	if loaded2.Envelope.Version != 1 {
		t.Errorf("second load version: got %d, want 1", loaded2.Envelope.Version)
	}
}

func TestLoadNetworkPolicy_RollbackRejected(t *testing.T) {
	tmpDir := t.TempDir()
	identityPath := filepath.Join(tmpDir, "identity.json")
	if err := os.WriteFile(identityPath, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write identity: %v", err)
	}
	policyPath := filepath.Join(tmpDir, "policy.signed")

	privKey, pubKey, err := GenerateAdminKey()
	if err != nil {
		t.Fatalf("GenerateAdminKey: %v", err)
	}

	adminKeys := map[[32]byte]struct{}{}
	var pubKeyArr [32]byte
	copy(pubKeyArr[:], pubKey)
	adminKeys[pubKeyArr] = struct{}{}

	// Write and load version 2
	policyTOMLv2 := `
version = 2
default = "deny"
[peers]
alice = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
`
	envelope2, err := SignPolicy(policyTOMLv2, privKey)
	if err != nil {
		t.Fatalf("SignPolicy v2: %v", err)
	}
	if err := WriteNetworkPolicyFile(policyPath, envelope2, 2); err != nil {
		t.Fatalf("Write v2: %v", err)
	}
	if _, _, err := LoadNetworkPolicy(policyPath, identityPath, adminKeys); err != nil {
		t.Fatalf("Load v2: %v", err)
	}

	// Write version 1 directly to the file (simulating an attacker replacing the file)
	// Bypass WriteNetworkPolicyFile which would refuse the overwrite
	policyTOMLv1 := `
version = 1
default = "deny"
[peers]
alice = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
`
	envelope1, err := SignPolicy(policyTOMLv1, privKey)
	if err != nil {
		t.Fatalf("SignPolicy v1: %v", err)
	}
	if err := os.WriteFile(policyPath, envelope1, 0o600); err != nil {
		t.Fatalf("Write v1: %v", err)
	}
	_, _, err = LoadNetworkPolicy(policyPath, identityPath, adminKeys)
	if err == nil {
		t.Fatal("expected error for rollback")
	}
	if err.Error() != "policy version 1 not higher than stored version 2 (possible rollback)" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNetworkPolicyLoader(t *testing.T) {
	tmpDir := t.TempDir()
	identityPath := filepath.Join(tmpDir, "identity.json")
	if err := os.WriteFile(identityPath, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write identity: %v", err)
	}
	policyPath := filepath.Join(tmpDir, "policy.signed")

	privKey, pubKey, err := GenerateAdminKey()
	if err != nil {
		t.Fatalf("GenerateAdminKey: %v", err)
	}

	adminKeys := map[[32]byte]struct{}{}
	var pubKeyArr [32]byte
	copy(pubKeyArr[:], pubKey)
	adminKeys[pubKeyArr] = struct{}{}

	policyTOML := `
version = 1
default = "deny"
[peers]
alice = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
bob   = "ed25519:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
[[rule]]
from = "alice"
to   = "bob"
ports = ["tcp/22"]
`

	envelope, err := SignPolicy(policyTOML, privKey)
	if err != nil {
		t.Fatalf("SignPolicy: %v", err)
	}

	if err := WriteNetworkPolicyFile(policyPath, envelope, 1); err != nil {
		t.Fatalf("WriteNetworkPolicyFile: %v", err)
	}

	swap := &PolicySwap{}
	loader := NewNetworkPolicyLoader(policyPath, identityPath, adminKeys, swap)

	if err := loader.Load(); err != nil {
		t.Fatalf("loader.Load: %v", err)
	}

	// Check that the compiled policy is in the swap
	cp := swap.Load()
	if cp == nil {
		t.Fatal("expected compiled policy in swap")
	}
	if cp.Version() != 1 {
		t.Errorf("swap version: got %d, want 1", cp.Version())
	}

	// Check status
	status := loader.NetworkPolicyStatus()
	if status.Version != 1 {
		t.Errorf("status version: got %d, want 1", status.Version)
	}
	if status.Signer != formatPeerKey(pubKeyArr) {
		t.Errorf("status signer: got %q, want %q", status.Signer, formatPeerKey(pubKeyArr))
	}
}

func TestNetworkPolicyLoader_NoAdminKeys(t *testing.T) {
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "policy.signed")

	swap := &PolicySwap{}
	loader := NewNetworkPolicyLoader(policyPath, "/tmp/identity.json", map[[32]byte]struct{}{}, swap)

	if err := loader.Load(); err != nil {
		t.Fatalf("loader.Load: %v", err)
	}

	// Should store nil policy (network policies ignored)
	if swap.Load() != nil {
		t.Error("expected nil policy when no admin keys")
	}
}

func TestNetworkPolicyLoader_NoFile(t *testing.T) {
	tmpDir := t.TempDir()
	identityPath := filepath.Join(tmpDir, "identity.json")
	if err := os.WriteFile(identityPath, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write identity: %v", err)
	}
	policyPath := filepath.Join(tmpDir, "nonexistent.signed")

	_, pubKey, err := GenerateAdminKey()
	if err != nil {
		t.Fatalf("GenerateAdminKey: %v", err)
	}

	adminKeys := map[[32]byte]struct{}{}
	var pubKeyArr [32]byte
	copy(pubKeyArr[:], pubKey)
	adminKeys[pubKeyArr] = struct{}{}

	swap := &PolicySwap{}
	loader := NewNetworkPolicyLoader(policyPath, identityPath, adminKeys, swap)

	if err := loader.Load(); err != nil {
		t.Fatalf("loader.Load: %v", err)
	}

	// Should store nil policy (no file)
	if swap.Load() != nil {
		t.Error("expected nil policy when no file")
	}
}

func TestNetworkPolicyLoader_InvalidFile(t *testing.T) {
	tmpDir := t.TempDir()
	identityPath := filepath.Join(tmpDir, "identity.json")
	if err := os.WriteFile(identityPath, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write identity: %v", err)
	}
	policyPath := filepath.Join(tmpDir, "policy.signed")

	_, pubKey, err := GenerateAdminKey()
	if err != nil {
		t.Fatalf("GenerateAdminKey: %v", err)
	}

	adminKeys := map[[32]byte]struct{}{}
	var pubKeyArr [32]byte
	copy(pubKeyArr[:], pubKey)
	adminKeys[pubKeyArr] = struct{}{}

	// Write invalid policy file
	if err := os.WriteFile(policyPath, []byte("not a valid envelope"), 0o600); err != nil {
		t.Fatalf("write invalid policy: %v", err)
	}

	swap := &PolicySwap{}
	loader := NewNetworkPolicyLoader(policyPath, identityPath, adminKeys, swap)

	// Load should not return error (logs and keeps current policy, which is nil initially)
	if err := loader.Load(); err != nil {
		t.Fatalf("loader.Load should not return error: %v", err)
	}

	// Swap should remain nil (no stored policy yet)
	if swap.Load() != nil {
		t.Error("expected nil policy for invalid file with no stored policy")
	}
}

func TestNetworkPolicyLoader_StoredPolicyPersists(t *testing.T) {
	tmpDir := t.TempDir()
	identityPath := filepath.Join(tmpDir, "identity.json")
	if err := os.WriteFile(identityPath, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write identity: %v", err)
	}
	policyPath := filepath.Join(tmpDir, "policy.signed")

	privKey, pubKey, err := GenerateAdminKey()
	if err != nil {
		t.Fatalf("GenerateAdminKey: %v", err)
	}

	adminKeys := map[[32]byte]struct{}{}
	var pubKeyArr [32]byte
	copy(pubKeyArr[:], pubKey)
	adminKeys[pubKeyArr] = struct{}{}

	// First, write and load a valid policy to populate the store
	policyTOML := `
version = 1
default = "deny"
[peers]
alice = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
bob   = "ed25519:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
[[rule]]
from = "alice"
to   = "bob"
ports = ["tcp/22"]
`

	envelope, err := SignPolicy(policyTOML, privKey)
	if err != nil {
		t.Fatalf("SignPolicy: %v", err)
	}

	if err := WriteNetworkPolicyFile(policyPath, envelope, 1); err != nil {
		t.Fatalf("WriteNetworkPolicyFile: %v", err)
	}

	swap := &PolicySwap{}
	loader := NewNetworkPolicyLoader(policyPath, identityPath, adminKeys, swap)

	if err := loader.Load(); err != nil {
		t.Fatalf("loader.Load: %v", err)
	}

	cp := swap.Load()
	if cp == nil {
		t.Fatal("expected compiled policy in swap after first load")
	}

	// Now overwrite the file with an invalid one
	if err := os.WriteFile(policyPath, []byte("not a valid envelope"), 0o600); err != nil {
		t.Fatalf("write invalid policy: %v", err)
	}

	// Load again - should keep the stored policy
	if err := loader.Load(); err != nil {
		t.Fatalf("loader.Load should not return error: %v", err)
	}

	// Swap should still have the valid policy
	cp = swap.Load()
	if cp == nil {
		t.Fatal("expected compiled policy to persist after invalid file load")
	}
	if cp.Version() != 1 {
		t.Errorf("swap version: got %d, want 1", cp.Version())
	}
}

func TestNetworkPolicyLoader_LoadStoredPolicy(t *testing.T) {
	tmpDir := t.TempDir()
	identityPath := filepath.Join(tmpDir, "identity.json")
	if err := os.WriteFile(identityPath, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write identity: %v", err)
	}
	policyPath := filepath.Join(tmpDir, "policy.signed")

	privKey, pubKey, err := GenerateAdminKey()
	if err != nil {
		t.Fatalf("GenerateAdminKey: %v", err)
	}

	adminKeys := map[[32]byte]struct{}{}
	var pubKeyArr [32]byte
	copy(pubKeyArr[:], pubKey)
	adminKeys[pubKeyArr] = struct{}{}

	policyTOML := `
version = 1
default = "deny"
[peers]
alice = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
bob   = "ed25519:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
[[rule]]
from = "alice"
to   = "bob"
ports = ["tcp/22"]
`

	envelope, err := SignPolicy(policyTOML, privKey)
	if err != nil {
		t.Fatalf("SignPolicy: %v", err)
	}

	if err := WriteNetworkPolicyFile(policyPath, envelope, 1); err != nil {
		t.Fatalf("WriteNetworkPolicyFile: %v", err)
	}

	// Load once to populate the store
	swap := &PolicySwap{}
	loader := NewNetworkPolicyLoader(policyPath, identityPath, adminKeys, swap)
	if err := loader.Load(); err != nil {
		t.Fatalf("loader.Load: %v", err)
	}

	// Now create a new loader with no policy file but same identity path
	// It should load the stored policy
	swap2 := &PolicySwap{}
	loader2 := NewNetworkPolicyLoader("", identityPath, adminKeys, swap2)
	if err := loader2.LoadStoredPolicy(); err != nil {
		t.Fatalf("loader.LoadStoredPolicy: %v", err)
	}

	cp := swap2.Load()
	if cp == nil {
		t.Fatal("expected compiled policy from store")
	}
	if cp.Version() != 1 {
		t.Errorf("swap version: got %d, want 1", cp.Version())
	}
}

func TestNetworkPolicyLoader_WaitIdempotent(t *testing.T) {
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "policy.signed")

	_, pubKey, err := GenerateAdminKey()
	if err != nil {
		t.Fatalf("GenerateAdminKey: %v", err)
	}

	adminKeys := map[[32]byte]struct{}{}
	var pubKeyArr [32]byte
	copy(pubKeyArr[:], pubKey)
	adminKeys[pubKeyArr] = struct{}{}

	swap := &PolicySwap{}
	loader := NewNetworkPolicyLoader(policyPath, "/tmp/identity.json", adminKeys, swap)

	// First Wait should succeed
	loader.Wait()

	// Second Wait should not panic
	loader.Wait()
}

func TestCombinedPolicy_LocalAndNetwork(t *testing.T) {
	peers := map[string]PeerKey{
		"a": {1},
		"b": {2},
	}
	rules := []Rule{
		{From: "a", To: "b", Ports: []PortRange{{Proto: ProtoTCP, Start: 22, End: 22}}},
	}

	// Local policy allows a->b
	local := makeTestPolicy(DefaultAllow, rules, peers, nil, nil)

	// Network policy denies a->b
	network := makeTestPolicy(DefaultDeny, nil, peers, nil, nil)

	// Combined: both must allow -> deny
	dec := Combine(local, network).Decide(peers["a"], peers["b"], ProtoTCP, 22)
	if dec.Action != ActionDeny {
		t.Errorf("combined: got %v, want deny", dec.Action)
	}

	// Local policy denies a->b, network allows
	localDeny := makeTestPolicy(DefaultDeny, nil, peers, nil, nil)
	networkAllow := makeTestPolicy(DefaultAllow, rules, peers, nil, nil)

	dec = Combine(localDeny, networkAllow).Decide(peers["a"], peers["b"], ProtoTCP, 22)
	if dec.Action != ActionDeny {
		t.Errorf("combined (local deny): got %v, want deny", dec.Action)
	}

	// Both allow -> allow
	dec = Combine(local, networkAllow).Decide(peers["a"], peers["b"], ProtoTCP, 22)
	if dec.Action != ActionAllow {
		t.Errorf("combined (both allow): got %v, want allow", dec.Action)
	}
}

func TestDateDiff(t *testing.T) {
	tests := []struct {
		name  string
		start time.Time
		end   time.Time
		wantY int
		wantM int
		wantD int
	}{
		{
			name:  "Feb 28 -> Mar 1 2023 (non-leap year)",
			start: time.Date(2023, 2, 28, 0, 0, 0, 0, time.UTC),
			end:   time.Date(2023, 3, 1, 0, 0, 0, 0, time.UTC),
			wantY: 0,
			wantM: 0,
			wantD: 1,
		},
		{
			name:  "Feb 28 -> Mar 1 2024 (leap year)",
			start: time.Date(2024, 2, 28, 0, 0, 0, 0, time.UTC),
			end:   time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC),
			wantY: 0,
			wantM: 0,
			wantD: 2, // Feb 28 -> Feb 29 -> Mar 1 = 2 days in leap year
		},
		{
			name:  "Jan 31 -> Mar 1 2024 (leap year, month borrow)",
			start: time.Date(2024, 1, 31, 0, 0, 0, 0, time.UTC),
			end:   time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC),
			wantY: 0,
			wantM: 1,
			wantD: 1, // Jan 31 -> Feb 29 -> Mar 1 = 1 month 1 day
		},
		{
			name:  "Jan 31 -> Mar 1 2023 (non-leap year, month borrow)",
			start: time.Date(2023, 1, 31, 0, 0, 0, 0, time.UTC),
			end:   time.Date(2023, 3, 1, 0, 0, 0, 0, time.UTC),
			wantY: 0,
			wantM: 1,
			wantD: 1, // Jan 31 -> Feb 28 -> Mar 1 = 1 month 1 day
		},
		{
			name:  "Exact year",
			start: time.Date(2023, 6, 15, 0, 0, 0, 0, time.UTC),
			end:   time.Date(2024, 6, 15, 0, 0, 0, 0, time.UTC),
			wantY: 1,
			wantM: 0,
			wantD: 0,
		},
		{
			name:  "Exact month",
			start: time.Date(2023, 1, 15, 0, 0, 0, 0, time.UTC),
			end:   time.Date(2023, 2, 15, 0, 0, 0, 0, time.UTC),
			wantY: 0,
			wantM: 1,
			wantD: 0,
		},
		{
			name:  "Cross year boundary",
			start: time.Date(2023, 12, 15, 0, 0, 0, 0, time.UTC),
			end:   time.Date(2024, 1, 15, 0, 0, 0, 0, time.UTC),
			wantY: 0,
			wantM: 1,
			wantD: 0,
		},
		{
			name:  "Same day",
			start: time.Date(2023, 5, 10, 0, 0, 0, 0, time.UTC),
			end:   time.Date(2023, 5, 10, 0, 0, 0, 0, time.UTC),
			wantY: 0,
			wantM: 0,
			wantD: 0,
		},
		{
			name:  "Feb 29 -> Mar 1 2024 (leap day)",
			start: time.Date(2024, 2, 29, 0, 0, 0, 0, time.UTC),
			end:   time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC),
			wantY: 0,
			wantM: 0,
			wantD: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			y, m, d := dateDiff(tc.start, tc.end)
			if y != tc.wantY || m != tc.wantM || d != tc.wantD {
				t.Errorf("dateDiff(%v, %v) = (%d, %d, %d), want (%d, %d, %d)",
					tc.start, tc.end, y, m, d, tc.wantY, tc.wantM, tc.wantD)
			}
		})
	}
}
