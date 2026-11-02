// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package acl

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLocalPolicyLoader_Load_BrokenFile(t *testing.T) {
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "policy.toml")

	invalidPolicy := `
version = 1
# missing default
[peers]
alice = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
`
	if err := os.WriteFile(policyPath, []byte(invalidPolicy), 0o600); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	swap := &PolicySwap{}
	loader := NewLocalPolicyLoader(policyPath, [32]byte{}, func(name string) ([32]byte, bool) {
		return [32]byte{}, false
	}, swap, nil)

	err := loader.Load()
	if err == nil {
		t.Fatal("expected error for invalid policy file")
	}
	if err.Error() != "parse policy: policy: default is required (allow or deny)" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLocalPolicyLoader_Load_WorldWritableFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permission checks skipped on Windows")
	}
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "policy.toml")

	validPolicy := `
version = 1
default = "deny"
[peers]
alice = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
bob   = "ed25519:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
[[rule]]
from = "alice"
to   = "bob"
ports = ["*"]
`
	if err := os.WriteFile(policyPath, []byte(validPolicy), 0o666); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	// Manually chmod to ensure world-writable (bypass umask)
	if err := os.Chmod(policyPath, 0o666); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	info, err := os.Stat(policyPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	t.Logf("file mode: %o, full mode: %o", info.Mode().Perm(), info.Mode())

	swap := &PolicySwap{}
	loader := NewLocalPolicyLoader(policyPath, [32]byte{}, func(name string) ([32]byte, bool) {
		return [32]byte{}, false
	}, swap, nil)

	err = loader.Load()
	if err == nil {
		t.Fatal("expected error for world-writable policy file")
	}
}

func TestLocalPolicyLoader_Load_GroupWritableFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permission checks skipped on Windows")
	}
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "policy.toml")

	validPolicy := `
version = 1
default = "deny"
[peers]
alice = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
bob   = "ed25519:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
[[rule]]
from = "alice"
to   = "bob"
ports = ["*"]
`
	if err := os.WriteFile(policyPath, []byte(validPolicy), 0o660); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	// Manually chmod to ensure group-writable
	if err := os.Chmod(policyPath, 0o660); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	info, err := os.Stat(policyPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	t.Logf("file mode: %o, full mode: %o", info.Mode().Perm(), info.Mode())

	swap := &PolicySwap{}
	loader := NewLocalPolicyLoader(policyPath, [32]byte{}, func(name string) ([32]byte, bool) {
		return [32]byte{}, false
	}, swap, nil)

	err = loader.Load()
	if err == nil {
		t.Fatal("expected error for group-writable policy file")
	}
}

func TestLocalPolicyLoader_Load_ValidFile(t *testing.T) {
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "policy.toml")

	validPolicy := `
version = 1
default = "deny"
[peers]
alice = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
bob   = "ed25519:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
[[rule]]
from = "alice"
to   = "bob"
ports = ["*"]
`
	if err := os.WriteFile(policyPath, []byte(validPolicy), 0o600); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	swap := &PolicySwap{}
	loader := NewLocalPolicyLoader(policyPath, [32]byte{}, func(name string) ([32]byte, bool) {
		return [32]byte{}, false
	}, swap, nil)

	err := loader.Load()
	if err != nil {
		t.Fatalf("unexpected error for valid policy file: %v", err)
	}
}

func TestLocalPolicyLoader_Load_MissingFile(t *testing.T) {
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "nonexistent.toml")

	swap := &PolicySwap{}
	loader := NewLocalPolicyLoader(policyPath, [32]byte{}, func(name string) ([32]byte, bool) {
		return [32]byte{}, false
	}, swap, nil)

	err := loader.Load()
	if err != nil {
		t.Fatalf("expected no error for missing policy file: %v", err)
	}
	if swap.Load() != nil {
		t.Error("expected nil policy for missing file")
	}
}

func TestLocalPolicyLoader_Load_FileRemovedAfterLoad(t *testing.T) {
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "policy.toml")

	validPolicy := `
version = 1
default = "deny"
[peers]
alice = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
bob   = "ed25519:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
[[rule]]
from = "alice"
to   = "bob"
ports = ["*"]
`
	if err := os.WriteFile(policyPath, []byte(validPolicy), 0o600); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	swap := &PolicySwap{}
	loader := NewLocalPolicyLoader(policyPath, [32]byte{}, func(name string) ([32]byte, bool) {
		return [32]byte{}, false
	}, swap, nil)

	if err := loader.Load(); err != nil {
		t.Fatalf("first load failed: %v", err)
	}
	if swap.Load() == nil {
		t.Error("expected policy to be loaded")
	}

	if err := os.Remove(policyPath); err != nil {
		t.Fatalf("remove policy file: %v", err)
	}

	if err := loader.Load(); err != nil {
		t.Fatalf("second load failed: %v", err)
	}
	if swap.Load() != nil {
		t.Error("expected nil policy after file removal")
	}
}

func TestLocalPolicyLoader_ValidatePermissions_Valid(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permission checks skipped on Windows")
	}
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "policy.toml")

	validPolicy := `
version = 1
default = "deny"
[peers]
alice = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
bob   = "ed25519:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
`
	if err := os.WriteFile(policyPath, []byte(validPolicy), 0o600); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	info, err := os.Stat(policyPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	err = validatePolicyFilePermissions(policyPath, info)
	if err != nil {
		t.Fatalf("unexpected error for 0600 file: %v", err)
	}
}

func TestLocalPolicyLoader_ValidatePermissions_WorldReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permission checks skipped on Windows")
	}
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "policy.toml")

	validPolicy := `
version = 1
default = "deny"
[peers]
alice = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
bob   = "ed25519:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
`
	if err := os.WriteFile(policyPath, []byte(validPolicy), 0o644); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	info, err := os.Stat(policyPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	err = validatePolicyFilePermissions(policyPath, info)
	if err != nil {
		t.Fatalf("unexpected error for 0644 file: %v", err)
	}
}

func TestValidatePolicyFilePermissions_Debug(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permission checks skipped on Windows")
	}
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "policy.toml")

	testCases := []struct {
		name     string
		mode     os.FileMode
		expected bool // true = should pass, false = should fail
	}{
		{"0600", 0o600, true},
		{"0640", 0o640, true},
		{"0644", 0o644, true},  // world-readable is fine, not writable
		{"0660", 0o660, false}, // group-writable
		{"0666", 0o666, false}, // world-writable
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(policyPath, []byte("test"), tc.mode); err != nil {
				t.Fatalf("write: %v", err)
			}
			// Force the mode to stick by chmod after write
			if err := os.Chmod(policyPath, tc.mode); err != nil {
				t.Fatalf("chmod: %v", err)
			}
			info, err := os.Stat(policyPath)
			if err != nil {
				t.Fatalf("stat: %v", err)
			}
			t.Logf("requested mode: %o, actual perm: %o, full mode: %o", tc.mode, info.Mode().Perm(), info.Mode())

			err = validatePolicyFilePermissions(policyPath, info)
			if tc.expected && err != nil {
				t.Errorf("expected pass but got error: %v", err)
			}
			if !tc.expected && err == nil {
				t.Errorf("expected fail but got pass")
			}
		})
	}
}
