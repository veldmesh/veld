// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package tofu

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

func genKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub
}

func tempStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tofu.json")
	s, err := New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func TestStore_FirstConnect_Pins(t *testing.T) {
	s := tempStore(t)
	pub := genKey(t)

	if err := s.Check("10.0.0.2", pub); err != nil {
		t.Fatalf("first Check: %v", err)
	}

	pins := s.List()
	if _, ok := pins["10.0.0.2"]; !ok {
		t.Error("fingerprint not saved after first Check")
	}
}

func TestStore_SameKey_Accepted(t *testing.T) {
	s := tempStore(t)
	pub := genKey(t)

	s.Check("10.0.0.2", pub) //nolint:errcheck — first pin

	if err := s.Check("10.0.0.2", pub); err != nil {
		t.Errorf("same key should be accepted: %v", err)
	}
}

func TestStore_DifferentKey_Rejected(t *testing.T) {
	s := tempStore(t)
	pub1 := genKey(t)
	pub2 := genKey(t)

	s.Check("10.0.0.2", pub1) //nolint:errcheck — first pin

	// Different Ed25519 key at SAME VPN address should be rejected.
	err := s.Check("10.0.0.2", pub2)
	if !errors.Is(err, ErrFingerprintMismatch) {
		t.Errorf("different key at same VPN should be rejected: got %v, want ErrFingerprintMismatch", err)
	}
}

func TestStore_Persist_AcrossLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tofu.json")

	pub := genKey(t)

	// First store: pin.
	s1, _ := New(path)
	s1.Check("10.0.0.2", pub) //nolint:errcheck

	// Second store (same path): should accept same key, reject different one.
	s2, err := New(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if err := s2.Check("10.0.0.2", pub); err != nil {
		t.Errorf("reloaded store rejected same key: %v", err)
	}

	pub2 := genKey(t)
	if err := s2.Check("10.0.0.2", pub2); !errors.Is(err, ErrFingerprintMismatch) {
		t.Errorf("reloaded store accepted different key: %v", err)
	}
}

func TestStore_Forget_ReallowsRepin(t *testing.T) {
	s := tempStore(t)
	pub1 := genKey(t)
	pub2 := genKey(t)

	s.Check("10.0.0.2", pub1) //nolint:errcheck

	if err := s.Forget("10.0.0.2"); err != nil {
		t.Fatalf("Forget: %v", err)
	}

	// After forget, a different key can be pinned at the same VPN.
	if err := s.Check("10.0.0.2", pub2); err != nil {
		t.Errorf("after Forget, new key should be accepted: %v", err)
	}
}

func TestStore_MultipleVPNs_Independent(t *testing.T) {
	s := tempStore(t)
	pubA := genKey(t)
	pubB := genKey(t)

	s.Check("10.0.0.1", pubA) //nolint:errcheck
	s.Check("10.0.0.2", pubB) //nolint:errcheck

	// Different VPNs with same pubkey are independent.
	if err := s.Check("10.0.0.1", pubA); err != nil {
		t.Errorf("VPN A with key A rejected: %v", err)
	}
	if err := s.Check("10.0.0.2", pubB); err != nil {
		t.Errorf("VPN B with key B rejected: %v", err)
	}
	// Same key at different VPNs is allowed.
	if err := s.Check("10.0.0.3", pubA); err != nil {
		t.Errorf("VPN C with key A rejected: %v", err)
	}
}

func TestStore_NewFile_NonExistent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "subdir", "tofu.json")
	_, err := New(path)
	if err != nil {
		t.Fatalf("New with non-existent path: %v", err)
	}
}

func TestStore_FilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file permission bits not enforced on Windows")
	}
	s := tempStore(t)
	pub := genKey(t)
	s.Check("10.0.0.1", pub) //nolint:errcheck

	info, err := os.Stat(s.path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode()&0077 != 0 {
		t.Errorf("TOFU file permissions too permissive: %v", info.Mode())
	}
}

func TestFingerprint_Deterministic(t *testing.T) {
	pub := genKey(t)
	fp1 := Fingerprint(pub)
	fp2 := Fingerprint(pub)
	if fp1 != fp2 {
		t.Error("Fingerprint not deterministic")
	}
}

func TestFingerprint_UniquePerKey(t *testing.T) {
	pub1 := genKey(t)
	pub2 := genKey(t)
	if Fingerprint(pub1) == Fingerprint(pub2) {
		t.Error("different keys produced same fingerprint (birthday collision)")
	}
}

func TestStore_ConcurrentCheck(t *testing.T) {
	s := tempStore(t)
	pub := genKey(t)

	// Pin the key with the first call.
	if err := s.Check("10.0.0.1", pub); err != nil {
		t.Fatalf("initial Check (pin): %v", err)
	}

	const goroutines = 50
	errCh := make(chan error, goroutines)
	var wg sync.WaitGroup

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- s.Check("10.0.0.1", pub)
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			t.Errorf("concurrent Check returned unexpected error: %v", err)
		}
	}
}

// TestStore_Migration_OldFormat verifies that old VPN-address-keyed entries
// (version 1) are migrated to version 2 on load.
func TestStore_Migration_OldFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tofu.json")

	// Write an old-format file with VPN address keys (version 1).
	oldData := `{
  "version": 1,
  "pins": [
    {"peer_key": "10.0.0.1", "fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
    {"peer_key": "10.0.0.2", "fingerprint": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
  ]
}`
	if err := os.WriteFile(path, []byte(oldData), 0600); err != nil {
		t.Fatalf("write old file: %v", err)
	}

	// Load with new code — should migrate (drop old entries).
	s, err := New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Old entries should be gone (List returns empty).
	pins := s.List()
	if len(pins) != 0 {
		t.Errorf("old entries should be migrated away, got %d", len(pins))
	}

	// New pins should work.
	pub := genKey(t)
	if err := s.Check("10.0.0.1", pub); err != nil {
		t.Errorf("new Check after migration: %v", err)
	}
	pins = s.List()
	if len(pins) != 1 {
		t.Errorf("expected 1 new pin, got %d", len(pins))
	}
}

// TestStore_ForgetByVPNAddr verifies forgetting all pins for a VPN address.
func TestStore_ForgetByVPNAddr(t *testing.T) {
	s := tempStore(t)
	pub1 := genKey(t)
	pub2 := genKey(t)

	s.Check("10.0.0.1", pub1) //nolint:errcheck
	s.Check("10.0.0.1", pub2) //nolint:errcheck
	s.Check("10.0.0.2", pub1) //nolint:errcheck

	// Forget all pins for 10.0.0.1
	if err := s.ForgetByVPNAddr("10.0.0.1"); err != nil {
		t.Fatalf("ForgetByVPNAddr: %v", err)
	}

	// 10.0.0.1 should be clean, 10.0.0.2 should still have pub1.
	pins := s.List()
	found10_0_0_1 := false
	found10_0_0_2 := false
	for k := range pins {
		if k == "10.0.0.1" {
			found10_0_0_1 = true
		}
		if k == "10.0.0.2" {
			found10_0_0_2 = true
		}
	}
	if found10_0_0_1 {
		t.Error("10.0.0.1 pins should have been forgotten")
	}
	if !found10_0_0_2 {
		t.Error("10.0.0.2 pins should still exist")
	}
}