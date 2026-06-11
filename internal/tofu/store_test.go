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

	err := s.Check("10.0.0.2", pub2)
	if !errors.Is(err, ErrFingerprintMismatch) {
		t.Errorf("different key: got %v, want ErrFingerprintMismatch", err)
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

	// After forget, a new key can be pinned.
	if err := s.Check("10.0.0.2", pub2); err != nil {
		t.Errorf("after Forget, new key should be accepted: %v", err)
	}
}

func TestStore_MultiplePeers_Independent(t *testing.T) {
	s := tempStore(t)
	pubA := genKey(t)
	pubB := genKey(t)

	s.Check("10.0.0.1", pubA) //nolint:errcheck
	s.Check("10.0.0.2", pubB) //nolint:errcheck

	// Swapping keys: A's key presented as B → mismatch.
	if err := s.Check("10.0.0.2", pubA); !errors.Is(err, ErrFingerprintMismatch) {
		t.Errorf("cross-peer key swap should be rejected: %v", err)
	}
	// Same key still accepted for correct peer.
	if err := s.Check("10.0.0.1", pubA); err != nil {
		t.Errorf("correct key for peer A rejected: %v", err)
	}
}

func TestStore_NewFile_NonExistent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "subdir", "tofu.json")
	// Path's parent doesn't exist — New should return an error only if saving fails,
	// but loading a non-existent file is fine (fresh store).
	// Actually: New calls load(); load returns ErrNotExist which is swallowed.
	// The save will fail if the parent dir doesn't exist.
	// Just verify that New on a non-existent path works.
	_, err := New(path)
	// We expect this to succeed (parent missing only causes save to fail later).
	// But on Windows/Linux, the file doesn't exist → load returns ErrNotExist → OK.
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
	// File should not be world-readable (mode 0600).
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
