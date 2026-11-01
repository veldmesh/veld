// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package tofu

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
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

	s.Check("10.0.0.2", pub) //nolint:errcheck -- first pin

	if err := s.Check("10.0.0.2", pub); err != nil {
		t.Errorf("same key should be accepted: %v", err)
	}
}

func TestStore_DifferentKeyAtSameVPN_Rejected(t *testing.T) {
	s := tempStore(t)
	pub1 := genKey(t)
	pub2 := genKey(t)

	s.Check("10.0.0.2", pub1) //nolint:errcheck -- first pin

	// Different Ed25519 key at same VPN is a TOFU violation -- rejected.
	err := s.Check("10.0.0.2", pub2)
	if !errors.Is(err, ErrFingerprintMismatch) {
		t.Errorf("different key at same VPN should be rejected: got %v, want ErrFingerprintMismatch", err)
	}

	pins := s.List()
	// Only the first peer remains pinned.
	if len(pins) != 1 {
		t.Errorf("expected 1 pin, got %d", len(pins))
	}
}

func TestStore_Persist_AcrossLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tofu.json")

	pub := genKey(t)

	s1, _ := New(path)
	s1.Check("10.0.0.2", pub) //nolint:errcheck

	s2, err := New(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if err := s2.Check("10.0.0.2", pub); err != nil {
		t.Errorf("reloaded store rejected same key: %v", err)
	}

	pub2 := genKey(t)
	// Different key at same VPN is a TOFU violation -- rejected.
	if err := s2.Check("10.0.0.2", pub2); !errors.Is(err, ErrFingerprintMismatch) {
		t.Errorf("reloaded store should reject different key at same VPN: %v", err)
	}
}

func TestStore_Forget_ReallowsRepin(t *testing.T) {
	s := tempStore(t)
	pub1 := genKey(t)
	pub2 := genKey(t)

	s.Check("10.0.0.2", pub1) //nolint:errcheck -- first pin

	if err := s.Forget(pub1); err != nil {
		t.Fatalf("Forget: %v", err)
	}

	// After Forget(pub1), the VPN address is unpinned.
	// pub1 can be pinned again.
	if err := s.Check("10.0.0.2", pub1); err != nil {
		t.Errorf("after Forget, pub1 should be accepted: %v", err)
	}

	// Now pub1 is pinned at 10.0.0.2 again. pub2 at same VPN should be rejected.
	if err := s.Check("10.0.0.2", pub2); !errors.Is(err, ErrFingerprintMismatch) {
		t.Errorf("pub2 should be rejected (pub1 now occupies VPN): %v", err)
	}
}

func TestStore_MultipleVPNs_Independent(t *testing.T) {
	s := tempStore(t)
	pubA := genKey(t)
	pubB := genKey(t)

	s.Check("10.0.0.1", pubA) //nolint:errcheck
	s.Check("10.0.0.2", pubB) //nolint:errcheck

	if err := s.Check("10.0.0.1", pubA); err != nil {
		t.Errorf("VPN A with key A rejected: %v", err)
	}
	if err := s.Check("10.0.0.2", pubB); err != nil {
		t.Errorf("VPN B with key B rejected: %v", err)
	}
	// Same pubA at different VPN -- updates VPN address for pubA.
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

func TestStore_Migration_OldFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tofu.json")

	oldData := `{
  "version": 1,
  "pins": [
    {"peer_key": "10.0.0.1", "fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
    {"peer_key": "10.0.0.2", "fingerprint": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
  ]
}`
	if err := os.WriteFile(path, []byte(oldData), 0600); err != nil {
		t.Fatalf("write old file: %v", err)
	}

	s, err := New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// v1 entries have no pubkey -- dropped during migration.
	pins := s.List()
	if len(pins) != 0 {
		t.Errorf("old entries should be migrated away, got %d", len(pins))
	}

	pub := genKey(t)
	if err := s.Check("10.0.0.1", pub); err != nil {
		t.Errorf("new Check after migration: %v", err)
	}
	pins = s.List()
	if len(pins) != 1 {
		t.Errorf("expected 1 new pin, got %d", len(pins))
	}
}

func TestStore_ForgetByVPNAddr(t *testing.T) {
	s := tempStore(t)
	pub1 := genKey(t)
	pub2 := genKey(t)

	// pub1 at 10.0.0.1
	s.Check("10.0.0.1", pub1) //nolint:errcheck
	// pub2 at 10.0.0.2 (different VPN)
	s.Check("10.0.0.2", pub2) //nolint:errcheck

	// Forget by VPN address 10.0.0.1 -- should remove pub1.
	if err := s.ForgetByVPNAddr("10.0.0.1"); err != nil {
		t.Fatalf("ForgetByVPNAddr: %v", err)
	}

	pins := s.List()
	_, found1 := pins["10.0.0.1"]
	_, found2 := pins["10.0.0.2"]
	if found1 {
		t.Error("10.0.0.1 pins should have been forgotten")
	}
	if !found2 {
		t.Error("10.0.0.2 pins should still exist")
	}
}

func TestStore_Migration_MixedFormats(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tofu.json")

	validFP := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	mixedData := `{
  "version": 2,
  "pins": [
    {"vpn_addr": "10.0.0.1", "ed25519_pub": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "fingerprint": "` + validFP + `"},
    {"vpn_addr": "10.0.0.2", "ed25519_pub": "", "fingerprint": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
  ]
}`
	if err := os.WriteFile(path, []byte(mixedData), 0600); err != nil {
		t.Fatalf("write mixed file: %v", err)
	}

	s, err := New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// v2 entry with pubkey is migrated (re-keyed by pubkey).
	// v2 entry without pubkey is dropped.
	pins := s.List()
	if len(pins) != 1 {
		t.Errorf("expected 1 valid pin after migration, got %d", len(pins))
	}

	// The migrated entry has pubkey "aaaa..." pinned to fingerprint "aaaa..." at VPN 10.0.0.1.
	// A different key at same VPN is a TOFU violation -- rejected.
	pub := genKey(t)
	if err := s.Check("10.0.0.1", pub); !errors.Is(err, ErrFingerprintMismatch) {
		t.Errorf("different key at same VPN should be rejected: got %v, want ErrFingerprintMismatch", err)
	}

	// Forget the migrated pubkey.
	pubKeyToForget, _ := hex.DecodeString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err := s.Forget(pubKeyToForget); err != nil {
		t.Fatalf("Forget: %v", err)
	}
	// Now the VPN is unpinned, first key is accepted.
	if err := s.Check("10.0.0.1", pub); err != nil {
		t.Errorf("after Forget, first key should be accepted: %v", err)
	}
	pins = s.List()
	if len(pins) != 1 {
		t.Errorf("expected 1 pin after re-pin, got %d", len(pins))
	}
}

// TestStore_MovedKeyKeepsOldAddress covers moving a peer and then pinning a
// new key at its old address: the old address must stay reserved, also
// across a reload.
func TestStore_MovedKeyKeepsOldAddress(t *testing.T) {
	s := tempStore(t)
	real, evil := genKey(t), genKey(t)

	if err := s.Check("10.0.0.2", real); err != nil {
		t.Fatal(err)
	}
	if err := s.Check("10.0.0.99", real); err != nil {
		t.Fatalf("move: %v", err)
	}
	if err := s.Check("10.0.0.2", evil); !errors.Is(err, ErrFingerprintMismatch) {
		t.Errorf("new key at the moved-from address: got %v, want mismatch", err)
	}

	s2, err := New(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s2.Check("10.0.0.2", evil); !errors.Is(err, ErrFingerprintMismatch) {
		t.Errorf("after reload: got %v, want mismatch", err)
	}
	// The key may move back to its old address.
	if err := s2.Check("10.0.0.2", real); err != nil {
		t.Errorf("move back: %v", err)
	}

	// Forgetting by any of its addresses releases all of them.
	if err := s2.ForgetByVPNAddr("10.0.0.99"); err != nil {
		t.Fatal(err)
	}
	if err := s2.Check("10.0.0.2", evil); err != nil {
		t.Errorf("after forget: %v", err)
	}
}

func TestStore_KnownKeyCannotTakePinnedAddress(t *testing.T) {
	s := tempStore(t)
	a, b := genKey(t), genKey(t)
	if err := s.Check("10.0.0.1", a); err != nil {
		t.Fatal(err)
	}
	if err := s.Check("10.0.0.2", b); err != nil {
		t.Fatal(err)
	}
	if err := s.Check("10.0.0.1", b); !errors.Is(err, ErrFingerprintMismatch) {
		t.Errorf("b moving onto a's address: got %v, want mismatch", err)
	}
	if err := s.Check("10.0.0.1", a); err != nil {
		t.Errorf("a at its own address: %v", err)
	}
}
