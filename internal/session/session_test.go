// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package session

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/veldmesh/veld/internal/crypto"
)

func newTestSessionPair(t *testing.T) (initiator *Session, responder *Session) {
	t.Helper()

	idA, err := crypto.Generate()
	if err != nil {
		t.Fatalf("failed to generate identity A: %v", err)
	}

	idB, err := crypto.Generate()
	if err != nil {
		t.Fatalf("failed to generate identity B: %v", err)
	}

	var networkID [16]byte

	initiatorHS, err := crypto.NewInitiatorHS(idA, idB.X25519Public, networkID)
	if err != nil {
		t.Fatalf("failed to create initiator handshake: %v", err)
	}

	responderHS, err := crypto.NewResponderHS(idB, func(ed25519Pub []byte) ([32]byte, bool) {
		if string(ed25519Pub) == string(idA.Ed25519Public) {
			return idA.X25519Public, true
		}
		return [32]byte{}, false
	})
	if err != nil {
		t.Fatalf("failed to create responder handshake: %v", err)
	}

	now := time.Now().UnixNano()

	msg1, err := initiatorHS.BuildMessage1(now)
	if err != nil {
		t.Fatalf("failed to build message 1: %v", err)
	}

	_, err = responderHS.ProcessMessage1(msg1, now)
	if err != nil {
		t.Fatalf("failed to process message 1: %v", err)
	}

	msg2, respResult, err := responderHS.BuildMessage2(now)
	if err != nil {
		t.Fatalf("failed to build message 2: %v", err)
	}

	initResult, err := initiatorHS.ProcessMessage2(msg2, now)
	if err != nil {
		t.Fatalf("failed to process message 2: %v", err)
	}

	return New(initResult), New(respResult)
}

func TestSession_EncryptDecryptRoundTrip(t *testing.T) {
	sA, sB := newTestSessionPair(t)

	plaintext := []byte("hello veld")
	nonce, ct, err := sA.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}
	if ct == nil {
		t.Fatal("ciphertext is nil")
	}

	decrypted, err := sB.Decrypt(nonce, ct)
	if err != nil {
		t.Fatalf("failed to decrypt: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Errorf("decrypted plaintext doesn't match: got %q, want %q", decrypted, plaintext)
	}
}

func TestSession_NonceMonotonicity(t *testing.T) {
	sA, _ := newTestSessionPair(t)

	nonce0, _, err := sA.Encrypt([]byte("msg1"))
	if err != nil {
		t.Fatalf("first encrypt failed: %v", err)
	}

	nonce1, _, err := sA.Encrypt([]byte("msg2"))
	if err != nil {
		t.Fatalf("second encrypt failed: %v", err)
	}

	nonce2, _, err := sA.Encrypt([]byte("msg3"))
	if err != nil {
		t.Fatalf("third encrypt failed: %v", err)
	}

	if nonce0 != 0 {
		t.Errorf("first nonce should be 0, got %d", nonce0)
	}
	if nonce1 != 1 {
		t.Errorf("second nonce should be 1, got %d", nonce1)
	}
	if nonce2 != 2 {
		t.Errorf("third nonce should be 2, got %d", nonce2)
	}
}

func TestSession_ReplayRejection_Duplicate(t *testing.T) {
	sA, sB := newTestSessionPair(t)

	nonce, ct, err := sA.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	plaintext, err := sB.Decrypt(nonce, ct)
	if err != nil {
		t.Fatalf("first decrypt failed: %v", err)
	}
	if plaintext == nil {
		t.Fatal("first decrypt returned nil plaintext")
	}

	plaintext2, err := sB.Decrypt(nonce, ct)
	if plaintext2 != nil || err != nil {
		t.Errorf("second decrypt should return (nil, nil) for replay, got (%v, %v)", plaintext2, err)
	}
}

func TestSession_AuthFailure_SilentDrop(t *testing.T) {
	sA, sB := newTestSessionPair(t)

	nonce, ct, err := sA.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	tampered := make([]byte, len(ct))
	copy(tampered, ct)
	tampered[0] ^= 0xFF

	result, err := sB.Decrypt(nonce, tampered)
	if result != nil || err != nil {
		t.Errorf("decrypt of tampered ciphertext should return (nil, nil), got (%v, %v)", result, err)
	}
}

func TestSession_RekeyThreshold(t *testing.T) {
	sA, _ := newTestSessionPair(t)

	sA.sendNonce = RekeyThreshold

	_, _, err := sA.Encrypt([]byte("x"))
	if !errors.Is(err, ErrRekeyRequired) {
		t.Errorf("expected ErrRekeyRequired, got %v", err)
	}
}

func TestSession_ID(t *testing.T) {
	sA, sB := newTestSessionPair(t)

	idA := sA.ID()
	idB := sB.ID()

	// SessionIDs are randomly assigned [8]byte values; zero is astronomically
	// unlikely but not impossible — log rather than fail hard.
	var zero [8]byte
	if idA == zero {
		t.Log("warning: session A ID is zero (possible but very unlikely)")
	}
	if idB == zero {
		t.Log("warning: session B ID is zero (possible but very unlikely)")
	}

	// The initiator and responder must share the same session ID (derived from
	// the noise handshake).
	if idA != idB {
		t.Errorf("session IDs don't match: initiator %v, responder %v", idA, idB)
	}
}

func TestSession_RekeyTimeLimit(t *testing.T) {
	sA, _ := newTestSessionPair(t)

	// Fresh session should not need rekey.
	if sA.NeedsRekey() {
		t.Error("fresh session should not need rekey")
	}

	// Simulate an old session by setting createdAt to the past (lowered threshold for testing).
	sA.createdAt = time.Now().Add(-RekeyTimeLimit - time.Second)

	// Old session should need rekey.
	if !sA.NeedsRekey() {
		t.Error("session older than RekeyTimeLimit should need rekey")
	}
}

func TestSession_NeedsRekey_NonceThreshold(t *testing.T) {
	sA, _ := newTestSessionPair(t)

	// Fresh session should not need rekey.
	if sA.NeedsRekey() {
		t.Error("fresh session should not need rekey")
	}

	// Set sendNonce to just below the threshold.
	sA.sendNonce = RekeyThreshold - 1

	// Should not need rekey yet.
	if sA.NeedsRekey() {
		t.Error("session at threshold-1 should not need rekey yet")
	}

	// Set sendNonce to the threshold.
	sA.sendNonce = RekeyThreshold

	// Should need rekey.
	if !sA.NeedsRekey() {
		t.Error("session at nonce threshold should need rekey")
	}
}

func TestSession_LossAndReorder(t *testing.T) {
	a, b := newTestSessionPair(t)

	type pkt struct {
		n  uint64
		ct []byte
	}
	var pkts []pkt
	for i := 0; i < 4; i++ {
		n, ct, err := a.Encrypt([]byte{byte(i)})
		if err != nil {
			t.Fatalf("encrypt %d: %v", i, err)
		}
		pkts = append(pkts, pkt{n, ct})
	}

	// Packet 1 is lost and 3 arrives before 2; 0 arrives last.
	for _, i := range []int{3, 2, 0} {
		plain, _ := b.Decrypt(pkts[i].n, pkts[i].ct)
		if len(plain) != 1 || plain[0] != byte(i) {
			t.Errorf("packet %d: got %v", i, plain)
		}
	}
}

func TestSession_ForgedPacketDoesNotPoisonWindow(t *testing.T) {
	a, b := newTestSessionPair(t)

	if plain, _ := b.Decrypt(1<<31, make([]byte, 32)); plain != nil {
		t.Fatal("forged packet decrypted")
	}

	n, ct, _ := a.Encrypt([]byte("hello"))
	if plain, _ := b.Decrypt(n, ct); string(plain) != "hello" {
		t.Errorf("legit packet after forged one: got %q", plain)
	}
}

func TestSession_WrongNonceRejected(t *testing.T) {
	a, b := newTestSessionPair(t)

	n, ct, _ := a.Encrypt([]byte("hello"))
	if plain, _ := b.Decrypt(n+1, ct); plain != nil {
		t.Error("packet decrypted under a nonce it was not sent with")
	}
}

func TestSession_ConcurrentEncryptUniqueNonces(t *testing.T) {
	a, b := newTestSessionPair(t)

	const workers, per = 4, 500
	type pkt struct {
		n  uint64
		ct []byte
	}
	out := make(chan pkt, workers*per)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < per; i++ {
				n, ct, err := a.Encrypt(make([]byte, 16))
				if err != nil {
					t.Error(err)
					return
				}
				out <- pkt{n, ct}
			}
		}()
	}
	wg.Wait()
	close(out)

	seen := map[string]bool{}
	for p := range out {
		if seen[string(p.ct)] {
			t.Fatal("two packets share a ciphertext: nonce reused")
		}
		seen[string(p.ct)] = true
		if plain, _ := b.Decrypt(p.n, p.ct); plain == nil {
			t.Fatalf("packet with nonce %d did not decrypt", p.n)
		}
	}
}
