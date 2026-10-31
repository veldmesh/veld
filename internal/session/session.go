// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package session

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/flynn/noise"
	"github.com/veldmesh/veld/internal/crypto"
)

const (
	RekeyThreshold uint64 = 1 << 32
	RekeyTimeLimit        = 120 * time.Second // 2 minutes, matching WireGuard
)

var ErrRekeyRequired = errors.New("session nonce threshold reached: rekey required")

// Session encrypts with the nonce carried on the wire rather than the
// CipherState's internal counter: Encrypt may be called from several
// goroutines at once, and packets may arrive lost or reordered.
type Session struct {
	id        [8]byte
	send      noise.Cipher
	recv      noise.Cipher
	sendNonce uint64
	createdAt time.Time
	mu        sync.Mutex
	window    replayWindow
}

func New(result *crypto.HandshakeResult) *Session {
	return &Session{
		id:        result.SessionID,
		send:      result.SendCS.Cipher(),
		recv:      result.RecvCS.Cipher(),
		createdAt: time.Now(),
	}
}

func (s *Session) ID() [8]byte { return s.id }

// CreatedAt returns the session creation time.
func (s *Session) CreatedAt() time.Time {
	return s.createdAt
}

// SetCreatedAt sets the session creation time. Used to adjust the session age
// for the time-based rekey check (e.g., after a clock adjustment).
func (s *Session) SetCreatedAt(t time.Time) {
	s.createdAt = t
}

// NeedsRekey returns true if the session has exceeded either the nonce
// threshold or the time limit and should be rekeyed.
func (s *Session) NeedsRekey() bool {
	return atomic.LoadUint64(&s.sendNonce) >= RekeyThreshold ||
		time.Since(s.createdAt) >= RekeyTimeLimit
}

func (s *Session) Encrypt(plaintext []byte) (uint64, []byte, error) {
	n := atomic.AddUint64(&s.sendNonce, 1) - 1
	if n >= RekeyThreshold {
		return 0, nil, ErrRekeyRequired
	}
	return n, s.send.Encrypt(nil, n, nil, plaintext), nil
}

// Decrypt authenticates and decrypts a packet sent with the given nonce. The
// replay window is only updated once the packet authenticates, so a forged
// packet cannot advance it.
func (s *Session) Decrypt(nonce uint64, ciphertext []byte) ([]byte, error) {
	if nonce >= RekeyThreshold {
		return nil, nil
	}
	s.mu.Lock()
	valid := s.window.check(nonce)
	s.mu.Unlock()
	if !valid {
		return nil, nil
	}

	plaintext, err := s.recv.Decrypt(nil, nonce, nil, ciphertext)
	if err != nil {
		return nil, nil
	}

	s.mu.Lock()
	valid = s.window.checkAndMark(nonce)
	s.mu.Unlock()
	if !valid {
		return nil, nil
	}
	return plaintext, nil
}
