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

type Session struct {
	id        [8]byte
	sendCS    *noise.CipherState
	recvCS    *noise.CipherState
	sendNonce uint64
	createdAt time.Time
	mu        sync.Mutex
	window    replayWindow
}

func New(result *crypto.HandshakeResult) *Session {
	return &Session{
		id:        result.SessionID,
		sendCS:    result.SendCS,
		recvCS:    result.RecvCS,
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
	ct, err := s.sendCS.Encrypt(nil, nil, plaintext)
	if err != nil {
		return 0, nil, err
	}
	return n, ct, nil
}

func (s *Session) Decrypt(nonce uint64, ciphertext []byte) ([]byte, error) {
	s.mu.Lock()
	valid := s.window.checkAndMark(nonce)
	s.mu.Unlock()
	if !valid {
		return nil, nil
	}

	plaintext, err := s.recvCS.Decrypt(nil, nil, ciphertext)
	if err != nil {
		return nil, nil
	}
	return plaintext, nil
}