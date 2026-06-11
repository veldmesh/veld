// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package session

import (
	"errors"
	"sync"
	"sync/atomic"

	"github.com/flynn/noise"
	"github.com/veldmesh/veld/internal/crypto"
)

const (
	RekeyThreshold uint64 = 1 << 32
)

var ErrRekeyRequired = errors.New("session nonce threshold reached: rekey required")

type Session struct {
	id        [8]byte
	sendCS    *noise.CipherState
	recvCS    *noise.CipherState
	sendNonce uint64
	mu        sync.Mutex
	window    replayWindow
}

func New(result *crypto.HandshakeResult) *Session {
	return &Session{
		id:     result.SessionID,
		sendCS: result.SendCS,
		recvCS: result.RecvCS,
	}
}

func (s *Session) ID() [8]byte { return s.id }

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
