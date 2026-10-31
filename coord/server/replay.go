// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package server

import (
	"crypto/sha256"
	"sync"
	"time"
)

// maxSeenSignatures bounds the replay cache. Only callers holding a peer's
// private key can add entries, so this is a backstop, not a quota.
const maxSeenSignatures = 1 << 16

// seenSignatures remembers signatures accepted within the timestamp window,
// so a captured Register or call signature cannot be replayed while its
// timestamp is still valid.
type seenSignatures struct {
	mu     sync.Mutex
	seen   map[[32]byte]time.Time // signature hash -> when it may be forgotten
	window time.Duration
}

func newSeenSignatures(window time.Duration) *seenSignatures {
	return &seenSignatures{seen: make(map[[32]byte]time.Time), window: window}
}

// firstUse records sig and reports whether it had not been seen before. It
// refuses new signatures while the cache is full of unexpired entries.
func (s *seenSignatures) firstUse(sig []byte, now time.Time) bool {
	key := sha256.Sum256(sig)
	s.mu.Lock()
	defer s.mu.Unlock()
	if exp, ok := s.seen[key]; ok && now.Before(exp) {
		return false
	}
	if len(s.seen) >= maxSeenSignatures {
		for k, exp := range s.seen {
			if !now.Before(exp) {
				delete(s.seen, k)
			}
		}
		if len(s.seen) >= maxSeenSignatures {
			return false
		}
	}
	// A timestamp may lie up to window in the future, so keep the entry
	// for twice the window.
	s.seen[key] = now.Add(2 * s.window)
	return true
}
