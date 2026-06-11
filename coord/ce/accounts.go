// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: BUSL-1.1
package ce

import (
	"context"
	"sync"

	coordcore "github.com/veldmesh/veld/coord/core"
)

// TokenAccountStore implements AccountStore using an in-memory token map.
// All tokens resolve to Free tier. Used by CE coord server.
type TokenAccountStore struct {
	mu     sync.RWMutex
	tokens map[string]coordcore.Account
}

func NewTokenAccountStore(tokens map[string]coordcore.Account) *TokenAccountStore {
	t := make(map[string]coordcore.Account, len(tokens))
	for k, v := range tokens {
		t[k] = v
	}
	return &TokenAccountStore{tokens: t}
}

func (s *TokenAccountStore) Resolve(_ context.Context, token string) (coordcore.Account, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	acc, ok := s.tokens[token]
	if !ok {
		return coordcore.Account{}, coordcore.ErrUnknownToken
	}
	return acc, nil
}

func (s *TokenAccountStore) RecordActivity(_ context.Context, _ string) error {
	return nil
}
