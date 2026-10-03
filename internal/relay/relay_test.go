// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package relay

import (
	"context"
	"testing"
	"time"

	"github.com/veldmesh/veld/internal/crypto"
)

func mustIdentity(t *testing.T) *crypto.Identity {
	t.Helper()
	id, err := crypto.Generate()
	if err != nil {
		t.Fatalf("crypto.Generate: %v", err)
	}
	return id
}

func TestChannelID(t *testing.T) {
	var a, b, c [32]byte
	for i := range a {
		a[i] = byte(i)
		b[i] = byte(i + 1)
		c[i] = byte(i + 2)
	}

	t.Run("symmetric", func(t *testing.T) {
		if ChannelID(a, b) != ChannelID(b, a) {
			t.Error("ChannelID must be symmetric in the peer pair")
		}
	})

	t.Run("deterministic", func(t *testing.T) {
		first := ChannelID(a, b)
		if ChannelID(a, b) != first {
			t.Error("ChannelID must be deterministic")
		}
	})

	t.Run("distinct per pair", func(t *testing.T) {
		if ChannelID(a, b) == ChannelID(a, c) {
			t.Error("different peer pairs must derive different channel IDs")
		}
	})

	t.Run("self pair is valid", func(t *testing.T) {
		_ = ChannelID(a, a) // must not panic
	})
}

func TestDialUnreachable(t *testing.T) {
	idA := mustIdentity(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// Port 1 on loopback is never listening.
	_, err := Dial(ctx, "127.0.0.1:1", [32]byte{9}, idA, [32]byte{1})
	if err == nil {
		t.Fatal("Dial to unreachable relay must fail")
	}
}
