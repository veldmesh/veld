// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"net/netip"
	"testing"
	"time"

	coordcore "github.com/veldmesh/veld/coord/core"
)

func newSweepTestRegistry(t *testing.T) *Registry {
	t.Helper()
	reg, err := NewRegistry(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	t.Cleanup(func() { _ = reg.Close() })

	cidr := netip.MustParsePrefix("10.0.0.0/24")
	net := coordcore.Network{ID: "net1", CIDR: cidr, Name: "Test Network"}
	if err := reg.CreateNetwork(net, "acc1"); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}
	return reg
}

func registerSweepPeer(t *testing.T, reg *Registry, id string, lastSeen int64) {
	t.Helper()
	rec := peerRecord{
		ID:            id,
		Name:          id,
		Ed25519Public: "dGVzdA==",
		X25519Public:  "dGVzdA==",
		LastSeen:      lastSeen,
		RegisteredAt:  lastSeen,
	}
	if _, err := reg.RegisterPeer(rec, "net1", 0); err != nil {
		t.Fatalf("RegisterPeer %s: %v", id, err)
	}
}

func TestRegistry_SweepStalePeers_RemovesOnlyStale(t *testing.T) {
	reg := newSweepTestRegistry(t)

	now := time.Now().Unix()
	registerSweepPeer(t, reg, "fresh", now)
	registerSweepPeer(t, reg, "stale", now-int64((48*time.Hour).Seconds()))

	removed, err := reg.SweepStalePeers(24 * time.Hour)
	if err != nil {
		t.Fatalf("SweepStalePeers: %v", err)
	}
	if removed != 1 {
		t.Errorf("removed: got %d, want 1", removed)
	}

	if _, err := reg.GetPeer("stale"); err == nil {
		t.Errorf("stale peer still present after sweep")
	}
	if _, err := reg.GetPeer("fresh"); err != nil {
		t.Errorf("fresh peer missing after sweep: %v", err)
	}

	count, err := reg.NetworkMachineCount("net1")
	if err != nil || count != 1 {
		t.Errorf("machine count after sweep: got %d, want 1", count)
	}
}

func TestRegistry_SweepStalePeers_NothingStale(t *testing.T) {
	reg := newSweepTestRegistry(t)

	now := time.Now().Unix()
	registerSweepPeer(t, reg, "fresh1", now)
	registerSweepPeer(t, reg, "fresh2", now)

	removed, err := reg.SweepStalePeers(24 * time.Hour)
	if err != nil {
		t.Fatalf("SweepStalePeers: %v", err)
	}
	if removed != 0 {
		t.Errorf("removed: got %d, want 0", removed)
	}

	count, err := reg.NetworkMachineCount("net1")
	if err != nil || count != 2 {
		t.Errorf("machine count: got %d, want 2", count)
	}
}

func TestRegistry_SweepStalePeers_FallsBackToRegisteredAt(t *testing.T) {
	reg := newSweepTestRegistry(t)

	now := time.Now().Unix()
	// LastSeen unset (0) but registered recently: must survive the sweep.
	rec := peerRecord{
		ID:            "no-heartbeat",
		Name:          "no-heartbeat",
		Ed25519Public: "dGVzdA==",
		X25519Public:  "dGVzdA==",
		LastSeen:      0,
		RegisteredAt:  now,
	}
	if _, err := reg.RegisterPeer(rec, "net1", 0); err != nil {
		t.Fatalf("RegisterPeer: %v", err)
	}

	removed, err := reg.SweepStalePeers(24 * time.Hour)
	if err != nil {
		t.Fatalf("SweepStalePeers: %v", err)
	}
	if removed != 0 {
		t.Errorf("removed: got %d, want 0 (peer registered recently)", removed)
	}
}

func TestStartPeerSweeper_RunsPeriodically(t *testing.T) {
	reg := newSweepTestRegistry(t)

	now := time.Now().Unix()
	registerSweepPeer(t, reg, "stale", now-int64((48*time.Hour).Seconds()))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	StartPeerSweeper(ctx, reg, 24*time.Hour, 10*time.Millisecond, func(string, ...any) {})

	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := reg.GetPeer("stale"); err != nil {
			return // swept
		}
		if time.Now().After(deadline) {
			t.Fatal("stale peer not swept within 2s")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestStartPeerSweeper_Disabled(t *testing.T) {
	reg := newSweepTestRegistry(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// ttl <= 0 must be a no-op (no goroutine panics, no deletions).
	registerSweepPeer(t, reg, "p", 0)
	StartPeerSweeper(ctx, reg, 0, 10*time.Millisecond, func(string, ...any) {})
	time.Sleep(50 * time.Millisecond)
	if _, err := reg.GetPeer("p"); err != nil {
		t.Errorf("peer removed with sweeper disabled: %v", err)
	}
}
