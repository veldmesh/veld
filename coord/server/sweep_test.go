// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/veldmesh/veld/coord/ce"
	coordcore "github.com/veldmesh/veld/coord/core"
	coordv1 "github.com/veldmesh/veld/gen/veld/coord/v1"
)

// recordingHooks records OnPeerLeft calls for assertions.
type recordingHooks struct {
	mu   sync.Mutex
	left []coordcore.Peer
}

func (h *recordingHooks) OnPeerRegistered(ctx context.Context, peer coordcore.Peer, network coordcore.Network) {
}
func (h *recordingHooks) OnPeerLeft(ctx context.Context, peer coordcore.Peer, network coordcore.Network) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.left = append(h.left, peer)
}
func (h *recordingHooks) OnNetworkCreated(ctx context.Context, network coordcore.Network, account coordcore.Account) {
}
func (h *recordingHooks) OnSubnetRouteAdvertised(ctx context.Context, peer coordcore.Peer, route netip.Prefix) {
}

// recordingAudit records audit events for assertions.
type recordingAudit struct {
	mu     sync.Mutex
	events []coordcore.AuditEvent
}

func (a *recordingAudit) Log(ctx context.Context, ev coordcore.AuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, ev)
	return nil
}

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

// newSweepTestServer builds a Server on the sweep test registry (network
// "net1", account "acc1") with recording hooks and audit.
func newSweepTestServer(t *testing.T) (*Server, *Registry, *recordingHooks, *recordingAudit) {
	t.Helper()
	reg := newSweepTestRegistry(t)
	hooks := &recordingHooks{}
	audit := &recordingAudit{}
	accounts := ce.NewTokenAccountStore(map[string]coordcore.Account{
		"tok": {ID: "acc1", Tier: coordcore.TierFree},
	})
	srv := New(reg, NewBus(), ce.NewFreeEnforcer(), accounts, audit, ce.NewRejectSubnetPolicy(), hooks)
	return srv, reg, hooks, audit
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

	removed, err := reg.SweepStalePeers(24*time.Hour, nil)
	if err != nil {
		t.Fatalf("SweepStalePeers: %v", err)
	}
	if len(removed) != 1 {
		t.Fatalf("removed: got %d, want 1", len(removed))
	}
	if removed[0].ID != "stale" {
		t.Errorf("removed peer: got %q, want %q", removed[0].ID, "stale")
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

	removed, err := reg.SweepStalePeers(24*time.Hour, nil)
	if err != nil {
		t.Fatalf("SweepStalePeers: %v", err)
	}
	if len(removed) != 0 {
		t.Errorf("removed: got %d, want 0", len(removed))
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

	removed, err := reg.SweepStalePeers(24*time.Hour, nil)
	if err != nil {
		t.Fatalf("SweepStalePeers: %v", err)
	}
	if len(removed) != 0 {
		t.Errorf("removed: got %d, want 0 (peer registered recently)", len(removed))
	}
}

func TestRegistry_SweepStalePeers_SkipPredicate(t *testing.T) {
	reg := newSweepTestRegistry(t)

	now := time.Now().Unix()
	registerSweepPeer(t, reg, "stale-but-online", now-int64((48*time.Hour).Seconds()))

	removed, err := reg.SweepStalePeers(24*time.Hour, func(peerID string) bool { return true })
	if err != nil {
		t.Fatalf("SweepStalePeers: %v", err)
	}
	if len(removed) != 0 {
		t.Errorf("removed: got %d, want 0 (peer skipped)", len(removed))
	}
	if _, err := reg.GetPeer("stale-but-online"); err != nil {
		t.Errorf("skipped peer removed anyway: %v", err)
	}
}

func TestRegistry_TouchPeer(t *testing.T) {
	reg := newSweepTestRegistry(t)

	old := time.Now().Add(-48 * time.Hour).Unix()
	registerSweepPeer(t, reg, "p", old)

	if err := reg.TouchPeer("p"); err != nil {
		t.Fatalf("TouchPeer: %v", err)
	}
	rec, err := reg.GetPeer("p")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if rec.LastSeen <= old {
		t.Errorf("LastSeen not refreshed: got %d, was %d", rec.LastSeen, old)
	}
	if rec.RegisteredAt != old {
		t.Errorf("RegisteredAt changed: got %d, want %d", rec.RegisteredAt, old)
	}

	if err := reg.TouchPeer("unknown"); err == nil {
		t.Errorf("TouchPeer on unknown peer should fail")
	}
}

func TestServer_ExpelStalePeers_FullLeaveSemantics(t *testing.T) {
	srv, reg, hooks, audit := newSweepTestServer(t)

	now := time.Now().Unix()
	registerSweepPeer(t, reg, "stale", now-int64((48*time.Hour).Seconds()))
	registerSweepPeer(t, reg, "fresh", now)

	// Watch the network so we can observe the LEAVE event for the swept peer.
	stream := newFakeWatchStream()
	done := make(chan error, 1)
	go func() {
		done <- srv.Watch(&coordv1.WatchRequest{NetworkId: "net1", Token: "tok"}, stream)
	}()
	time.Sleep(50 * time.Millisecond)

	removed, err := srv.ExpelStalePeers(context.Background(), 24*time.Hour)
	if err != nil {
		t.Fatalf("ExpelStalePeers: %v", err)
	}
	if removed != 1 {
		t.Errorf("removed: got %d, want 1", removed)
	}
	if _, err := reg.GetPeer("stale"); err == nil {
		t.Errorf("stale peer still present after expel")
	}

	time.Sleep(50 * time.Millisecond)
	stream.cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Watch error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Watch goroutine did not finish")
	}

	// LEAVE event published to watchers, exactly like a graceful Leave.
	var leave *coordv1.PeerEvent
	for _, ev := range stream.events {
		if ev.Type == coordv1.EventType_LEAVE {
			leave = ev
		}
	}
	if leave == nil {
		t.Fatalf("no LEAVE event for swept peer; events: %v", stream.events)
	}
	if leave.Peer.Id != "stale" {
		t.Errorf("LEAVE peer id: got %q, want %q", leave.Peer.Id, "stale")
	}

	// Lifecycle hook fired.
	hooks.mu.Lock()
	defer hooks.mu.Unlock()
	if len(hooks.left) != 1 || hooks.left[0].ID != "stale" {
		t.Errorf("OnPeerLeft calls: got %+v, want exactly one for \"stale\"", hooks.left)
	}

	// Audit entry recorded with the network's account.
	audit.mu.Lock()
	defer audit.mu.Unlock()
	var found bool
	for _, ev := range audit.events {
		if ev.Kind == coordcore.AuditPeerLeft && ev.PeerID == "stale" && ev.AccountID == "acc1" {
			found = true
		}
	}
	if !found {
		t.Errorf("no peer.left audit entry for swept peer; events: %+v", audit.events)
	}
}

func TestServer_ExpelStalePeers_SkipsConnectedPeer(t *testing.T) {
	srv, reg, hooks, _ := newSweepTestServer(t)

	// Peer is stale by LastSeen but currently connected via Watch.
	old := time.Now().Add(-48 * time.Hour).Unix()
	registerSweepPeer(t, reg, "online-stale", old)

	stream := newFakeWatchStream()
	done := make(chan error, 1)
	go func() {
		done <- srv.Watch(&coordv1.WatchRequest{NetworkId: "net1", Token: "tok", PeerId: "online-stale"}, stream)
	}()

	// Wait until the server observes the peer as connected.
	deadline := time.Now().Add(time.Second)
	for !srv.IsConnected("online-stale") {
		if time.Now().After(deadline) {
			t.Fatal("peer never marked connected")
		}
		time.Sleep(5 * time.Millisecond)
	}

	removed, err := srv.ExpelStalePeers(context.Background(), time.Hour)
	if err != nil {
		t.Fatalf("ExpelStalePeers: %v", err)
	}
	if removed != 0 {
		t.Errorf("removed: got %d, want 0 (peer is connected)", removed)
	}
	if _, err := reg.GetPeer("online-stale"); err != nil {
		t.Errorf("connected peer was swept: %v", err)
	}

	// Connecting also refreshed LastSeen (async), so the peer is no longer stale.
	freshDeadline := time.Now().Add(2 * time.Second)
	for {
		rec, err := reg.GetPeer("online-stale")
		if err != nil {
			t.Fatalf("GetPeer: %v", err)
		}
		if rec.LastSeen > old {
			break
		}
		if time.Now().After(freshDeadline) {
			t.Errorf("LastSeen not refreshed while connected: got %d, was %d", rec.LastSeen, old)
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	rec, err := reg.GetPeer("online-stale")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if rec.LastSeen <= old {
		t.Errorf("LastSeen not refreshed while connected: got %d, was %d", rec.LastSeen, old)
	}

	stream.cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Watch error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Watch goroutine did not finish")
	}

	// After disconnect the peer is no longer tracked.
	deadline = time.Now().Add(time.Second)
	for srv.IsConnected("online-stale") {
		if time.Now().After(deadline) {
			t.Fatal("peer still marked connected after Watch ended")
		}
		time.Sleep(5 * time.Millisecond)
	}

	hooks.mu.Lock()
	defer hooks.mu.Unlock()
	if len(hooks.left) != 0 {
		t.Errorf("OnPeerLeft fired for connected peer: %+v", hooks.left)
	}
}

func TestStartPeerSweeper_RunsPeriodically(t *testing.T) {
	srv, reg, _, _ := newSweepTestServer(t)

	now := time.Now().Unix()
	registerSweepPeer(t, reg, "stale", now-int64((48*time.Hour).Seconds()))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Interval is intentionally tiny (10ms) so the test does not wait for
	// the 1h production default; see DefaultSweepInterval docs.
	StartPeerSweeper(ctx, srv, 24*time.Hour, 10*time.Millisecond, func(string, ...any) {})

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
	srv, reg, _, _ := newSweepTestServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// ttl <= 0 must be a no-op (no goroutine panics, no deletions).
	registerSweepPeer(t, reg, "p", 0)
	StartPeerSweeper(ctx, srv, 0, 10*time.Millisecond, func(string, ...any) {})
	time.Sleep(50 * time.Millisecond)
	if _, err := reg.GetPeer("p"); err != nil {
		t.Errorf("peer removed with sweeper disabled: %v", err)
	}
}
