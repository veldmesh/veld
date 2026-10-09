// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	coordv1 "github.com/veldmesh/veld/gen/veld/coord/v1"
	coordcore "github.com/veldmesh/veld/coord/core"
	"github.com/veldmesh/veld/coord/ce"
)

// fakeWatchStream implements coordv1.Coord_WatchServer for testing.
type fakeWatchStream struct {
	ctx    context.Context
	cancel context.CancelFunc
	events []*coordv1.PeerEvent
}

func (f *fakeWatchStream) Send(ev *coordv1.PeerEvent) error {
	f.events = append(f.events, ev)
	return nil
}

func (f *fakeWatchStream) Context() context.Context {
	return f.ctx
}

func (f *fakeWatchStream) SetHeader(metadata.MD) error      { return nil }
func (f *fakeWatchStream) SendHeader(metadata.MD) error     { return nil }
func (f *fakeWatchStream) SetTrailer(metadata.MD)           {}
func (f *fakeWatchStream) SendMsg(m interface{}) error      { return nil }
func (f *fakeWatchStream) RecvMsg(m interface{}) error      { return nil }

func newFakeWatchStream() *fakeWatchStream {
	ctx, cancel := context.WithCancel(context.Background())
	return &fakeWatchStream{ctx: ctx, cancel: cancel}
}

// testServer creates a server with a temp registry and known token setup
func testServer(t *testing.T) (*Server, *Registry) {
	tmpDir := t.TempDir()
	reg, err := NewRegistry(tmpDir + "/test.db")
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	// Create test network
	cidr := netip.MustParsePrefix("10.99.0.0/24")
	net := coordcore.Network{ID: "test-net", CIDR: cidr, Name: "Test Network"}
	if err := reg.CreateNetwork(net, "acc1"); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}

	bus := NewBus()
	enforcer := ce.NewFreeEnforcer()
	accounts := ce.NewTokenAccountStore(map[string]coordcore.Account{
		"test-token": {ID: "acc1", Tier: coordcore.TierFree},
	})
	audit := ce.NewNoopAuditLogger()
	subnet := ce.NewRejectSubnetPolicy()
	hooks := ce.NewNoopHooks()

	return New(reg, bus, enforcer, accounts, audit, subnet, hooks), reg
}

func TestServer_Register_OK(t *testing.T) {
	srv, reg := testServer(t)
	defer reg.Close()

	ed25519Pub := base64.StdEncoding.EncodeToString([]byte("ed25519pubkey123"))
	x25519Pub := base64.StdEncoding.EncodeToString([]byte("x25519pubkey123"))

	req := &coordv1.RegisterRequest{
		NetworkId:     "test-net",
		Token:         "test-token",
		Name:          "peer1",
		Ed25519Public: ed25519Pub,
		X25519Public:  x25519Pub,
		Endpoint:      "192.168.1.1:51820",
	}

	resp, err := srv.Register(context.Background(), req)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	if resp.VpnAddr == "" || resp.PeerId == "" {
		t.Errorf("Register response incomplete: %+v", resp)
	}

	// Verify IP is within CIDR
	vpnAddr, _ := netip.ParseAddr(resp.VpnAddr)
	cidr := netip.MustParsePrefix("10.99.0.0/24")
	if !cidr.Contains(vpnAddr) {
		t.Errorf("assigned IP %s not in CIDR %s", resp.VpnAddr, cidr)
	}

	if resp.NetworkId != "test-net" {
		t.Errorf("NetworkId mismatch: got %s, want test-net", resp.NetworkId)
	}
}

func TestServer_Register_InvalidToken(t *testing.T) {
	srv, reg := testServer(t)
	defer reg.Close()

	ed25519Pub := base64.StdEncoding.EncodeToString([]byte("ed25519pubkey123"))
	x25519Pub := base64.StdEncoding.EncodeToString([]byte("x25519pubkey123"))

	req := &coordv1.RegisterRequest{
		NetworkId:     "test-net",
		Token:         "bad-token",
		Name:          "peer1",
		Ed25519Public: ed25519Pub,
		X25519Public:  x25519Pub,
	}

	_, err := srv.Register(context.Background(), req)
	if err == nil {
		t.Fatal("Register should fail with invalid token")
	}
}

func TestServer_Register_NetworkNotFound(t *testing.T) {
	srv, reg := testServer(t)
	defer reg.Close()

	ed25519Pub := base64.StdEncoding.EncodeToString([]byte("ed25519pubkey123"))
	x25519Pub := base64.StdEncoding.EncodeToString([]byte("x25519pubkey123"))

	req := &coordv1.RegisterRequest{
		NetworkId:     "nonexistent-net",
		Token:         "test-token",
		Name:          "peer1",
		Ed25519Public: ed25519Pub,
		X25519Public:  x25519Pub,
	}

	_, err := srv.Register(context.Background(), req)
	if err == nil {
		t.Fatal("Register should fail with nonexistent network")
	}
}

func TestServer_Register_MachineLimit(t *testing.T) {
	srv, reg := testServer(t)
	defer reg.Close()

	// Register 5 peers (free limit is 5)
	for i := 0; i < 5; i++ {
		ed25519Pub := base64.StdEncoding.EncodeToString([]byte("ed25519pubkey" + string(rune('0'+i))))
		x25519Pub := base64.StdEncoding.EncodeToString([]byte("x25519pubkey" + string(rune('0'+i))))

		req := &coordv1.RegisterRequest{
			NetworkId:     "test-net",
			Token:         "test-token",
			Name:          "peer" + string(rune('1'+i)),
			Ed25519Public: ed25519Pub,
			X25519Public:  x25519Pub,
		}

		if _, err := srv.Register(context.Background(), req); err != nil {
			t.Fatalf("Register peer %d: %v", i+1, err)
		}
	}

	// 6th registration should fail
	ed25519Pub := base64.StdEncoding.EncodeToString([]byte("ed25519pubkey5"))
	x25519Pub := base64.StdEncoding.EncodeToString([]byte("x25519pubkey5"))

	req := &coordv1.RegisterRequest{
		NetworkId:     "test-net",
		Token:         "test-token",
		Name:          "peer6",
		Ed25519Public: ed25519Pub,
		X25519Public:  x25519Pub,
	}

	_, err := srv.Register(context.Background(), req)
	if err == nil {
		t.Fatal("Register should fail when machine limit reached")
	}
}

func TestServer_ListPeers_OK(t *testing.T) {
	srv, reg := testServer(t)
	defer reg.Close()

	// Register 2 peers
	for i := 0; i < 2; i++ {
		ed25519Pub := base64.StdEncoding.EncodeToString([]byte("ed25519pubkey" + string(rune('0'+i))))
		x25519Pub := base64.StdEncoding.EncodeToString([]byte("x25519pubkey" + string(rune('0'+i))))

		req := &coordv1.RegisterRequest{
			NetworkId:     "test-net",
			Token:         "test-token",
			Name:          "peer" + string(rune('1'+i)),
			Ed25519Public: ed25519Pub,
			X25519Public:  x25519Pub,
		}

		if _, err := srv.Register(context.Background(), req); err != nil {
			t.Fatalf("Register: %v", err)
		}
	}

	// List peers
	listReq := &coordv1.ListPeersRequest{
		NetworkId: "test-net",
		Token:     "test-token",
	}

	resp, err := srv.ListPeers(context.Background(), listReq)
	if err != nil {
		t.Fatalf("ListPeers: %v", err)
	}

	if len(resp.Peers) != 2 {
		t.Errorf("ListPeers: got %d peers, want 2", len(resp.Peers))
	}

	for i, peer := range resp.Peers {
		if peer.Name != "peer"+string(rune('1'+i)) {
			t.Errorf("Peer %d name: got %s, want peer%d", i, peer.Name, 1+i)
		}
	}
}

func TestServer_ListPeers_InvalidToken(t *testing.T) {
	srv, reg := testServer(t)
	defer reg.Close()

	listReq := &coordv1.ListPeersRequest{
		NetworkId: "test-net",
		Token:     "bad-token",
	}

	_, err := srv.ListPeers(context.Background(), listReq)
	if err == nil {
		t.Fatal("ListPeers should fail with invalid token")
	}
}

func TestServer_Leave_OK(t *testing.T) {
	srv, reg := testServer(t)
	defer reg.Close()

	// Register a peer
	ed25519Pub := base64.StdEncoding.EncodeToString([]byte("ed25519pubkey123"))
	x25519Pub := base64.StdEncoding.EncodeToString([]byte("x25519pubkey123"))

	regReq := &coordv1.RegisterRequest{
		NetworkId:     "test-net",
		Token:         "test-token",
		Name:          "peer1",
		Ed25519Public: ed25519Pub,
		X25519Public:  x25519Pub,
	}

	regResp, err := srv.Register(context.Background(), regReq)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Leave
	leaveReq := &coordv1.LeaveRequest{
		Token:  "test-token",
		PeerId: regResp.PeerId,
	}

	_, err = srv.Leave(context.Background(), leaveReq)
	if err != nil {
		t.Fatalf("Leave: %v", err)
	}

	// Verify peer is gone
	listReq := &coordv1.ListPeersRequest{
		NetworkId: "test-net",
		Token:     "test-token",
	}

	listResp, err := srv.ListPeers(context.Background(), listReq)
	if err != nil {
		t.Fatalf("ListPeers: %v", err)
	}

	if len(listResp.Peers) != 0 {
		t.Errorf("ListPeers after Leave: got %d peers, want 0", len(listResp.Peers))
	}
}

func TestServer_Leave_NotFound(t *testing.T) {
	srv, reg := testServer(t)
	defer reg.Close()

	leaveReq := &coordv1.LeaveRequest{
		Token:  "test-token",
		PeerId: "nonexistent-peer",
	}

	_, err := srv.Leave(context.Background(), leaveReq)
	if err == nil {
		t.Fatal("Leave should fail with nonexistent peer")
	}
}

func TestServer_SendSignal_OK(t *testing.T) {
	srv, reg := testServer(t)
	defer reg.Close()

	register := func(name string) string {
		t.Helper()
		resp, err := srv.Register(context.Background(), &coordv1.RegisterRequest{
			NetworkId:     "test-net",
			Token:         "test-token",
			Name:          name,
			Ed25519Public: base64.StdEncoding.EncodeToString([]byte("ed25519-" + name)),
			X25519Public:  base64.StdEncoding.EncodeToString([]byte("x25519-" + name)),
		})
		if err != nil {
			t.Fatalf("Register %s: %v", name, err)
		}
		return resp.PeerId
	}
	idA := register("signal-a")
	idB := register("signal-b")

	_, err := srv.SendSignal(context.Background(), &coordv1.SendSignalRequest{
		Token:      "test-token",
		FromPeerId: idA,
		ToPeerId:   idB,
		Payload:    []byte("test signal"),
	})
	if err != nil {
		t.Fatalf("SendSignal: %v", err)
	}
}

func TestServer_SendSignal_InvalidToken(t *testing.T) {
	srv, reg := testServer(t)
	defer reg.Close()

	req := &coordv1.SendSignalRequest{
		Token:      "bad-token",
		FromPeerId: "peer1",
		ToPeerId:   "peer2",
		Payload:    []byte("test signal"),
	}

	_, err := srv.SendSignal(context.Background(), req)
	if err == nil {
		t.Fatal("SendSignal should fail with invalid token")
	}
}

func TestServer_Watch_ReceivesJoinEvent(t *testing.T) {
	srv, reg := testServer(t)
	defer reg.Close()

	// Start Watch in a goroutine
	watchReq := &coordv1.WatchRequest{
		NetworkId: "test-net",
		Token:     "test-token",
	}

	stream := newFakeWatchStream()
	done := make(chan error, 1)

	go func() {
		done <- srv.Watch(watchReq, stream)
	}()

	// Give Watch time to start
	time.Sleep(50 * time.Millisecond)

	// Register a peer (this should trigger a JOIN event)
	ed25519Pub := base64.StdEncoding.EncodeToString([]byte("ed25519pubkey123"))
	x25519Pub := base64.StdEncoding.EncodeToString([]byte("x25519pubkey123"))

	regReq := &coordv1.RegisterRequest{
		NetworkId:     "test-net",
		Token:         "test-token",
		Name:          "peer1",
		Ed25519Public: ed25519Pub,
		X25519Public:  x25519Pub,
	}

	_, err := srv.Register(context.Background(), regReq)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Cancel the watch context to stop the goroutine
	stream.cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Watch returned error: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Watch goroutine did not finish")
	}

	// Verify we received the JOIN event
	if len(stream.events) == 0 {
		t.Fatal("Watch did not receive JOIN event")
	}

	firstEvent := stream.events[0]
	if firstEvent.Type != coordv1.EventType_JOIN {
		t.Errorf("First event type: got %v, want JOIN", firstEvent.Type)
	}

	if firstEvent.Peer.Name != "peer1" {
		t.Errorf("Peer name: got %s, want peer1", firstEvent.Peer.Name)
	}
}

func TestServer_Watch_ReceivesLeaveEvent(t *testing.T) {
	srv, reg := testServer(t)
	defer reg.Close()

	// Register a peer first.
	ed25519Pub := base64.StdEncoding.EncodeToString([]byte("ed25519pubkey123"))
	x25519Pub := base64.StdEncoding.EncodeToString([]byte("x25519pubkey123"))

	regResp, err := srv.Register(context.Background(), &coordv1.RegisterRequest{
		NetworkId:     "test-net",
		Token:         "test-token",
		Name:          "peer1",
		Ed25519Public: ed25519Pub,
		X25519Public:  x25519Pub,
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Start Watch.
	stream := newFakeWatchStream()
	done := make(chan error, 1)
	go func() {
		done <- srv.Watch(&coordv1.WatchRequest{
			NetworkId: "test-net",
			Token:     "test-token",
		}, stream)
	}()

	time.Sleep(50 * time.Millisecond)

	// Now leave — should trigger LEAVE event.
	_, err = srv.Leave(context.Background(), &coordv1.LeaveRequest{
		Token:  "test-token",
		PeerId: regResp.PeerId,
	})
	if err != nil {
		t.Fatalf("Leave: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	stream.cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Watch error: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Watch goroutine did not finish")
	}

	var leaveEvent *coordv1.PeerEvent
	for _, ev := range stream.events {
		if ev.Type == coordv1.EventType_LEAVE {
			leaveEvent = ev
			break
		}
	}
	if leaveEvent == nil {
		t.Fatalf("no LEAVE event received; events: %v", stream.events)
	}
	if leaveEvent.Peer.Id != regResp.PeerId {
		t.Errorf("LEAVE event peer ID: got %s, want %s", leaveEvent.Peer.Id, regResp.PeerId)
	}
}

func TestServer_Watch_ReceivesEndpointUpdate(t *testing.T) {
	srv, reg := testServer(t)
	defer reg.Close()

	ed25519Pub := base64.StdEncoding.EncodeToString([]byte("ed25519pubkey123"))
	x25519Pub := base64.StdEncoding.EncodeToString([]byte("x25519pubkey123"))

	// First registration.
	regResp, err := srv.Register(context.Background(), &coordv1.RegisterRequest{
		NetworkId:     "test-net",
		Token:         "test-token",
		Name:          "peer1",
		Ed25519Public: ed25519Pub,
		X25519Public:  x25519Pub,
		Endpoint:      "1.2.3.4:51820",
	})
	if err != nil {
		t.Fatalf("first Register: %v", err)
	}

	// Start Watch.
	stream := newFakeWatchStream()
	done := make(chan error, 1)
	go func() {
		done <- srv.Watch(&coordv1.WatchRequest{
			NetworkId: "test-net",
			Token:     "test-token",
		}, stream)
	}()

	time.Sleep(50 * time.Millisecond)

	// Re-register with a different endpoint.
	_, err = srv.Register(context.Background(), &coordv1.RegisterRequest{
		NetworkId:     "test-net",
		Token:         "test-token",
		Name:          "peer1",
		Ed25519Public: ed25519Pub,
		X25519Public:  x25519Pub,
		Endpoint:      "9.8.7.6:51820",
	})
	if err != nil {
		t.Fatalf("second Register: %v", err)
	}

	time.Sleep(50 * time.Millisecond)
	stream.cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Watch error: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Watch goroutine did not finish")
	}

	// We expect at least one event related to this peer after Watch started
	// (either an ENDPOINT_UPDATE or a second JOIN).
	found := false
	for _, ev := range stream.events {
		if ev.Peer != nil && ev.Peer.Id == regResp.PeerId {
			if ev.Type == coordv1.EventType_ENDPOINT_UPDATE || ev.Type == coordv1.EventType_JOIN {
				found = true
				break
			}
		}
	}
	if !found {
		t.Errorf("no ENDPOINT_UPDATE or JOIN event for peer %s after re-register; events: %v", regResp.PeerId, stream.events)
	}
}

func TestServer_Register_Concurrent(t *testing.T) {
	srv, reg := testServer(t)
	defer reg.Close()

	const total = 10
	errCh := make(chan error, total)
	var wg sync.WaitGroup

	for i := 0; i < total; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			ed25519Pub := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("ed25519pubkey%02d", i)))
			x25519Pub := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("x25519pubkey%02d", i)))
			_, err := srv.Register(context.Background(), &coordv1.RegisterRequest{
				NetworkId:     "test-net",
				Token:         "test-token",
				Name:          fmt.Sprintf("peer%d", i),
				Ed25519Public: ed25519Pub,
				X25519Public:  x25519Pub,
			})
			errCh <- err
		}()
	}

	wg.Wait()
	close(errCh)

	var successes, failures int
	for err := range errCh {
		if err == nil {
			successes++
		} else {
			failures++
		}
	}

	// Free tier allows 5 machines; the other 5 should fail.
	if successes > 5 {
		t.Errorf("expected at most 5 successes (free limit), got %d", successes)
	}
	if successes+failures != total {
		t.Errorf("successes+failures should equal %d, got %d", total, successes+failures)
	}
}

func TestServer_Register_Idempotent(t *testing.T) {
	srv, reg := testServer(t)
	defer reg.Close()

	ed25519Pub := base64.StdEncoding.EncodeToString([]byte("ed25519pubkeyXX"))
	x25519Pub := base64.StdEncoding.EncodeToString([]byte("x25519pubkeyXX"))

	req := &coordv1.RegisterRequest{
		NetworkId:     "test-net",
		Token:         "test-token",
		Name:          "idempotent-peer",
		Ed25519Public: ed25519Pub,
		X25519Public:  x25519Pub,
	}

	resp1, err := srv.Register(context.Background(), req)
	if err != nil {
		t.Fatalf("first Register: %v", err)
	}

	resp2, err := srv.Register(context.Background(), req)
	if err != nil {
		t.Fatalf("second Register: %v", err)
	}

	if resp1.VpnAddr != resp2.VpnAddr {
		t.Errorf("VpnAddr changed on idempotent register: first %s, second %s", resp1.VpnAddr, resp2.VpnAddr)
	}
	if resp1.PeerId != resp2.PeerId {
		t.Errorf("PeerId changed on idempotent register: first %s, second %s", resp1.PeerId, resp2.PeerId)
	}
}

// A client registers first and opens Watch afterwards. A peer that is already
// watching sees the JOIN in between and signals immediately; that signal must
// reach the newcomer once its Watch opens (it used to be dropped, so NAT
// traversal succeeded on one side only — flaky TestNATTraversal_TwoPeersViaCoord).
func TestServer_SignalSentBeforeRecipientWatches_IsDelivered(t *testing.T) {
	srv, reg := testServer(t)
	defer reg.Close()

	register := func(name string) string {
		resp, err := srv.Register(context.Background(), &coordv1.RegisterRequest{
			NetworkId:     "test-net",
			Token:         "test-token",
			Name:          name,
			Ed25519Public: base64.StdEncoding.EncodeToString([]byte("ed25519-" + name)),
			X25519Public:  base64.StdEncoding.EncodeToString([]byte("x25519-" + name)),
		})
		if err != nil {
			t.Fatalf("Register %s: %v", name, err)
		}
		return resp.PeerId
	}
	idA := register("node-a")
	idB := register("node-b")

	// B signals A before A has opened its Watch stream.
	if _, err := srv.SendSignal(context.Background(), &coordv1.SendSignalRequest{
		Token: "test-token", FromPeerId: idB, ToPeerId: idA, Payload: []byte("candidates-from-b"),
	}); err != nil {
		t.Fatalf("SendSignal: %v", err)
	}

	stream := newFakeWatchStream()
	done := make(chan error, 1)
	go func() {
		done <- srv.Watch(&coordv1.WatchRequest{NetworkId: "test-net", Token: "test-token", PeerId: idA}, stream)
	}()
	time.Sleep(100 * time.Millisecond)
	stream.cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Watch goroutine did not finish")
	}

	for _, ev := range stream.events {
		if ev.Type == coordv1.EventType_SIGNAL && ev.Signal != nil &&
			ev.Signal.FromPeerId == idB && string(ev.Signal.Payload) == "candidates-from-b" {
			return
		}
	}
	t.Fatalf("signal sent before Watch was not delivered; events: %v", stream.events)
}

func TestServer_SignalToUnknownPeer_IsNotHeld(t *testing.T) {
	srv, reg := testServer(t)
	defer reg.Close()

	resp, err := srv.Register(context.Background(), &coordv1.RegisterRequest{
		NetworkId:     "test-net",
		Token:         "test-token",
		Name:          "signal-sender",
		Ed25519Public: base64.StdEncoding.EncodeToString([]byte("ed25519-signal-sender")),
		X25519Public:  base64.StdEncoding.EncodeToString([]byte("x25519-signal-sender")),
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	// The recipient is not registered: the request must be rejected outright
	// instead of silently accepted, and nothing may be held for it.
	_, err = srv.SendSignal(context.Background(), &coordv1.SendSignalRequest{
		Token: "test-token", FromPeerId: resp.PeerId, ToPeerId: "no-such-peer", Payload: []byte("p"),
	})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("SendSignal to an unregistered peer: got %v, want NotFound", err)
	}
	srv.bus.mu.RLock()
	defer srv.bus.mu.RUnlock()
	if len(srv.bus.pending) != 0 {
		t.Fatalf("signal for an unregistered peer was held: %v", srv.bus.pending)
	}
}

// twoAccountTestServer builds a server with two accounts (token "tok-a" ->
// account acc1, token "tok-b" -> account acc2) and two networks: "net-a"
// owned by acc1 and "net-b" owned by acc2.
func twoAccountTestServer(t *testing.T) (*Server, *Registry) {
	t.Helper()
	reg, err := NewRegistry(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	if err := reg.CreateNetwork(coordcore.Network{ID: "net-a", CIDR: netip.MustParsePrefix("10.1.0.0/24"), Name: "A"}, "acc1"); err != nil {
		t.Fatalf("CreateNetwork net-a: %v", err)
	}
	if err := reg.CreateNetwork(coordcore.Network{ID: "net-b", CIDR: netip.MustParsePrefix("10.2.0.0/24"), Name: "B"}, "acc2"); err != nil {
		t.Fatalf("CreateNetwork net-b: %v", err)
	}
	accounts := ce.NewTokenAccountStore(map[string]coordcore.Account{
		"tok-a": {ID: "acc1", Tier: coordcore.TierFree},
		"tok-b": {ID: "acc2", Tier: coordcore.TierFree},
	})
	srv := New(reg, NewBus(), ce.NewFreeEnforcer(), accounts, ce.NewNoopAuditLogger(), ce.NewRejectSubnetPolicy(), ce.NewNoopHooks())
	return srv, reg
}

// registerTestPeer inserts a peer record directly into the registry.
func registerTestPeer(t *testing.T, reg *Registry, id, networkID string) {
	t.Helper()
	now := time.Now().Unix()
	rec := peerRecord{
		ID:            id,
		Name:          id,
		Ed25519Public: "dGVzdA==",
		X25519Public:  "dGVzdA==",
		LastSeen:      now,
		RegisteredAt:  now,
	}
	if _, err := reg.RegisterPeer(rec, networkID, 0); err != nil {
		t.Fatalf("RegisterPeer %s: %v", id, err)
	}
}

func TestServer_SendSignal_SenderNotOwnedByCaller_IsRejected(t *testing.T) {
	srv, reg := twoAccountTestServer(t)
	defer reg.Close()
	registerTestPeer(t, reg, "a1", "net-a") // acc1's peer
	registerTestPeer(t, reg, "b1", "net-b") // acc2's peer

	// A caller authenticated as acc1 claims to be acc2's peer. Without the
	// ownership check it could both spoof acc2 and make the registered
	// recipient hold a signal that never really came from b1's account.
	_, err := srv.SendSignal(context.Background(), &coordv1.SendSignalRequest{
		Token: "tok-a", FromPeerId: "b1", ToPeerId: "a1", Payload: []byte("spoofed"),
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("SendSignal with a foreign from_peer_id: got %v, want PermissionDenied", err)
	}

	srv.bus.mu.RLock()
	defer srv.bus.mu.RUnlock()
	if len(srv.bus.pending) != 0 {
		t.Fatalf("signal from a spoofed sender was held: %v", srv.bus.pending)
	}
}

func TestServer_SendSignal_PeersNotInSameNetwork_IsRejected(t *testing.T) {
	srv, reg := twoAccountTestServer(t)
	defer reg.Close()
	registerTestPeer(t, reg, "a1", "net-a")
	registerTestPeer(t, reg, "b1", "net-b")

	// Both peers are registered, but they do not share a network.
	_, err := srv.SendSignal(context.Background(), &coordv1.SendSignalRequest{
		Token: "tok-a", FromPeerId: "a1", ToPeerId: "b1", Payload: []byte("p"),
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("SendSignal across networks: got %v, want PermissionDenied", err)
	}

	srv.bus.mu.RLock()
	defer srv.bus.mu.RUnlock()
	if len(srv.bus.pending) != 0 {
		t.Fatalf("signal to a peer in another network was held: %v", srv.bus.pending)
	}
}

func TestServer_SendSignal_UnknownSender_IsRejected(t *testing.T) {
	srv, reg := twoAccountTestServer(t)
	defer reg.Close()
	registerTestPeer(t, reg, "a1", "net-a")

	_, err := srv.SendSignal(context.Background(), &coordv1.SendSignalRequest{
		Token: "tok-a", FromPeerId: "no-such-sender", ToPeerId: "a1", Payload: []byte("p"),
	})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("SendSignal with an unregistered sender: got %v, want NotFound", err)
	}

	srv.bus.mu.RLock()
	defer srv.bus.mu.RUnlock()
	if len(srv.bus.pending) != 0 {
		t.Fatalf("signal from an unregistered sender was held: %v", srv.bus.pending)
	}
}
