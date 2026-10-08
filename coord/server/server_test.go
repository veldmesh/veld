// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"encoding/base64"
	"encoding/hex"
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

	// Signals are scoped to registered peers, so register two first.
	var ids [2]string
	for i := 0; i < 2; i++ {
		ed25519Pub := base64.StdEncoding.EncodeToString([]byte("ed25519pubkey" + string(rune('0'+i))))
		x25519Pub := base64.StdEncoding.EncodeToString([]byte("x25519pubkey" + string(rune('0'+i))))

		resp, err := srv.Register(context.Background(), &coordv1.RegisterRequest{
			NetworkId:     "test-net",
			Token:         "test-token",
			Name:          "peer" + string(rune('1'+i)),
			Ed25519Public: ed25519Pub,
			X25519Public:  x25519Pub,
		})
		if err != nil {
			t.Fatalf("Register peer %d: %v", i, err)
		}
		ids[i] = resp.PeerId
	}

	// Watch as the target peer so the delivered signal is observable.
	stream := newFakeWatchStream()
	done := make(chan error, 1)
	go func() {
		done <- srv.Watch(&coordv1.WatchRequest{
			NetworkId: "test-net",
			Token:     "test-token",
			PeerId:    ids[1],
		}, stream)
	}()
	time.Sleep(50 * time.Millisecond)

	_, err := srv.SendSignal(context.Background(), &coordv1.SendSignalRequest{
		Token:      "test-token",
		FromPeerId: ids[0],
		ToPeerId:   ids[1],
		Payload:    []byte("test signal"),
	})
	if err != nil {
		stream.cancel()
		t.Fatalf("SendSignal: %v", err)
	}

	// Let the signal flow through the bus before closing the stream.
	time.Sleep(100 * time.Millisecond)
	stream.cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Watch error: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Watch goroutine did not finish")
	}

	var got *coordv1.SignalEvent
	for _, ev := range stream.events {
		if ev.Type == coordv1.EventType_SIGNAL && ev.Signal != nil {
			got = ev.Signal
			break
		}
	}
	if got == nil {
		t.Fatalf("signal not delivered to target peer; events: %+v", stream.events)
	}
	if got.FromPeerId != ids[0] || string(got.Payload) != "test signal" {
		t.Errorf("delivered signal: got %+v, want from %s payload %q", got, ids[0], "test signal")
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

// scopedKeyB64 base64-encodes test key material, the wire form the coord
// API uses for public keys.
func scopedKeyB64(material string) string {
	return base64.StdEncoding.EncodeToString([]byte(material))
}

// scopedFixture is a Server wired for per-account scoping tests: account A
// ("acc-a", token "token-a") owns netA and netA2, account B ("acc-b", token
// "token-b") owns netB, and seed peers are registered in each network.
type scopedFixture struct {
	srv    *Server
	reg    *Registry
	netA   string
	netA2  string
	netB   string
	tokenA string
	tokenB string
	peerA1 string // peer in netA  (account A)
	peerA2 string // peer in netA  (account A)
	peerA3 string // peer in netA2 (account A)
	peerB1 string // peer in netB  (account B)

	// watched holds the events collected by the most recent watch helper
	// call so a table row's check can assert on them.
	watched []*coordv1.PeerEvent
}

// newScopedFixture builds the two-account test server and registers the
// seed peers through the Register RPC, exactly like real daemons do.
func newScopedFixture(t *testing.T) *scopedFixture {
	t.Helper()
	reg, err := NewRegistry(t.TempDir() + "/scoped.db")
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	t.Cleanup(func() { _ = reg.Close() })

	nets := []struct{ id, cidr, owner string }{
		{"net-a", "10.99.0.0/24", "acc-a"},
		{"net-a2", "10.99.2.0/24", "acc-a"},
		{"net-b", "10.99.1.0/24", "acc-b"},
	}
	for _, n := range nets {
		cidr := netip.MustParsePrefix(n.cidr)
		if err := reg.CreateNetwork(coordcore.Network{ID: n.id, CIDR: cidr, Name: n.id}, n.owner); err != nil {
			t.Fatalf("CreateNetwork %s: %v", n.id, err)
		}
	}

	accounts := ce.NewTokenAccountStore(map[string]coordcore.Account{
		"token-a": {ID: "acc-a", Tier: coordcore.TierFree},
		"token-b": {ID: "acc-b", Tier: coordcore.TierFree},
	})
	srv := New(reg, NewBus(), ce.NewFreeEnforcer(), accounts, ce.NewNoopAuditLogger(), ce.NewRejectSubnetPolicy(), ce.NewNoopHooks())

	f := &scopedFixture{
		srv:    srv,
		reg:    reg,
		netA:   "net-a",
		netA2:  "net-a2",
		netB:   "net-b",
		tokenA: "token-a",
		tokenB: "token-b",
	}
	f.peerA1 = scopedRegister(t, f, f.netA, f.tokenA, "peer-a1", "peer-a1-ed25519", "peer-a1-x25519", "1.1.1.1:1111")
	f.peerA2 = scopedRegister(t, f, f.netA, f.tokenA, "peer-a2", "peer-a2-ed25519", "peer-a2-x25519", "")
	f.peerA3 = scopedRegister(t, f, f.netA2, f.tokenA, "peer-a3", "peer-a3-ed25519", "peer-a3-x25519", "")
	f.peerB1 = scopedRegister(t, f, f.netB, f.tokenB, "peer-b1", "peer-b1-ed25519", "peer-b1-x25519", "")
	return f
}

// scopedRegister registers a peer through the Register RPC and returns the
// assigned peer ID (hex of the Ed25519 key material).
func scopedRegister(t *testing.T, f *scopedFixture, networkID, token, name, ed25519Mat, x25519Mat, endpoint string) string {
	t.Helper()
	resp, err := f.srv.Register(context.Background(), &coordv1.RegisterRequest{
		NetworkId:     networkID,
		Token:         token,
		Name:          name,
		Ed25519Public: scopedKeyB64(ed25519Mat),
		X25519Public:  scopedKeyB64(x25519Mat),
		Endpoint:      endpoint,
	})
	if err != nil {
		t.Fatalf("Register %s into %s: %v", name, networkID, err)
	}
	return resp.PeerId
}

// scopedWatch runs a Watch stream for req to completion (stopping it after
// a short wait) and returns the stream error and the events received.
func (f *scopedFixture) scopedWatch(t *testing.T, req *coordv1.WatchRequest) ([]*coordv1.PeerEvent, error) {
	t.Helper()
	stream := newFakeWatchStream()
	done := make(chan error, 1)
	go func() { done <- f.srv.Watch(req, stream) }()
	time.Sleep(100 * time.Millisecond)
	stream.cancel()
	select {
	case err := <-done:
		return stream.events, err
	case <-time.After(2 * time.Second):
		t.Fatal("Watch did not finish after cancel")
		return nil, nil
	}
}

// watchDuring starts a Watch for peerID in networkID (authenticated with
// token), lets the subscription establish, runs fn, then stops the stream
// and returns the events it received.
func (f *scopedFixture) watchDuring(t *testing.T, token, networkID, peerID string, fn func()) []*coordv1.PeerEvent {
	t.Helper()
	stream := newFakeWatchStream()
	done := make(chan error, 1)
	go func() {
		done <- f.srv.Watch(&coordv1.WatchRequest{NetworkId: networkID, Token: token, PeerId: peerID}, stream)
	}()
	time.Sleep(100 * time.Millisecond) // let the subscription establish
	fn()
	time.Sleep(100 * time.Millisecond) // let any (wrongly) delivered signal arrive
	stream.cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("watchDuring: Watch did not finish")
	}
	return stream.events
}

// assertNetworkPeers fails unless an authorized ListPeers shows networkID
// holding exactly the given peer IDs.
func assertNetworkPeers(t *testing.T, f *scopedFixture, token, networkID string, wantIDs ...string) {
	t.Helper()
	resp, err := f.srv.ListPeers(context.Background(), &coordv1.ListPeersRequest{NetworkId: networkID, Token: token})
	if err != nil {
		t.Fatalf("ListPeers %s: %v", networkID, err)
	}
	got := make(map[string]bool, len(resp.Peers))
	for _, p := range resp.Peers {
		got[p.Id] = true
	}
	if len(got) != len(wantIDs) {
		t.Errorf("network %s peers: got %d (%v), want exactly %d (%v)", networkID, len(got), got, len(wantIDs), wantIDs)
		return
	}
	for _, id := range wantIDs {
		if !got[id] {
			t.Errorf("network %s: expected peer %s, got %v", networkID, id, got)
		}
	}
}

// assertMachineCount fails unless the network's registered machine count
// equals want.
func assertMachineCount(t *testing.T, f *scopedFixture, networkID string, want int) {
	t.Helper()
	count, err := f.reg.NetworkMachineCount(networkID)
	if err != nil {
		t.Fatalf("NetworkMachineCount %s: %v", networkID, err)
	}
	if count != want {
		t.Errorf("network %s machine count: got %d, want %d", networkID, count, want)
	}
}

// assertNoSignal fails if any collected event is a delivered signal.
func assertNoSignal(t *testing.T, events []*coordv1.PeerEvent) {
	t.Helper()
	for _, ev := range events {
		if ev.Type == coordv1.EventType_SIGNAL {
			t.Errorf("signal delivered despite scoping: %+v", ev.Signal)
		}
	}
}

// TestServer_PerAccountScoping is a table over every coord RPC: a request
// may only read or change state inside networks owned by the token's
// account, and may only name peers registered in those networks. Each
// cross-account row uses account B's valid token against account A's
// networks or peers and must fail with codes.NotFound without any state
// change; each same-account row keeps working.
func TestServer_PerAccountScoping(t *testing.T) {
	cases := []struct {
		name     string
		call     func(t *testing.T, f *scopedFixture) error
		check    func(t *testing.T, f *scopedFixture)
		wantCode codes.Code
	}{
		{
			name: "Register into another account's network",
			call: func(t *testing.T, f *scopedFixture) error {
				_, err := f.srv.Register(context.Background(), &coordv1.RegisterRequest{
					NetworkId:     f.netA,
					Token:         f.tokenB,
					Name:          "b-new-peer",
					Ed25519Public: scopedKeyB64("b-new-peer-ed25519"),
					X25519Public:  scopedKeyB64("b-new-peer-x25519"),
				})
				return err
			},
			check: func(t *testing.T, f *scopedFixture) {
				// A's network still holds exactly its own peers.
				assertNetworkPeers(t, f, f.tokenA, f.netA, f.peerA1, f.peerA2)
				assertMachineCount(t, f, f.netA, 2)
			},
			wantCode: codes.NotFound,
		},
		{
			name: "ListPeers of another account's network",
			call: func(t *testing.T, f *scopedFixture) error {
				_, err := f.srv.ListPeers(context.Background(), &coordv1.ListPeersRequest{NetworkId: f.netA, Token: f.tokenB})
				return err
			},
			check: func(t *testing.T, f *scopedFixture) {
				// Account A's own view is unchanged.
				assertNetworkPeers(t, f, f.tokenA, f.netA, f.peerA1, f.peerA2)
			},
			wantCode: codes.NotFound,
		},
		{
			name: "Watch another account's network",
			call: func(t *testing.T, f *scopedFixture) error {
				events, err := f.scopedWatch(t, &coordv1.WatchRequest{NetworkId: f.netA, Token: f.tokenB})
				f.watched = events
				return err
			},
			check: func(t *testing.T, f *scopedFixture) {
				if len(f.watched) != 0 {
					t.Errorf("rejected Watch delivered events: %+v", f.watched)
				}
			},
			wantCode: codes.NotFound,
		},
		{
			name: "Watch own network naming another account's peer",
			call: func(t *testing.T, f *scopedFixture) error {
				events, err := f.scopedWatch(t, &coordv1.WatchRequest{NetworkId: f.netB, Token: f.tokenB, PeerId: f.peerA1})
				f.watched = events
				return err
			},
			check: func(t *testing.T, f *scopedFixture) {
				if len(f.watched) != 0 {
					t.Errorf("rejected Watch delivered events: %+v", f.watched)
				}
				if f.srv.IsConnected(f.peerA1) {
					t.Error("rejected Watch still marked the foreign peer connected")
				}
			},
			wantCode: codes.NotFound,
		},
		{
			name: "SendSignal to another account's peer",
			call: func(t *testing.T, f *scopedFixture) error {
				var rpcErr error
				f.watched = f.watchDuring(t, f.tokenA, f.netA, f.peerA1, func() {
					_, rpcErr = f.srv.SendSignal(context.Background(), &coordv1.SendSignalRequest{
						Token:      f.tokenB,
						FromPeerId: f.peerB1,
						ToPeerId:   f.peerA1,
						Payload:    []byte("scoped?"),
					})
				})
				return rpcErr
			},
			check: func(t *testing.T, f *scopedFixture) {
				assertNoSignal(t, f.watched)
			},
			wantCode: codes.NotFound,
		},
		{
			name: "SendSignal as another account's peer",
			call: func(t *testing.T, f *scopedFixture) error {
				var rpcErr error
				f.watched = f.watchDuring(t, f.tokenA, f.netA, f.peerA2, func() {
					_, rpcErr = f.srv.SendSignal(context.Background(), &coordv1.SendSignalRequest{
						Token:      f.tokenB,
						FromPeerId: f.peerA1,
						ToPeerId:   f.peerA2,
						Payload:    []byte("scoped?"),
					})
				})
				return rpcErr
			},
			check: func(t *testing.T, f *scopedFixture) {
				assertNoSignal(t, f.watched)
			},
			wantCode: codes.NotFound,
		},
		{
			name: "Leave another account's peer",
			call: func(t *testing.T, f *scopedFixture) error {
				_, err := f.srv.Leave(context.Background(), &coordv1.LeaveRequest{Token: f.tokenB, PeerId: f.peerA1})
				return err
			},
			check: func(t *testing.T, f *scopedFixture) {
				// The peer is still registered.
				assertNetworkPeers(t, f, f.tokenA, f.netA, f.peerA1, f.peerA2)
				assertMachineCount(t, f, f.netA, 2)
			},
			wantCode: codes.NotFound,
		},
		{
			name: "SendSignal across two networks of the same account",
			call: func(t *testing.T, f *scopedFixture) error {
				var rpcErr error
				f.watched = f.watchDuring(t, f.tokenA, f.netA2, f.peerA3, func() {
					_, rpcErr = f.srv.SendSignal(context.Background(), &coordv1.SendSignalRequest{
						Token:      f.tokenA,
						FromPeerId: f.peerA1,
						ToPeerId:   f.peerA3,
						Payload:    []byte("cross-net"),
					})
				})
				return rpcErr
			},
			check: func(t *testing.T, f *scopedFixture) {
				assertNoSignal(t, f.watched)
			},
			wantCode: codes.NotFound,
		},
		// Same-account requests keep working.
		{
			name: "Register into own network succeeds",
			call: func(t *testing.T, f *scopedFixture) error {
				_, err := f.srv.Register(context.Background(), &coordv1.RegisterRequest{
					NetworkId:     f.netB,
					Token:         f.tokenB,
					Name:          "b-second-peer",
					Ed25519Public: scopedKeyB64("b-second-peer-ed25519"),
					X25519Public:  scopedKeyB64("b-second-peer-x25519"),
				})
				return err
			},
			check: func(t *testing.T, f *scopedFixture) {
				assertNetworkPeers(t, f, f.tokenB, f.netB, f.peerB1, hex.EncodeToString([]byte("b-second-peer-ed25519")))
				assertMachineCount(t, f, f.netB, 2)
			},
			wantCode: codes.OK,
		},
		{
			name: "ListPeers of own network succeeds",
			call: func(t *testing.T, f *scopedFixture) error {
				_, err := f.srv.ListPeers(context.Background(), &coordv1.ListPeersRequest{NetworkId: f.netA, Token: f.tokenA})
				return err
			},
			check: func(t *testing.T, f *scopedFixture) {
				assertNetworkPeers(t, f, f.tokenA, f.netA, f.peerA1, f.peerA2)
			},
			wantCode: codes.OK,
		},
		{
			name: "Watch own network with own peer succeeds",
			call: func(t *testing.T, f *scopedFixture) error {
				events, err := f.scopedWatch(t, &coordv1.WatchRequest{NetworkId: f.netA, Token: f.tokenA, PeerId: f.peerA1})
				f.watched = events
				return err
			},
			check: func(t *testing.T, f *scopedFixture) {
				// The initial snapshot arrives as synthetic JOIN events
				// for the other peers in the network.
				var sawPeerA2 bool
				for _, ev := range f.watched {
					if ev.Type == coordv1.EventType_JOIN && ev.Peer != nil && ev.Peer.Id == f.peerA2 {
						sawPeerA2 = true
					}
				}
				if !sawPeerA2 {
					t.Errorf("Watch snapshot missing JOIN for %s; events: %+v", f.peerA2, f.watched)
				}
			},
			wantCode: codes.OK,
		},
		{
			name: "SendSignal within own network succeeds",
			call: func(t *testing.T, f *scopedFixture) error {
				var rpcErr error
				f.watched = f.watchDuring(t, f.tokenA, f.netA, f.peerA2, func() {
					_, rpcErr = f.srv.SendSignal(context.Background(), &coordv1.SendSignalRequest{
						Token:      f.tokenA,
						FromPeerId: f.peerA1,
						ToPeerId:   f.peerA2,
						Payload:    []byte("probe"),
					})
				})
				return rpcErr
			},
			check: func(t *testing.T, f *scopedFixture) {
				var got *coordv1.SignalEvent
				for _, ev := range f.watched {
					if ev.Type == coordv1.EventType_SIGNAL && ev.Signal != nil {
						got = ev.Signal
					}
				}
				if got == nil {
					t.Fatalf("no SIGNAL delivered; events: %+v", f.watched)
				}
				if got.FromPeerId != f.peerA1 || string(got.Payload) != "probe" {
					t.Errorf("SIGNAL content: got %+v, want from %s payload %q", got, f.peerA1, "probe")
				}
			},
			wantCode: codes.OK,
		},
		{
			name: "Leave own peer succeeds",
			call: func(t *testing.T, f *scopedFixture) error {
				_, err := f.srv.Leave(context.Background(), &coordv1.LeaveRequest{Token: f.tokenA, PeerId: f.peerA2})
				return err
			},
			check: func(t *testing.T, f *scopedFixture) {
				assertNetworkPeers(t, f, f.tokenA, f.netA, f.peerA1)
				assertMachineCount(t, f, f.netA, 1)
			},
			wantCode: codes.OK,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newScopedFixture(t)
			err := tc.call(t, f)
			if status.Code(err) != tc.wantCode {
				t.Fatalf("RPC returned %v (code %s), want code %s", err, status.Code(err), tc.wantCode)
			}
			tc.check(t, f)
		})
	}
}

// TestServer_Register_PeerIDAlreadyRegisteredElsewhere verifies that a
// peer ID (the Ed25519 public key) already registered in one network cannot
// be registered into another network: the attempt is rejected with
// codes.AlreadyExists and the existing registration, network membership and
// endpoint are left untouched.
func TestServer_Register_PeerIDAlreadyRegisteredElsewhere(t *testing.T) {
	f := newScopedFixture(t)

	before, err := f.reg.GetPeer(f.peerA1)
	if err != nil {
		t.Fatalf("GetPeer before: %v", err)
	}

	// Account B registers account A's Ed25519 public key into B's own
	// network while A's watcher is connected.
	events := f.watchDuring(t, f.tokenB, f.netB, f.peerB1, func() {
		_, err = f.srv.Register(context.Background(), &coordv1.RegisterRequest{
			NetworkId:     f.netB,
			Token:         f.tokenB,
			Name:          "b-clone",
			Ed25519Public: scopedKeyB64("peer-a1-ed25519"),
			X25519Public:  scopedKeyB64("b-clone-x25519"),
			Endpoint:      "9.9.9.9:9999",
		})
	})
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("Register: got %v, want code %s", err, codes.AlreadyExists)
	}

	// No JOIN event for the clone reached B's network watchers.
	for _, ev := range events {
		if ev.Type == coordv1.EventType_JOIN && ev.Peer != nil && ev.Peer.Id == f.peerA1 {
			t.Errorf("JOIN event published for rejected registration: %+v", ev.Peer)
		}
	}

	// A's peer record is unchanged: still in A's network with its VPN
	// address, name and X25519 key.
	after, err := f.reg.GetPeer(f.peerA1)
	if err != nil {
		t.Fatalf("GetPeer after: %v", err)
	}
	if after.NetworkID != f.netA {
		t.Errorf("peer moved networks: got %q, want %q", after.NetworkID, f.netA)
	}
	if after.VPNAddr != before.VPNAddr {
		t.Errorf("VPN address changed: got %q, want %q", after.VPNAddr, before.VPNAddr)
	}
	if after.Name != before.Name {
		t.Errorf("name changed: got %q, want %q", after.Name, before.Name)
	}
	if after.X25519Public != before.X25519Public {
		t.Errorf("X25519 key changed: got %q, want %q", after.X25519Public, before.X25519Public)
	}

	// Network membership is unchanged on both sides...
	assertNetworkPeers(t, f, f.tokenA, f.netA, f.peerA1, f.peerA2)
	assertMachineCount(t, f, f.netA, 2)
	assertNetworkPeers(t, f, f.tokenB, f.netB, f.peerB1)
	assertMachineCount(t, f, f.netB, 1)

	// ...and A's peer still serves its original advertised endpoint.
	resp, err := f.srv.ListPeers(context.Background(), &coordv1.ListPeersRequest{NetworkId: f.netA, Token: f.tokenA})
	if err != nil {
		t.Fatalf("ListPeers: %v", err)
	}
	for _, p := range resp.Peers {
		if p.Id == f.peerA1 && p.Endpoint != "1.1.1.1:1111" {
			t.Errorf("endpoint changed: got %q, want 1.1.1.1:1111", p.Endpoint)
		}
	}
}

// TestServer_Register_X25519MismatchOnReregistration verifies that a
// same-network re-registration presenting a different X25519 public key
// than the stored one is rejected with codes.AlreadyExists and the stored
// key is kept. Re-registering with the same key stays idempotent.
func TestServer_Register_X25519MismatchOnReregistration(t *testing.T) {
	f := newScopedFixture(t)

	_, err := f.srv.Register(context.Background(), &coordv1.RegisterRequest{
		NetworkId:     f.netA,
		Token:         f.tokenA,
		Name:          "peer-a1-rotated",
		Ed25519Public: scopedKeyB64("peer-a1-ed25519"),
		X25519Public:  scopedKeyB64("peer-a1-rotated-x25519"),
	})
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("Register with rotated X25519: got %v, want code %s", err, codes.AlreadyExists)
	}

	rec, err := f.reg.GetPeer(f.peerA1)
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if rec.X25519Public != scopedKeyB64("peer-a1-x25519") {
		t.Errorf("stored X25519 key: got %q, want the original", rec.X25519Public)
	}
	if rec.Name == "peer-a1-rotated" {
		t.Errorf("rejected re-registration still updated the name: %q", rec.Name)
	}

	// Re-registering with the same keys stays idempotent and keeps working.
	if _, err := f.srv.Register(context.Background(), &coordv1.RegisterRequest{
		NetworkId:     f.netA,
		Token:         f.tokenA,
		Name:          "peer-a1-renamed",
		Ed25519Public: scopedKeyB64("peer-a1-ed25519"),
		X25519Public:  scopedKeyB64("peer-a1-x25519"),
	}); err != nil {
		t.Fatalf("idempotent re-registration: %v", err)
	}
	rec, err = f.reg.GetPeer(f.peerA1)
	if err != nil {
		t.Fatalf("GetPeer after re-register: %v", err)
	}
	if rec.Name != "peer-a1-renamed" {
		t.Errorf("idempotent re-registration did not update the name: got %q", rec.Name)
	}
}
