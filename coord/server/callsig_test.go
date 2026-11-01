// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/veldmesh/veld/coord/ce"
	coordcore "github.com/veldmesh/veld/coord/core"
	coordv1 "github.com/veldmesh/veld/gen/veld/coord/v1"
	"github.com/veldmesh/veld/internal/crypto"
)

// registerPeer registers a new peer with a fresh identity in test-net.
func registerPeer(t *testing.T, srv *Server, name string) (*crypto.Identity, *coordv1.RegisterResponse) {
	t.Helper()
	id := newRegisterIdentity(t)
	req := newRegisterRequest(id, "test-net", "test-token", name, "", nil)
	signRegisterReq(t, id, req)
	return id, mustRegister(t, srv, req)
}

func assertPeerCount(t *testing.T, srv *Server, want int) []*coordv1.Peer {
	t.Helper()
	resp, err := srv.ListPeers(context.Background(), &coordv1.ListPeersRequest{NetworkId: "test-net", Token: "test-token"})
	if err != nil {
		t.Fatalf("ListPeers: %v", err)
	}
	if len(resp.Peers) != want {
		t.Fatalf("ListPeers: got %d peers, want %d", len(resp.Peers), want)
	}
	return resp.Peers
}

func TestServer_Leave_WrongOrMissingSignature_IsRejected(t *testing.T) {
	srv, reg := testServer(t)
	defer reg.Close()

	_, victim := registerPeer(t, srv, "victim")
	attacker, _ := registerPeer(t, srv, "attacker")

	// Signed by another peer of the same account (shared token).
	_, err := srv.Leave(context.Background(), signLeave(t, attacker, &coordv1.LeaveRequest{Token: "test-token", PeerId: victim.PeerId}))
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("Leave signed by another peer: got %v, want Unauthenticated", err)
	}
	// Unsigned.
	_, err = srv.Leave(context.Background(), &coordv1.LeaveRequest{Token: "test-token", PeerId: victim.PeerId})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unsigned Leave: got %v, want Unauthenticated", err)
	}
	assertPeerCount(t, srv, 2)
}

func TestServer_Watch_PeerIDRequiresSignature(t *testing.T) {
	srv, reg := testServer(t)
	defer reg.Close()

	idA, a := registerPeer(t, srv, "peer-a")
	idB, _ := registerPeer(t, srv, "peer-b")

	watch := func(req *coordv1.WatchRequest) error {
		stream := newFakeWatchStream()
		done := make(chan error, 1)
		go func() { done <- srv.Watch(req, stream) }()
		time.Sleep(100 * time.Millisecond)
		stream.cancel()
		select {
		case err := <-done:
			return err
		case <-time.After(2 * time.Second):
			t.Fatal("Watch did not finish")
			return nil
		}
	}

	if err := watch(&coordv1.WatchRequest{NetworkId: "test-net", Token: "test-token", PeerId: a.PeerId}); status.Code(err) != codes.Unauthenticated {
		t.Errorf("unsigned Watch naming a peer: got %v, want Unauthenticated", err)
	}
	if err := watch(signWatch(t, idB, &coordv1.WatchRequest{NetworkId: "test-net", Token: "test-token", PeerId: a.PeerId})); status.Code(err) != codes.Unauthenticated {
		t.Errorf("Watch signed by another peer: got %v, want Unauthenticated", err)
	}
	if srv.IsConnected(a.PeerId) {
		t.Error("rejected Watch marked the peer connected")
	}
	// A signature bound to another network does not carry over.
	wrongNet := &coordv1.WatchRequest{NetworkId: "test-net", Token: "test-token", PeerId: a.PeerId}
	wrongNet.TimestampUnix, wrongNet.Signature = signedCall(idA, func(ts int64) crypto.CallClaims {
		return crypto.WatchClaims(a.PeerId, "other-net", ts)
	})
	if err := watch(wrongNet); status.Code(err) != codes.Unauthenticated {
		t.Errorf("Watch signed for another network: got %v, want Unauthenticated", err)
	}

	// Properly signed and anonymous watches work.
	if err := watch(signWatch(t, idA, &coordv1.WatchRequest{NetworkId: "test-net", Token: "test-token", PeerId: a.PeerId})); err != nil {
		t.Errorf("signed Watch: %v", err)
	}
	if err := watch(&coordv1.WatchRequest{NetworkId: "test-net", Token: "test-token"}); err != nil {
		t.Errorf("Watch without PeerId needs no signature: %v", err)
	}
}

func TestServer_SendSignal_SpoofedFrom_IsRejected(t *testing.T) {
	srv, reg := testServer(t)
	defer reg.Close()

	_, a := registerPeer(t, srv, "peer-a")
	idB, b := registerPeer(t, srv, "peer-b")
	idC, _ := registerPeer(t, srv, "peer-c")

	// C claims to be B while signing with its own key.
	_, err := srv.SendSignal(context.Background(), signSendSignal(t, idC, &coordv1.SendSignalRequest{
		Token: "test-token", FromPeerId: b.PeerId, ToPeerId: a.PeerId, Payload: []byte("spoofed"),
	}))
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("SendSignal with spoofed from: got %v, want Unauthenticated", err)
	}
	// Unsigned.
	_, err = srv.SendSignal(context.Background(), &coordv1.SendSignalRequest{
		Token: "test-token", FromPeerId: b.PeerId, ToPeerId: a.PeerId, Payload: []byte("unsigned"),
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unsigned SendSignal: got %v, want Unauthenticated", err)
	}
	// A signature does not cover a different payload.
	req := signSendSignal(t, idB, &coordv1.SendSignalRequest{
		Token: "test-token", FromPeerId: b.PeerId, ToPeerId: a.PeerId, Payload: []byte("original"),
	})
	req.Payload = []byte("tampered")
	if _, err = srv.SendSignal(context.Background(), req); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("SendSignal with tampered payload: got %v, want Unauthenticated", err)
	}

	srv.bus.mu.RLock()
	defer srv.bus.mu.RUnlock()
	if len(srv.bus.pending) != 0 {
		t.Fatalf("rejected signal was held: %v", srv.bus.pending)
	}
}

func TestServer_CallSignature_ReplayIsRejected(t *testing.T) {
	srv, reg := testServer(t)
	defer reg.Close()

	id, resp := registerPeer(t, srv, "peer-a")

	leave := signLeave(t, id, &coordv1.LeaveRequest{Token: "test-token", PeerId: resp.PeerId})
	if _, err := srv.Leave(context.Background(), leave); err != nil {
		t.Fatalf("Leave: %v", err)
	}

	// The peer registers again (a later timestamp: Register signatures are
	// single-use too); a captured copy of the old Leave must not remove it.
	reReg := newRegisterRequest(id, "test-net", "test-token", "peer-a", "", nil)
	reReg.TimestampUnix = time.Now().Unix() + 1
	reReg.Signature = crypto.SignRegister(id.Ed25519Private, registerClaimsFor(reReg))
	mustRegister(t, srv, reReg)

	_, err := srv.Leave(context.Background(), leave)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("replayed Leave: got %v, want Unauthenticated", err)
	}
	assertPeerCount(t, srv, 1)

	// A fresh signature still works.
	if _, err := srv.Leave(context.Background(), signLeave(t, id, &coordv1.LeaveRequest{Token: "test-token", PeerId: resp.PeerId})); err != nil {
		t.Fatalf("fresh Leave: %v", err)
	}
	assertPeerCount(t, srv, 0)
}

func TestServer_Register_ReplayIsRejected(t *testing.T) {
	srv, reg := testServer(t)
	defer reg.Close()

	id := newRegisterIdentity(t)
	req := newRegisterRequest(id, "test-net", "test-token", "peer-a", "", nil)
	signRegisterReq(t, id, req)
	mustRegister(t, srv, req)

	if _, err := srv.Register(context.Background(), req); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("replayed Register: got %v, want Unauthenticated", err)
	}
	assertPeerCount(t, srv, 1)
}

// newSmallNetServer builds a server whose test-net has the given CIDR.
func newSmallNetServer(t *testing.T, cidr string) (*Server, *Registry) {
	t.Helper()
	reg, err := NewRegistry(t.TempDir() + "/small.db")
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	net := coordcore.Network{ID: "test-net", CIDR: netip.MustParsePrefix(cidr), Name: "Small"}
	if err := reg.CreateNetwork(net, "acc1"); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}
	accounts := ce.NewTokenAccountStore(map[string]coordcore.Account{
		"test-token": {ID: "acc1", Tier: coordcore.TierFree},
	})
	srv := New(reg, NewBus(), ce.NewFreeEnforcer(), accounts, ce.NewNoopAuditLogger(), ce.NewRejectSubnetPolicy(), ce.NewNoopHooks())
	return srv, reg
}

func TestServer_Register_ReusesFreedAddressWhenExhausted(t *testing.T) {
	// A /30 has 4 addresses: network (.0) and broadcast (.3) are never
	// assigned, leaving .1 and .2 (well under the free-tier machine limit,
	// so exhaustion is the address space, not the limit).
	srv, reg := newSmallNetServer(t, "10.77.0.0/30")
	defer reg.Close()

	var ids []*crypto.Identity
	var resps []*coordv1.RegisterResponse
	seen := map[string]bool{}
	for i := 0; i < 2; i++ {
		id, resp := registerPeer(t, srv, "")
		ids = append(ids, id)
		resps = append(resps, resp)
		if seen[resp.VpnAddr] {
			t.Fatalf("address %s assigned twice", resp.VpnAddr)
		}
		seen[resp.VpnAddr] = true
		if strings.HasPrefix(resp.VpnAddr, "10.77.0.3") {
			t.Fatalf("reserved address assigned: %s", resp.VpnAddr)
		}
	}

	// Exhausted.
	idX := newRegisterIdentity(t)
	reqX := newRegisterRequest(idX, "test-net", "test-token", "", "", nil)
	signRegisterReq(t, idX, reqX)
	_, err := srv.Register(context.Background(), reqX)
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("Register into a full network: code = %v, want %v (err %v)", status.Code(err), codes.ResourceExhausted, err)
	}
	if got := status.Convert(err).Message(); got != "no free addresses in network" {
		t.Fatalf("Register into a full network: message = %q, want %q", got, "no free addresses in network")
	}

	// One peer leaves; a new peer gets its address.
	freed := resps[0]
	if _, err := srv.Leave(context.Background(), signLeave(t, ids[0], &coordv1.LeaveRequest{Token: "test-token", PeerId: freed.PeerId})); err != nil {
		t.Fatalf("Leave: %v", err)
	}
	reqX.TimestampUnix++
	reqX.Signature = crypto.SignRegister(idX.Ed25519Private, registerClaimsFor(reqX))
	got := mustRegister(t, srv, reqX)
	if got.VpnAddr != freed.VpnAddr {
		t.Errorf("new peer address: got %s, want freed %s", got.VpnAddr, freed.VpnAddr)
	}
}

func TestServer_Register_NameValidation(t *testing.T) {
	srv, reg := testServer(t)
	defer reg.Close()

	for _, name := range []string{"bad name", "-x", "x-", "under_score", "dot.ted", strings.Repeat("a", 64)} {
		id := newRegisterIdentity(t)
		req := newRegisterRequest(id, "test-net", "test-token", name, "", nil)
		signRegisterReq(t, id, req)
		if _, err := srv.Register(context.Background(), req); status.Code(err) != codes.InvalidArgument {
			t.Errorf("Register name %q: got %v, want InvalidArgument", name, err)
		}
	}
	for _, name := range []string{"", "a", "Host-1", strings.Repeat("a", 63)} {
		id := newRegisterIdentity(t)
		req := newRegisterRequest(id, "test-net", "test-token", name, "", nil)
		signRegisterReq(t, id, req)
		if _, err := srv.Register(context.Background(), req); err != nil {
			t.Errorf("Register name %q: %v", name, err)
		}
	}
}

func TestServer_Register_NameCollision_StoredEmpty(t *testing.T) {
	srv, reg := testServer(t)
	defer reg.Close()

	_, first := registerPeer(t, srv, "fileserver")
	_, second := registerPeer(t, srv, "FileServer")

	names := map[string]string{}
	for _, p := range assertPeerCount(t, srv, 2) {
		names[p.Id] = p.Name
	}
	if names[first.PeerId] != "fileserver" {
		t.Errorf("first peer name: got %q, want %q", names[first.PeerId], "fileserver")
	}
	if names[second.PeerId] != "" {
		t.Errorf("colliding peer name: got %q, want empty", names[second.PeerId])
	}
}

func TestServer_Register_EndpointValidation(t *testing.T) {
	srv, reg := testServer(t)
	defer reg.Close()

	for _, ep := range []string{"not-an-endpoint", "1.2.3.4:0", "1.2.3.4", "0.0.0.0:51820", "224.0.0.1:51820"} {
		id := newRegisterIdentity(t)
		req := newRegisterRequest(id, "test-net", "test-token", "", ep, nil)
		signRegisterReq(t, id, req)
		if _, err := srv.Register(context.Background(), req); status.Code(err) != codes.InvalidArgument {
			t.Errorf("Register endpoint %q: got %v, want InvalidArgument", ep, err)
		}
	}
	for _, ep := range []string{"", "1.2.3.4:51820", "[2001:db8::1]:51820"} {
		id := newRegisterIdentity(t)
		req := newRegisterRequest(id, "test-net", "test-token", "", ep, nil)
		signRegisterReq(t, id, req)
		if _, err := srv.Register(context.Background(), req); err != nil {
			t.Errorf("Register endpoint %q: %v", ep, err)
		}
	}
}
