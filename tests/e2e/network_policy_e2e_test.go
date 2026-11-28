// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package e2e_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/veldmesh/veld/coord/ce"
	coordcore "github.com/veldmesh/veld/coord/core"
	"github.com/veldmesh/veld/coord/server"
	coordv1 "github.com/veldmesh/veld/gen/veld/coord/v1"
	"github.com/veldmesh/veld/internal/acl"
	"github.com/veldmesh/veld/internal/crypto"
)

func signPushNetworkPolicy(t *testing.T, id *crypto.Identity, req *coordv1.PushNetworkPolicyRequest) *coordv1.PushNetworkPolicyRequest {
	t.Helper()
	req.TimestampUnix = time.Now().Unix()
	req.Signature = crypto.SignCall(id.Ed25519Private,
		crypto.PushNetworkPolicyClaims(req.PeerId, req.NetworkId, req.Envelope, req.TimestampUnix))
	return req
}

func signWatchReq(t *testing.T, id *crypto.Identity, req *coordv1.WatchRequest) *coordv1.WatchRequest {
	t.Helper()
	req.TimestampUnix = time.Now().Unix()
	req.Signature = crypto.SignCall(id.Ed25519Private,
		crypto.WatchClaims(req.PeerId, req.NetworkId, req.TimestampUnix))
	return req
}

func signPolicyEnvelope(t *testing.T, version int, adminPriv ed25519.PrivateKey) []byte {
	t.Helper()
	policyTOML := fmt.Sprintf(`
version = %d
default = "deny"
[peers]
alice = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
bob   = "ed25519:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
[[rule]]
from = "alice"
to   = "bob"
ports = ["tcp/22"]
`, version)
	envelope, err := acl.SignPolicy(policyTOML, adminPriv)
	if err != nil {
		t.Fatalf("SignPolicy: %v", err)
	}
	return envelope
}

func newCoordServerWithNetwork(t *testing.T, adminKeys []string) (*grpc.Server, *server.Registry, *server.Bus, net.Listener) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}

	grpcServer := grpc.NewServer()

	tmpDir := t.TempDir()
	reg, err := server.NewRegistry(tmpDir + "/test.db")
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	cidr := netip.MustParsePrefix("10.99.0.0/24")
	testNet := coordcore.Network{ID: "test-net", CIDR: cidr, Name: "Test Network"}
	if err := reg.CreateNetwork(testNet, "acc1"); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}

	if err := reg.SetNetworkAdminKeys("test-net", "acc1", adminKeys); err != nil {
		t.Fatalf("SetNetworkAdminKeys: %v", err)
	}

	bus := server.NewBus()
	enforcer := ce.NewFreeEnforcer()
	accounts := ce.NewTokenAccountStore(map[string]coordcore.Account{
		"test-token": {ID: "acc1", Tier: coordcore.TierFree},
	})
	audit := ce.NewNoopAuditLogger()
	subnet := ce.NewRejectSubnetPolicy()
	hooks := ce.NewNoopHooks()

	coordServer := server.New(reg, bus, enforcer, accounts, audit, subnet, hooks)
	coordv1.RegisterCoordServer(grpcServer, coordServer)

	go grpcServer.Serve(listener)

	return grpcServer, reg, bus, listener
}

func connectClient(t *testing.T, listener net.Listener) (coordv1.CoordClient, *grpc.ClientConn) {
	t.Helper()
	conn, err := grpc.NewClient(
		listener.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	client := coordv1.NewCoordClient(conn)
	return client, conn
}

func registerPeer(t *testing.T, client coordv1.CoordClient, id *crypto.Identity, peerName string) *coordv1.RegisterResponse {
	t.Helper()
	resp, err := client.Register(context.Background(),
		signedRegisterReq(t, id, "test-net", "test-token", peerName, "", nil))
	if err != nil {
		t.Fatalf("Register %s: %v", peerName, err)
	}
	return resp
}

// TestNetworkPolicy_PushAndWatch_DeliversToTwoPeers verifies that pushing a policy
// delivers it to multiple watching peers, including one connected before the push.
func TestNetworkPolicy_PushAndWatch_DeliversToTwoPeers(t *testing.T) {
	adminPriv, adminPub := generateAdminKeyPair(t)
	adminKeyB64 := base64.StdEncoding.EncodeToString(adminPub[:])

	grpcServer, _, _, listener := newCoordServerWithNetwork(t, []string{adminKeyB64})
	defer grpcServer.Stop()
	defer listener.Close()

	client, conn := connectClient(t, listener)
	defer conn.Close()

	// Register peer1 (will connect Watch BEFORE push)
	id1, _ := crypto.Generate()
	regResp1 := registerPeer(t, client, id1, "peer1")

	// Start Watch for peer1
	ctx1, cancel1 := context.WithCancel(context.Background())
	watchReq1 := signWatchReq(t, id1, &coordv1.WatchRequest{
		NetworkId: "test-net",
		Token:     "test-token",
		PeerId:    regResp1.PeerId,
	})
	watchClient1, err := client.Watch(ctx1, watchReq1)
	if err != nil {
		t.Fatalf("Watch peer1: %v", err)
	}

	// Consume initial snapshot: NETWORK_POLICY (if exists) + JOIN events
	// Since there's no policy yet and no other peers, we might get nothing or just NETWORK_POLICY (empty)
	// Just try to receive one event with a short timeout
	initialDone := make(chan struct{}, 1)
	initialErr := make(chan error, 1)
	go func() {
		ev, err := watchClient1.Recv()
		if err != nil {
			initialErr <- err
			return
		}
		if ev.Type == coordv1.EventType_NETWORK_POLICY {
			// Empty snapshot - this is expected
			if len(ev.NetworkPolicy.Envelope) != 0 {
				t.Logf("initial NETWORK_POLICY has %d bytes", len(ev.NetworkPolicy.Envelope))
			}
		}
		// If JOIN, also fine - we're ready
		initialDone <- struct{}{}
	}()

	select {
	case <-initialDone:
		// Got initial event, ready for push
	case err := <-initialErr:
		t.Fatalf("Recv peer1 initial: %v", err)
	case <-time.After(5 * time.Second):
		// No initial event received, but that's OK - the stream is ready
		t.Log("no initial event, proceeding to push")
	}

	// Register peer2 (will connect Watch AFTER push)
	id2, _ := crypto.Generate()
	regResp2 := registerPeer(t, client, id2, "peer2")

	// Push policy
	envelope := signPolicyEnvelope(t, 1, adminPriv)
	pushReq := &coordv1.PushNetworkPolicyRequest{
		NetworkId: "test-net",
		Token:     "test-token",
		PeerId:    regResp1.PeerId,
		Envelope:  envelope,
	}
	signPushNetworkPolicy(t, id1, pushReq)

	_, err = client.PushNetworkPolicy(context.Background(), pushReq)
	if err != nil {
		t.Fatalf("PushNetworkPolicy: %v", err)
	}

	// peer1 should receive NETWORK_POLICY event with timeout
	evCh := make(chan *coordv1.PeerEvent, 1)
	errCh := make(chan error, 1)
	go func() {
		ev, err := watchClient1.Recv()
		if err != nil {
			errCh <- err
			return
		}
		evCh <- ev
	}()

	select {
	case ev := <-evCh:
		if ev.Type != coordv1.EventType_NETWORK_POLICY {
			t.Errorf("peer1 event type: got %v, want NETWORK_POLICY", ev.Type)
		}
		if len(ev.NetworkPolicy.Envelope) == 0 {
			t.Error("peer1 envelope is empty")
		}
	case err := <-errCh:
		t.Fatalf("Recv peer1 after push: %v", err)
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for NETWORK_POLICY event on peer1")
	}

	// Now start Watch for peer2 (after push)
	ctx2, cancel2 := context.WithCancel(context.Background())
	watchReq2 := signWatchReq(t, id2, &coordv1.WatchRequest{
		NetworkId: "test-net",
		Token:     "test-token",
		PeerId:    regResp2.PeerId,
	})
	watchClient2, err := client.Watch(ctx2, watchReq2)
	if err != nil {
		t.Fatalf("Watch peer2: %v", err)
	}

	// peer2 should receive initial snapshot with the policy
	for {
		ev, err := watchClient2.Recv()
		if err != nil {
			t.Fatalf("Recv peer2: %v", err)
		}
		if ev.Type == coordv1.EventType_NETWORK_POLICY {
			if len(ev.NetworkPolicy.Envelope) == 0 {
				t.Error("peer2 initial snapshot envelope is empty")
			}
			break
		}
		// Consume JOIN events
	}

	cancel1()
	cancel2()
}

// TestNetworkPolicy_MaliciousCoord_RefusedByPeers simulates a malicious coordinator
// sending forged/invalid/lower-version envelopes and verifies peers refuse them.
func TestNetworkPolicy_MaliciousCoord_RefusedByPeers(t *testing.T) {
	adminPriv, adminPub := generateAdminKeyPair(t)
	adminKeyB64 := base64.StdEncoding.EncodeToString(adminPub[:])

	grpcServer, reg, _, listener := newCoordServerWithNetwork(t, []string{adminKeyB64})
	defer grpcServer.Stop()
	defer listener.Close()
	defer reg.Close()

	client, conn := connectClient(t, listener)
	defer conn.Close()

	// Register peer1
	id1, _ := crypto.Generate()
	regResp1 := registerPeer(t, client, id1, "peer1")

	// Push valid policy v2 first (so v1 is lower)
	envelopeV2 := signPolicyEnvelope(t, 2, adminPriv)
	pushReq := &coordv1.PushNetworkPolicyRequest{
		NetworkId: "test-net",
		Token:     "test-token",
		PeerId:    regResp1.PeerId,
		Envelope:  envelopeV2,
	}
	signPushNetworkPolicy(t, id1, pushReq)
	_, err := client.PushNetworkPolicy(context.Background(), pushReq)
	if err != nil {
		t.Fatalf("PushNetworkPolicy v2: %v", err)
	}

	// Start Watch
	ctx, cancel := context.WithCancel(context.Background())
	watchReq := signWatchReq(t, id1, &coordv1.WatchRequest{
		NetworkId: "test-net",
		Token:     "test-token",
		PeerId:    regResp1.PeerId,
	})
	watchClient, err := client.Watch(ctx, watchReq)
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}

	// Consume initial events
	for {
		ev, err := watchClient.Recv()
		if err != nil {
			t.Fatalf("Recv initial: %v", err)
		}
		if ev.Type == coordv1.EventType_NETWORK_POLICY && len(ev.NetworkPolicy.Envelope) > 0 {
			break
		}
	}

	// Test peer's StoreEnvelope with malicious envelopes
	// Create a fresh loader without pre-loading from file
	tmpDir := t.TempDir()
	identityPath := tmpDir + "/identity.json"
	_ = os.WriteFile(identityPath, []byte(`{"ed25519":"","x25519":""}`), 0o600)

	netPolicyFile := tmpDir + "/policy.signed"
	netPolicySwap := &acl.PolicySwap{}
	adminKeys := map[[32]byte]struct{}{}
	adminKeys[adminPub] = struct{}{}

	// Don't write to file - just use the loader with empty file
	loader := acl.NewNetworkPolicyLoader(netPolicyFile, identityPath, adminKeys, netPolicySwap)
	err = loader.Load()
	if err != nil {
		t.Fatalf("loader.Load: %v", err)
	}

	// Push v2 directly via StoreEnvelope to establish current version
	stored, err := loader.StoreEnvelope(envelopeV2)
	if err != nil {
		t.Fatalf("StoreEnvelope v2: %v", err)
	}
	if !stored {
		t.Error("expected stored=true for v2")
	}

	// Test: lower version (v1) should be refused
	envelopeV1 := signPolicyEnvelope(t, 1, adminPriv)
	stored, err = loader.StoreEnvelope(envelopeV1)
	if err == nil {
		t.Fatal("expected error for lower version")
	}
	if stored {
		t.Error("expected stored=false for lower version")
	}

	// Test: same version (v2) should be refused
	envelopeV2b := signPolicyEnvelope(t, 2, adminPriv)
	stored, err = loader.StoreEnvelope(envelopeV2b)
	if err == nil {
		t.Fatal("expected error for same version")
	}
	if stored {
		t.Error("expected stored=false for same version")
	}

	// Test: unpinned signer should be refused
	unpinnedPriv, _ := generateAdminKeyPair(t)
	unpinnedEnvelope := signPolicyEnvelope(t, 3, unpinnedPriv)
	stored, err = loader.StoreEnvelope(unpinnedEnvelope)
	if err == nil {
		t.Fatal("expected error for unpinned signer")
	}
	if stored {
		t.Error("expected stored=false for unpinned signer")
	}

	// Test: invalid signature should be refused
	invalidEnvelope := signPolicyEnvelope(t, 3, adminPriv)
	// Corrupt signature
	invalidEnvelope[len(invalidEnvelope)-1] ^= 0xFF
	stored, err = loader.StoreEnvelope(invalidEnvelope)
	if err == nil {
		t.Fatal("expected error for invalid signature")
	}
	if stored {
		t.Error("expected stored=false for invalid signature")
	}

	// Test: higher version (v3) should be accepted
	envelopeV3 := signPolicyEnvelope(t, 3, adminPriv)
	stored, err = loader.StoreEnvelope(envelopeV3)
	if err != nil {
		t.Fatalf("StoreEnvelope v3: %v", err)
	}
	if !stored {
		t.Error("expected stored=true for higher version")
	}

	cancel()
}

// TestNetworkPolicy_CoordRestart_KeepsBlob verifies that restarting the coordinator
// preserves the stored policy and serves it on Register and Watch.
func TestNetworkPolicy_CoordRestart_KeepsBlob(t *testing.T) {
	adminPriv, adminPub := generateAdminKeyPair(t)
	adminKeyB64 := base64.StdEncoding.EncodeToString(adminPub[:])

	tmpDir := t.TempDir()
	dbPath := tmpDir + "/test.db"

	// First coord instance
	reg, err := server.NewRegistry(dbPath)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	cidr := netip.MustParsePrefix("10.99.0.0/24")
	testNet := coordcore.Network{ID: "test-net", CIDR: cidr, Name: "Test Network"}
	if err := reg.CreateNetwork(testNet, "acc1"); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}
	if err := reg.SetNetworkAdminKeys("test-net", "acc1", []string{adminKeyB64}); err != nil {
		t.Fatalf("SetNetworkAdminKeys: %v", err)
	}

	bus := server.NewBus()
	enforcer := ce.NewFreeEnforcer()
	accounts := ce.NewTokenAccountStore(map[string]coordcore.Account{
		"test-token": {ID: "acc1", Tier: coordcore.TierFree},
	})
	audit := ce.NewNoopAuditLogger()
	subnet := ce.NewRejectSubnetPolicy()
	hooks := ce.NewNoopHooks()

	coordServer1 := server.New(reg, bus, enforcer, accounts, audit, subnet, hooks)

	listener1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	grpcServer1 := grpc.NewServer()
	coordv1.RegisterCoordServer(grpcServer1, coordServer1)
	go grpcServer1.Serve(listener1)

	client1, conn1 := connectClient(t, listener1)
	defer conn1.Close()
	defer grpcServer1.Stop()

	// Register peer and push policy
	id1, _ := crypto.Generate()
	regResp1 := registerPeer(t, client1, id1, "peer1")

	envelope := signPolicyEnvelope(t, 1, adminPriv)
	pushReq := &coordv1.PushNetworkPolicyRequest{
		NetworkId: "test-net",
		Token:     "test-token",
		PeerId:    regResp1.PeerId,
		Envelope:  envelope,
	}
	signPushNetworkPolicy(t, id1, pushReq)
	_, err = client1.PushNetworkPolicy(context.Background(), pushReq)
	if err != nil {
		t.Fatalf("PushNetworkPolicy: %v", err)
	}

	// Verify policy is stored
	storedEnv, storedVer, err := reg.GetNetworkPolicy("test-net")
	if err != nil {
		t.Fatalf("GetNetworkPolicy: %v", err)
	}
	if storedVer != 1 {
		t.Errorf("stored version: got %d, want 1", storedVer)
	}
	if len(storedEnv) == 0 {
		t.Error("stored envelope is empty")
	}

	// Shut down first coord
	grpcServer1.Stop()
	listener1.Close()
	reg.Close()

	// Start second coord on same DB
	reg2, err := server.NewRegistry(dbPath)
	if err != nil {
		t.Fatalf("NewRegistry (restart): %v", err)
	}
	defer reg2.Close()

	bus2 := server.NewBus()
	coordServer2 := server.New(reg2, bus2, enforcer, accounts, audit, subnet, hooks)

	listener2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen (restart): %v", err)
	}
	defer listener2.Close()

	grpcServer2 := grpc.NewServer()
	coordv1.RegisterCoordServer(grpcServer2, coordServer2)
	go grpcServer2.Serve(listener2)
	defer grpcServer2.Stop()

	client2, conn2 := connectClient(t, listener2)
	defer conn2.Close()

	// Register a new peer and verify it receives the policy on Register
	id2, _ := crypto.Generate()
	regResp2, err := client2.Register(context.Background(),
		signedRegisterReq(t, id2, "test-net", "test-token", "peer2", "", nil))
	if err != nil {
		t.Fatalf("Register after restart: %v", err)
	}

	if len(regResp2.NetworkPolicy) == 0 {
		t.Error("Register response after restart should include policy envelope")
	}

	// Start Watch and verify it receives the policy in initial snapshot
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	watchReq := signWatchReq(t, id2, &coordv1.WatchRequest{
		NetworkId: "test-net",
		Token:     "test-token",
		PeerId:    regResp2.PeerId,
	})
	watchClient, err := client2.Watch(ctx, watchReq)
	if err != nil {
		t.Fatalf("Watch after restart: %v", err)
	}

	for {
		ev, err := watchClient.Recv()
		if err != nil {
			t.Fatalf("Recv after restart: %v", err)
		}
		if ev.Type == coordv1.EventType_NETWORK_POLICY {
			if len(ev.NetworkPolicy.Envelope) == 0 {
				t.Error("Watch snapshot after restart should include policy envelope")
			}
			break
		}
	}

	// Also verify another new peer gets the policy
	id3, _ := crypto.Generate()
	regResp3, err := client2.Register(context.Background(),
		signedRegisterReq(t, id3, "test-net", "test-token", "peer3", "", nil))
	if err != nil {
		t.Fatalf("Register peer3: %v", err)
	}

	if len(regResp3.NetworkPolicy) == 0 {
		t.Error("Register response for peer3 should include policy envelope")
	}
}

func generateAdminKeyPair(t *testing.T) (ed25519.PrivateKey, [32]byte) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Generate admin key: %v", err)
	}
	var pub [32]byte
	copy(pub[:], priv.Public().(ed25519.PublicKey))
	return priv, pub
}
