// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/veldmesh/veld/coord/ce"
	coordcore "github.com/veldmesh/veld/coord/core"
	coordv1 "github.com/veldmesh/veld/gen/veld/coord/v1"
	"github.com/veldmesh/veld/internal/acl"
	"github.com/veldmesh/veld/internal/crypto"
)

// testServerWithAdminKeys creates a server with a network that has admin keys pinned.
func testServerWithAdminKeys(t *testing.T, adminKeys []string) (*Server, *Registry, *crypto.Identity, string) {
	t.Helper()
	tmpDir := t.TempDir()
	reg, err := NewRegistry(tmpDir + "/test.db")
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	cidr := netip.MustParsePrefix("10.99.0.0/24")
	net := coordcore.Network{ID: "test-net", CIDR: cidr, Name: "Test Network"}
	if err := reg.CreateNetwork(net, "acc1"); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}

	// Set admin keys
	if err := reg.SetNetworkAdminKeys("test-net", "acc1", adminKeys); err != nil {
		t.Fatalf("SetNetworkAdminKeys: %v", err)
	}

	bus := NewBus()
	enforcer := ce.NewFreeEnforcer()
	accounts := ce.NewTokenAccountStore(map[string]coordcore.Account{
		"test-token": {ID: "acc1", Tier: coordcore.TierFree},
	})
	audit := ce.NewNoopAuditLogger()
	subnet := ce.NewRejectSubnetPolicy()
	hooks := ce.NewNoopHooks()

	srv := New(reg, bus, enforcer, accounts, audit, subnet, hooks)

	// Register a peer to use for PushNetworkPolicy
	id := newRegisterIdentity(t)
	req := newRegisterRequest(id, "test-net", "test-token", "peer1", "", nil)
	signRegisterReq(t, id, req)
	resp, err := srv.Register(context.Background(), req)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	return srv, reg, id, resp.PeerId
}

// generateAdminKeyPair creates a new Ed25519 key pair for testing admin keys.
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

// signPolicyEnvelope creates a signed network policy envelope with the given version and admin key.
func signPolicyEnvelope(t *testing.T, version int, adminPriv ed25519.PrivateKey) []byte {
	t.Helper()
	policyTOML := fmt.Sprintf(`version = %d
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

// signPushNetworkPolicy stamps and signs req (acting as req.PeerId) with id.
func signPushNetworkPolicy(t *testing.T, id *crypto.Identity, req *coordv1.PushNetworkPolicyRequest) *coordv1.PushNetworkPolicyRequest {
	t.Helper()
	req.TimestampUnix, req.Signature = signedCall(id, func(ts int64) crypto.CallClaims {
		return crypto.PushNetworkPolicyClaims(req.PeerId, req.NetworkId, req.Envelope, ts)
	})
	return req
}

// makePushRequest creates a new PushNetworkPolicyRequest with the given envelope, signed by the peer.
func makePushRequest(t *testing.T, peerID *crypto.Identity, peerIDStr, networkID, token string, envelope []byte) *coordv1.PushNetworkPolicyRequest {
	req := &coordv1.PushNetworkPolicyRequest{
		NetworkId: networkID,
		Token:     token,
		PeerId:    peerIDStr,
		Envelope:  envelope,
	}
	signPushNetworkPolicy(t, peerID, req)
	return req
}

// TestServer_PushNetworkPolicy_OK verifies that a valid policy push succeeds.
func TestServer_PushNetworkPolicy_OK(t *testing.T) {
	adminPriv, adminPub := generateAdminKeyPair(t)
	adminKeyB64 := base64.StdEncoding.EncodeToString(adminPub[:])

	srv, reg, peerID, peerIDStr := testServerWithAdminKeys(t, []string{adminKeyB64})
	defer reg.Close()

	envelope := signPolicyEnvelope(t, 1, adminPriv)

	req := makePushRequest(t, peerID, peerIDStr, "test-net", "test-token", envelope)

	resp, err := srv.PushNetworkPolicy(context.Background(), req)
	if err != nil {
		t.Fatalf("PushNetworkPolicy: %v", err)
	}
	if resp.Version != 1 {
		t.Errorf("version: got %d, want 1", resp.Version)
	}

	// Verify the policy is stored
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
}

// TestServer_PushNetworkPolicy_InvalidToken verifies that an invalid token is rejected.
func TestServer_PushNetworkPolicy_InvalidToken(t *testing.T) {
	adminPriv, adminPub := generateAdminKeyPair(t)
	adminKeyB64 := base64.StdEncoding.EncodeToString(adminPub[:])

	srv, _, peerID, peerIDStr := testServerWithAdminKeys(t, []string{adminKeyB64})

	envelope := signPolicyEnvelope(t, 1, adminPriv)

	req := makePushRequest(t, peerID, peerIDStr, "test-net", "bad-token", envelope)

	_, err := srv.PushNetworkPolicy(context.Background(), req)
	if err == nil {
		t.Fatal("PushNetworkPolicy should fail with invalid token")
	}
	if status.Code(err) != codes.Unauthenticated {
		t.Errorf("code: got %s, want Unauthenticated", status.Code(err))
	}
}

// TestServer_PushNetworkPolicy_NetworkNotFound verifies that a network the token doesn't own is rejected.
func TestServer_PushNetworkPolicy_NetworkNotFound(t *testing.T) {
	adminPriv, adminPub := generateAdminKeyPair(t)
	adminKeyB64 := base64.StdEncoding.EncodeToString(adminPub[:])

	srv, _, peerID, peerIDStr := testServerWithAdminKeys(t, []string{adminKeyB64})

	envelope := signPolicyEnvelope(t, 1, adminPriv)

	req := makePushRequest(t, peerID, peerIDStr, "nonexistent-net", "test-token", envelope)

	_, err := srv.PushNetworkPolicy(context.Background(), req)
	if err == nil {
		t.Fatal("PushNetworkPolicy should fail with nonexistent network")
	}
	if status.Code(err) != codes.NotFound {
		t.Errorf("code: got %s, want NotFound", status.Code(err))
	}
}

// TestServer_PushNetworkPolicy_NoAdminKeys verifies that push fails when no admin keys are pinned.
func TestServer_PushNetworkPolicy_NoAdminKeys(t *testing.T) {
	srv, _, peerID, peerIDStr := testServerWithAdminKeys(t, []string{})

	adminPriv, _ := generateAdminKeyPair(t)
	envelope := signPolicyEnvelope(t, 1, adminPriv)

	req := makePushRequest(t, peerID, peerIDStr, "test-net", "test-token", envelope)

	_, err := srv.PushNetworkPolicy(context.Background(), req)
	if err == nil {
		t.Fatal("PushNetworkPolicy should fail when no admin keys are pinned")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("code: got %s, want FailedPrecondition", status.Code(err))
	}
}

// TestServer_PushNetworkPolicy_UnpinnedSigner verifies that push fails when signer is not pinned.
func TestServer_PushNetworkPolicy_UnpinnedSigner(t *testing.T) {
	_, adminPub1 := generateAdminKeyPair(t)
	adminKeyB64_1 := base64.StdEncoding.EncodeToString(adminPub1[:])

	// Create admin key 2 (not pinned)
	adminPriv2, _ := generateAdminKeyPair(t)

	srv, _, peerID, peerIDStr := testServerWithAdminKeys(t, []string{adminKeyB64_1})

	// Sign with admin key 2 (not pinned)
	envelope := signPolicyEnvelope(t, 1, adminPriv2)

	req := makePushRequest(t, peerID, peerIDStr, "test-net", "test-token", envelope)

	_, err := srv.PushNetworkPolicy(context.Background(), req)
	if err == nil {
		t.Fatal("PushNetworkPolicy should fail with unpinned signer")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("code: got %s, want InvalidArgument", status.Code(err))
	}
}

// TestServer_PushNetworkPolicy_InvalidSignature verifies that push fails with invalid signature.
func TestServer_PushNetworkPolicy_InvalidSignature(t *testing.T) {
	adminPriv, adminPub := generateAdminKeyPair(t)
	adminKeyB64 := base64.StdEncoding.EncodeToString(adminPub[:])

	srv, _, peerID, peerIDStr := testServerWithAdminKeys(t, []string{adminKeyB64})

	envelope := signPolicyEnvelope(t, 1, adminPriv)
	// Corrupt the signature
	envelope[len(envelope)-1] ^= 0xFF

	req := makePushRequest(t, peerID, peerIDStr, "test-net", "test-token", envelope)

	_, err := srv.PushNetworkPolicy(context.Background(), req)
	if err == nil {
		t.Fatal("PushNetworkPolicy should fail with invalid signature")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("code: got %s, want InvalidArgument", status.Code(err))
	}
}

// TestServer_PushNetworkPolicy_SizeExceeded verifies that push fails when envelope exceeds 256 KiB.
func TestServer_PushNetworkPolicy_SizeExceeded(t *testing.T) {
	adminPriv, adminPub := generateAdminKeyPair(t)
	adminKeyB64 := base64.StdEncoding.EncodeToString(adminPub[:])

	srv, _, peerID, peerIDStr := testServerWithAdminKeys(t, []string{adminKeyB64})

	// Create a large envelope (over 256 KiB)
	largeEnvelope := make([]byte, maxNetworkPolicySize+1)
	copy(largeEnvelope, signPolicyEnvelope(t, 1, adminPriv))

	req := makePushRequest(t, peerID, peerIDStr, "test-net", "test-token", largeEnvelope)

	_, err := srv.PushNetworkPolicy(context.Background(), req)
	if err == nil {
		t.Fatal("PushNetworkPolicy should fail with oversized envelope")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("code: got %s, want InvalidArgument", status.Code(err))
	}
}

// TestServer_PushNetworkPolicy_VersionNotHigher verifies that push fails when version is not higher than stored.
func TestServer_PushNetworkPolicy_VersionNotHigher(t *testing.T) {
	adminPriv, adminPub := generateAdminKeyPair(t)
	adminKeyB64 := base64.StdEncoding.EncodeToString(adminPub[:])

	srv, reg, peerID, peerIDStr := testServerWithAdminKeys(t, []string{adminKeyB64})
	defer reg.Close()

	// Push version 1
	envelopeV1 := signPolicyEnvelope(t, 1, adminPriv)
	reqV1 := makePushRequest(t, peerID, peerIDStr, "test-net", "test-token", envelopeV1)

	_, err := srv.PushNetworkPolicy(context.Background(), reqV1)
	if err != nil {
		t.Fatalf("first PushNetworkPolicy: %v", err)
	}

	// Push version 1 again (should fail - version not higher)
	envelopeV1b := signPolicyEnvelope(t, 1, adminPriv)
	reqV1b := makePushRequest(t, peerID, peerIDStr, "test-net", "test-token", envelopeV1b)

	_, err = srv.PushNetworkPolicy(context.Background(), reqV1b)
	if err == nil {
		t.Fatal("PushNetworkPolicy should fail when version is not higher")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("code: got %s, want FailedPrecondition", status.Code(err))
	}

	// Push version 2 then try version 1 (should fail - version lower)
	envelopeV2 := signPolicyEnvelope(t, 2, adminPriv)
	reqV2 := makePushRequest(t, peerID, peerIDStr, "test-net", "test-token", envelopeV2)

	_, err = srv.PushNetworkPolicy(context.Background(), reqV2)
	if err != nil {
		t.Fatalf("PushNetworkPolicy v2: %v", err)
	}

	// Try to push version 1 (should fail)
	envelopeV1c := signPolicyEnvelope(t, 1, adminPriv)
	reqV1c := makePushRequest(t, peerID, peerIDStr, "test-net", "test-token", envelopeV1c)

	_, err = srv.PushNetworkPolicy(context.Background(), reqV1c)
	if err == nil {
		t.Fatal("PushNetworkPolicy should fail when version is lower")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("code: got %s, want FailedPrecondition", status.Code(err))
	}
}

// TestServer_PushNetworkPolicy_VersionMonotonicity verifies that version must strictly increase.
func TestServer_PushNetworkPolicy_VersionMonotonicity(t *testing.T) {
	adminPriv, adminPub := generateAdminKeyPair(t)
	adminKeyB64 := base64.StdEncoding.EncodeToString(adminPub[:])

	srv, _, peerID, peerIDStr := testServerWithAdminKeys(t, []string{adminKeyB64})

	// Push version 2 first
	envelopeV2 := signPolicyEnvelope(t, 2, adminPriv)
	reqV2 := makePushRequest(t, peerID, peerIDStr, "test-net", "test-token", envelopeV2)

	_, err := srv.PushNetworkPolicy(context.Background(), reqV2)
	if err != nil {
		t.Fatalf("PushNetworkPolicy v2: %v", err)
	}

	// Push version 1 (rollback, should fail)
	envelopeV1 := signPolicyEnvelope(t, 1, adminPriv)
	reqV1 := makePushRequest(t, peerID, peerIDStr, "test-net", "test-token", envelopeV1)

	_, err = srv.PushNetworkPolicy(context.Background(), reqV1)
	if err == nil {
		t.Fatal("PushNetworkPolicy should fail when version is lower")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("code: got %s, want FailedPrecondition", status.Code(err))
	}
}

// TestServer_PushNetworkPolicy_CrossAccount verifies that push from another account's token is rejected.
func TestServer_PushNetworkPolicy_CrossAccount(t *testing.T) {
	adminPriv, adminPub := generateAdminKeyPair(t)
	adminKeyB64 := base64.StdEncoding.EncodeToString(adminPub[:])

	// Create server with two accounts
	tmpDir := t.TempDir()
	reg, err := NewRegistry(tmpDir + "/test.db")
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	cidr := netip.MustParsePrefix("10.99.0.0/24")
	net := coordcore.Network{ID: "test-net", CIDR: cidr, Name: "Test Network"}
	if err := reg.CreateNetwork(net, "acc1"); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}

	if err := reg.SetNetworkAdminKeys("test-net", "acc1", []string{adminKeyB64}); err != nil {
		t.Fatalf("SetNetworkAdminKeys: %v", err)
	}

	bus := NewBus()
	enforcer := ce.NewFreeEnforcer()
	accounts := ce.NewTokenAccountStore(map[string]coordcore.Account{
		"token-acc1": {ID: "acc1", Tier: coordcore.TierFree},
		"token-acc2": {ID: "acc2", Tier: coordcore.TierFree},
	})
	audit := ce.NewNoopAuditLogger()
	subnet := ce.NewRejectSubnetPolicy()
	hooks := ce.NewNoopHooks()

	srv := New(reg, bus, enforcer, accounts, audit, subnet, hooks)

	// Register a peer in acc1's network
	id := newRegisterIdentity(t)
	req := newRegisterRequest(id, "test-net", "token-acc1", "peer1", "", nil)
	signRegisterReq(t, id, req)
	resp, err := srv.Register(context.Background(), req)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	envelope := signPolicyEnvelope(t, 1, adminPriv)

	// Try to push with acc2's token
	reqPush := makePushRequest(t, id, resp.PeerId, "test-net", "token-acc2", envelope)

	_, err = srv.PushNetworkPolicy(context.Background(), reqPush)
	if err == nil {
		t.Fatal("PushNetworkPolicy should fail with another account's token")
	}
	if status.Code(err) != codes.NotFound {
		t.Errorf("code: got %s, want NotFound", status.Code(err))
	}
}

// TestServer_PushNetworkPolicy_WatchDeliversEvent verifies that Watch receives NETWORK_POLICY event on push.
func TestServer_PushNetworkPolicy_WatchDeliversEvent(t *testing.T) {
	adminPriv, adminPub := generateAdminKeyPair(t)
	adminKeyB64 := base64.StdEncoding.EncodeToString(adminPub[:])

	srv, _, peerID, peerIDStr := testServerWithAdminKeys(t, []string{adminKeyB64})

	// Start Watch
	stream := newFakeWatchStream()
	done := make(chan error, 1)
	go func() {
		done <- srv.Watch(signWatch(t, peerID, &coordv1.WatchRequest{
			NetworkId: "test-net",
			Token:     "test-token",
			PeerId:    peerIDStr,
		}), stream)
	}()
	time.Sleep(50 * time.Millisecond)

	// Push policy
	envelope := signPolicyEnvelope(t, 1, adminPriv)
	req := makePushRequest(t, peerID, peerIDStr, "test-net", "test-token", envelope)

	_, err := srv.PushNetworkPolicy(context.Background(), req)
	if err != nil {
		t.Fatalf("PushNetworkPolicy: %v", err)
	}

	// Wait for event
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

	// Verify NETWORK_POLICY event was received
	var gotPolicy *coordv1.NetworkPolicyEvent
	for _, ev := range stream.events {
		if ev.Type == coordv1.EventType_NETWORK_POLICY && ev.NetworkPolicy != nil {
			gotPolicy = ev.NetworkPolicy
			break
		}
	}
	if gotPolicy == nil {
		t.Fatalf("no NETWORK_POLICY event received; events: %v", stream.events)
	}
	if len(gotPolicy.Envelope) == 0 {
		t.Error("NETWORK_POLICY event envelope is empty")
	}
}

// TestServer_PushNetworkPolicy_RefusedPushDoesNotChangeStoredVersion verifies that a refused push does not change the stored version.
func TestServer_PushNetworkPolicy_RefusedPushDoesNotChangeStoredVersion(t *testing.T) {
	adminPriv, adminPub := generateAdminKeyPair(t)
	adminKeyB64 := base64.StdEncoding.EncodeToString(adminPub[:])

	srv, reg, peerID, peerIDStr := testServerWithAdminKeys(t, []string{adminKeyB64})
	defer reg.Close()

	// Push version 2 first
	envelopeV2 := signPolicyEnvelope(t, 2, adminPriv)
	reqV2 := makePushRequest(t, peerID, peerIDStr, "test-net", "test-token", envelopeV2)

	_, err := srv.PushNetworkPolicy(context.Background(), reqV2)
	if err != nil {
		t.Fatalf("PushNetworkPolicy v2: %v", err)
	}

	// Try to push version 1 (should fail)
	envelopeV1 := signPolicyEnvelope(t, 1, adminPriv)
	reqV1 := makePushRequest(t, peerID, peerIDStr, "test-net", "test-token", envelopeV1)

	_, err = srv.PushNetworkPolicy(context.Background(), reqV1)
	if err == nil {
		t.Fatal("PushNetworkPolicy should fail when version is lower")
	}

	// Verify stored version is still 2
	_, storedVer, err := reg.GetNetworkPolicy("test-net")
	if err != nil {
		t.Fatalf("GetNetworkPolicy: %v", err)
	}
	if storedVer != 2 {
		t.Errorf("stored version after refused push: got %d, want 2", storedVer)
	}
}

// TestServer_PushNetworkPolicy_InvalidEnvelopeFormat verifies that malformed envelope is rejected.
func TestServer_PushNetworkPolicy_InvalidEnvelopeFormat(t *testing.T) {
	adminPriv, adminPub := generateAdminKeyPair(t)
	adminKeyB64 := base64.StdEncoding.EncodeToString(adminPub[:])

	srv, _, peerID, peerIDStr := testServerWithAdminKeys(t, []string{adminKeyB64})

	// Create malformed envelope (wrong magic)
	envelope := signPolicyEnvelope(t, 1, adminPriv)
	binary.BigEndian.PutUint32(envelope[0:4], 0xDEADBEEF)

	req := makePushRequest(t, peerID, peerIDStr, "test-net", "test-token", envelope)

	_, err := srv.PushNetworkPolicy(context.Background(), req)
	if err == nil {
		t.Fatal("PushNetworkPolicy should fail with invalid envelope format")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("code: got %s, want InvalidArgument", status.Code(err))
	}
}

// TestServer_PushNetworkPolicy_PeerNotInNetwork verifies that push fails when peer is not in the network.
func TestServer_PushNetworkPolicy_PeerNotInNetwork(t *testing.T) {
	adminPriv, adminPub := generateAdminKeyPair(t)
	adminKeyB64 := base64.StdEncoding.EncodeToString(adminPub[:])

	srv, _, peerID, _ := testServerWithAdminKeys(t, []string{adminKeyB64})

	envelope := signPolicyEnvelope(t, 1, adminPriv)

	// Try to push with a peer ID that doesn't exist in the network
	fakePeerID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	req := makePushRequest(t, peerID, fakePeerID, "test-net", "test-token", envelope)

	_, err := srv.PushNetworkPolicy(context.Background(), req)
	if err == nil {
		t.Fatal("PushNetworkPolicy should fail when peer is not in network")
	}
	if status.Code(err) != codes.NotFound {
		t.Errorf("code: got %s, want NotFound", status.Code(err))
	}
}
