// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package e2e_test

import (
	"context"
	"encoding/base64"
	"net"
	"net/netip"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	coordv1 "github.com/veldmesh/veld/gen/veld/coord/v1"
	coordcore "github.com/veldmesh/veld/coord/core"
	"github.com/veldmesh/veld/coord/ce"
	"github.com/veldmesh/veld/coord/server"
	"github.com/veldmesh/veld/internal/crypto"
)

// signedRegisterReq builds a RegisterRequest presenting id's public keys
// and signs it as proof of key possession, exactly like a real daemon does
// — the coord server rejects an unsigned Register.
func signedRegisterReq(t *testing.T, id *crypto.Identity, networkID, token, name, endpoint string, routes []string) *coordv1.RegisterRequest {
	t.Helper()
	req := &coordv1.RegisterRequest{
		NetworkId:     networkID,
		Token:         token,
		Name:          name,
		Ed25519Public: base64.StdEncoding.EncodeToString(id.Ed25519Public),
		X25519Public:  base64.StdEncoding.EncodeToString(id.X25519Public[:]),
		Endpoint:      endpoint,
		SubnetRoutes:  routes,
	}
	req.TimestampUnix = time.Now().Unix()
	req.Signature = crypto.SignRegister(id.Ed25519Private, crypto.RegisterClaims{
		NetworkID:     req.NetworkId,
		Ed25519Public: req.Ed25519Public,
		X25519Public:  req.X25519Public,
		Endpoint:      req.Endpoint,
		SubnetRoutes:  req.SubnetRoutes,
		TimestampUnix: req.TimestampUnix,
	})
	return req
}

func TestCoord_E2E(t *testing.T) {
	// Start gRPC server on random port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer listener.Close()

	grpcServer := grpc.NewServer()

	// Setup registry and server
	tmpDir := t.TempDir()
	reg, err := server.NewRegistry(tmpDir + "/test.db")
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	defer reg.Close()

	// Create test network
	cidr := netip.MustParsePrefix("10.99.0.0/24")
	net := coordcore.Network{ID: "test-net", CIDR: cidr, Name: "Test Network"}
	if err := reg.CreateNetwork(net, "acc1"); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
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

	// Start server in goroutine
	go grpcServer.Serve(listener)
	defer grpcServer.Stop()

	// Connect client
	conn, err := grpc.NewClient(
		listener.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer conn.Close()

	client := coordv1.NewCoordClient(conn)

	// Register first peer
	idA, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate peer1 identity: %v", err)
	}
	regResp1, err := client.Register(context.Background(),
		signedRegisterReq(t, idA, "test-net", "test-token", "peer1", "192.168.1.1:51820", nil))
	if err != nil {
		t.Fatalf("Register peer1: %v", err)
	}

	// Register second peer
	idB, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate peer2 identity: %v", err)
	}
	regResp2, err := client.Register(context.Background(),
		signedRegisterReq(t, idB, "test-net", "test-token", "peer2", "192.168.1.2:51820", nil))
	if err != nil {
		t.Fatalf("Register peer2: %v", err)
	}

	// ListPeers should return both
	listReq := &coordv1.ListPeersRequest{
		NetworkId: "test-net",
		Token:     "test-token",
	}

	listResp, err := client.ListPeers(context.Background(), listReq)
	if err != nil {
		t.Fatalf("ListPeers: %v", err)
	}

	if len(listResp.Peers) != 2 {
		t.Errorf("ListPeers: got %d peers, want 2", len(listResp.Peers))
	}

	// Verify VPN addresses are sequential and within CIDR
	vpnAddr1, _ := netip.ParseAddr(regResp1.VpnAddr)
	vpnAddr2, _ := netip.ParseAddr(regResp2.VpnAddr)

	if vpnAddr1 != netip.MustParseAddr("10.99.0.1") {
		t.Errorf("peer1 VPN address: got %s, want 10.99.0.1", regResp1.VpnAddr)
	}

	if vpnAddr2 != netip.MustParseAddr("10.99.0.2") {
		t.Errorf("peer2 VPN address: got %s, want 10.99.0.2", regResp2.VpnAddr)
	}

	// Both should be in CIDR
	if !cidr.Contains(vpnAddr1) || !cidr.Contains(vpnAddr2) {
		t.Errorf("VPN addresses not in CIDR: %s, %s not in %s", vpnAddr1, vpnAddr2, cidr)
	}

	// Leave with peer1
	leaveReq := &coordv1.LeaveRequest{
		Token:  "test-token",
		PeerId: regResp1.PeerId,
	}

	_, err = client.Leave(context.Background(), leaveReq)
	if err != nil {
		t.Fatalf("Leave: %v", err)
	}

	// ListPeers should return only peer2
	listResp, err = client.ListPeers(context.Background(), listReq)
	if err != nil {
		t.Fatalf("ListPeers after Leave: %v", err)
	}

	if len(listResp.Peers) != 1 {
		t.Errorf("ListPeers after Leave: got %d peers, want 1", len(listResp.Peers))
	}

	if listResp.Peers[0].Name != "peer2" {
		t.Errorf("Remaining peer: got %s, want peer2", listResp.Peers[0].Name)
	}
}

func TestCoord_E2E_Watch(t *testing.T) {
	// Start gRPC server on random port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer listener.Close()

	grpcServer := grpc.NewServer()

	// Setup registry and server
	tmpDir := t.TempDir()
	reg, err := server.NewRegistry(tmpDir + "/test.db")
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	defer reg.Close()

	// Create test network
	cidr := netip.MustParsePrefix("10.99.0.0/24")
	net := coordcore.Network{ID: "test-net", CIDR: cidr, Name: "Test Network"}
	if err := reg.CreateNetwork(net, "acc1"); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
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

	// Start server in goroutine
	go grpcServer.Serve(listener)
	defer grpcServer.Stop()

	// Connect client
	conn, err := grpc.NewClient(
		listener.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer conn.Close()

	client := coordv1.NewCoordClient(conn)

	// Start watching
	watchReq := &coordv1.WatchRequest{
		NetworkId: "test-net",
		Token:     "test-token",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	watchClient, err := client.Watch(ctx, watchReq)
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}

	// Register a peer (should trigger JOIN event in Watch)
	id, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	regResp, err := client.Register(context.Background(),
		signedRegisterReq(t, id, "test-net", "test-token", "peer1", "", nil))
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Receive JOIN event
	event, err := watchClient.Recv()
	if err != nil {
		t.Fatalf("Watch.Recv: %v", err)
	}

	if event.Type != coordv1.EventType_JOIN {
		t.Errorf("Event type: got %v, want JOIN", event.Type)
	}

	if event.Peer.Name != "peer1" {
		t.Errorf("Peer name: got %s, want peer1", event.Peer.Name)
	}

	// Leave and verify LEAVE event
	leaveReq := &coordv1.LeaveRequest{
		Token:  "test-token",
		PeerId: regResp.PeerId,
	}

	_, err = client.Leave(context.Background(), leaveReq)
	if err != nil {
		t.Fatalf("Leave: %v", err)
	}

	// Receive LEAVE event
	event, err = watchClient.Recv()
	if err != nil {
		t.Fatalf("Watch.Recv for LEAVE: %v", err)
	}

	if event.Type != coordv1.EventType_LEAVE {
		t.Errorf("Event type: got %v, want LEAVE", event.Type)
	}

	if event.Peer.Id != regResp.PeerId {
		t.Errorf("Peer ID in LEAVE: got %s, want %s", event.Peer.Id, regResp.PeerId)
	}
}
