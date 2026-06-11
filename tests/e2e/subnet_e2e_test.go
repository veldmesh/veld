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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	coordv1 "github.com/veldmesh/veld/gen/veld/coord/v1"
	coordcore "github.com/veldmesh/veld/coord/core"
	coordce "github.com/veldmesh/veld/coord/ce"
	coordserver "github.com/veldmesh/veld/coord/server"
)

// startSubnetCoordServer starts an in-process coord server and returns the
// gRPC client address and a teardown function.
func startSubnetCoordServer(t *testing.T) (coordv1.CoordClient, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}

	grpcSrv := grpc.NewServer()
	reg, err := coordserver.NewRegistry(t.TempDir() + "/subnet.db")
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	cidr := netip.MustParsePrefix("10.96.0.0/24")
	net := coordcore.Network{ID: "subnet-net", CIDR: cidr, Name: "Subnet Test"}
	if err := reg.CreateNetwork(net, "acc1"); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}

	bus := coordserver.NewBus()
	srv := coordserver.New(
		reg,
		bus,
		coordce.NewFreeEnforcer(),
		coordce.NewTokenAccountStore(map[string]coordcore.Account{
			"tok": {ID: "acc1", Tier: coordcore.TierFree},
		}),
		coordce.NewNoopAuditLogger(),
		coordce.NewRejectSubnetPolicy(), // CE always rejects subnet routes
		coordce.NewNoopHooks(),
	)
	coordv1.RegisterCoordServer(grpcSrv, srv)
	go grpcSrv.Serve(ln)

	conn, err := grpc.NewClient(ln.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	teardown := func() {
		conn.Close()
		grpcSrv.Stop()
		reg.Close()
	}
	return coordv1.NewCoordClient(conn), teardown
}

// TestSubnet_CE_Rejects verifies that the CE coord server rejects subnet route
// advertisements with PermissionDenied (SubnetPolicy.Allow always returns ErrSubnetNotAvailable).
func TestSubnet_CE_Rejects(t *testing.T) {
	client, teardown := startSubnetCoordServer(t)
	defer teardown()

	ctx := context.Background()
	_, err := client.Register(ctx, &coordv1.RegisterRequest{
		NetworkId:     "subnet-net",
		Token:         "tok",
		Name:          "router",
		Ed25519Public: base64.StdEncoding.EncodeToString(make([]byte, 32)),
		X25519Public:  base64.StdEncoding.EncodeToString(make([]byte, 32)),
		SubnetRoutes:  []string{"192.168.1.0/24"},
	})
	if err == nil {
		t.Fatal("expected error when advertising subnet routes on CE; got nil")
	}
	s, ok := status.FromError(err)
	if !ok || s.Code() != codes.PermissionDenied {
		t.Errorf("expected PermissionDenied; got %v", err)
	}
}

// TestSubnet_NoRoutes_Succeeds verifies that registration without subnet routes
// still works normally (no regression).
func TestSubnet_NoRoutes_Succeeds(t *testing.T) {
	client, teardown := startSubnetCoordServer(t)
	defer teardown()

	ctx := context.Background()
	resp, err := client.Register(ctx, &coordv1.RegisterRequest{
		NetworkId:     "subnet-net",
		Token:         "tok",
		Name:          "peer",
		Ed25519Public: base64.StdEncoding.EncodeToString(make([]byte, 32)),
		X25519Public:  base64.StdEncoding.EncodeToString(make([]byte, 32)),
	})
	if err != nil {
		t.Fatalf("Register without subnet routes: %v", err)
	}
	if resp.VpnAddr == "" {
		t.Error("expected non-empty VPN address")
	}
}

// TestSubnet_InvalidCIDR verifies that malformed CIDR strings in subnet_routes
// are rejected with InvalidArgument before hitting the SubnetPolicy.
func TestSubnet_InvalidCIDR(t *testing.T) {
	client, teardown := startSubnetCoordServer(t)
	defer teardown()

	ctx := context.Background()
	_, err := client.Register(ctx, &coordv1.RegisterRequest{
		NetworkId:     "subnet-net",
		Token:         "tok",
		Name:          "bad",
		Ed25519Public: base64.StdEncoding.EncodeToString(make([]byte, 32)),
		X25519Public:  base64.StdEncoding.EncodeToString(make([]byte, 32)),
		SubnetRoutes:  []string{"not-a-cidr"},
	})
	if err == nil {
		t.Fatal("expected error for malformed CIDR; got nil")
	}
	s, ok := status.FromError(err)
	if !ok || s.Code() != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument; got %v", err)
	}
}

// TestSubnet_ListPeers_IncludesRoutes verifies that a peer registered without
// routes returns an empty route list in ListPeers (field is present and empty).
func TestSubnet_ListPeers_IncludesRoutes(t *testing.T) {
	client, teardown := startSubnetCoordServer(t)
	defer teardown()

	ctx := context.Background()

	// Register a peer without subnet routes.
	_, err := client.Register(ctx, &coordv1.RegisterRequest{
		NetworkId:     "subnet-net",
		Token:         "tok",
		Name:          "p1",
		Ed25519Public: base64.StdEncoding.EncodeToString(make([]byte, 32)),
		X25519Public:  base64.StdEncoding.EncodeToString(make([]byte, 32)),
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	list, err := client.ListPeers(ctx, &coordv1.ListPeersRequest{
		NetworkId: "subnet-net",
		Token:     "tok",
	})
	if err != nil {
		t.Fatalf("ListPeers: %v", err)
	}
	if len(list.Peers) != 1 {
		t.Fatalf("expected 1 peer; got %d", len(list.Peers))
	}
	// SubnetRoutes should be nil/empty for a peer that advertised none.
	if len(list.Peers[0].SubnetRoutes) != 0 {
		t.Errorf("expected no subnet routes; got %v", list.Peers[0].SubnetRoutes)
	}
}

// TestSubnet_Watch_JOIN_CarriesRoutes verifies that a JOIN Watch event for a peer
// that registered without routes has an empty route list in the event.
func TestSubnet_Watch_JOIN_CarriesRoutes(t *testing.T) {
	client, teardown := startSubnetCoordServer(t)
	defer teardown()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	watchStream, err := client.Watch(ctx, &coordv1.WatchRequest{
		NetworkId: "subnet-net",
		Token:     "tok",
	})
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}

	// Register a peer (triggers a JOIN event on the watch stream).
	go func() {
		client.Register(ctx, &coordv1.RegisterRequest{ //nolint:errcheck
			NetworkId:     "subnet-net",
			Token:         "tok",
			Name:          "watcher-peer",
			Ed25519Public: base64.StdEncoding.EncodeToString(make([]byte, 32)),
			X25519Public:  base64.StdEncoding.EncodeToString(make([]byte, 32)),
		})
	}()

	ev, err := watchStream.Recv()
	if err != nil {
		t.Fatalf("Watch.Recv: %v", err)
	}
	if ev.Type != coordv1.EventType_JOIN {
		t.Errorf("expected JOIN event; got %v", ev.Type)
	}
	if ev.Peer == nil {
		t.Fatal("JOIN event has nil Peer")
	}
	// For a peer with no routes, SubnetRoutes should be empty.
	if len(ev.Peer.SubnetRoutes) != 0 {
		t.Errorf("expected no subnet routes in JOIN event; got %v", ev.Peer.SubnetRoutes)
	}
}
