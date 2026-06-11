// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package e2e_test

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"google.golang.org/grpc"

	coordce "github.com/veldmesh/veld/coord/ce"
	coordcore "github.com/veldmesh/veld/coord/core"
	coordserver "github.com/veldmesh/veld/coord/server"
	coordv1 "github.com/veldmesh/veld/gen/veld/coord/v1"
	"github.com/veldmesh/veld/internal/coord"
	"github.com/veldmesh/veld/internal/crypto"
	"github.com/veldmesh/veld/internal/peer"
)

// startCoordServer starts an in-process coord gRPC server and returns its address.
func startCoordServer(t *testing.T, networkID string, cidr netip.Prefix) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	reg, err := coordserver.NewRegistry(t.TempDir() + "/coord.db")
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	if err := reg.CreateNetwork(coordcore.Network{
		ID:   networkID,
		CIDR: cidr,
		Name: "e2e-net",
	}, "acc1"); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}

	bus := coordserver.NewBus()
	srv := coordserver.New(
		reg,
		bus,
		coordce.NewFreeEnforcer(),
		coordce.NewTokenAccountStore(map[string]coordcore.Account{
			"e2e-token": {ID: "acc1", Tier: coordcore.TierFree},
		}),
		coordce.NewNoopAuditLogger(),
		coordce.NewRejectSubnetPolicy(),
		coordce.NewNoopHooks(),
	)

	grpcSrv := grpc.NewServer()
	coordv1.RegisterCoordServer(grpcSrv, srv)
	go grpcSrv.Serve(ln)

	return ln.Addr().String(), func() {
		grpcSrv.Stop()
		reg.Close()
		ln.Close()
	}
}

// pollUntil polls cond every 5 ms until it returns true or timeout elapses.
func pollUntil(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

// TestCoordClient_TwoPeersDiscover verifies that two coord clients connecting to
// the same server each discover the other in their peer tables.
func TestCoordClient_TwoPeersDiscover(t *testing.T) {
	cidr := netip.MustParsePrefix("10.50.0.0/24")
	serverAddr, stopServer := startCoordServer(t, "e2e-net", cidr)
	defer stopServer()

	idA, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate idA: %v", err)
	}
	idB, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate idB: %v", err)
	}

	tblA := peer.New()
	tblB := peer.New()

	addedToA := make(chan *peer.Entry, 4)
	addedToB := make(chan *peer.Entry, 4)

	cA := coord.New(coord.Config{
		ServerAddr:  serverAddr,
		NetworkID:   "e2e-net",
		Token:       "e2e-token",
		Identity:    idA,
		LocalName:   "node-a",
		PeerTable:   tblA,
		TLSInsecure: true,
	})
	cA.OnPeerAdded = func(e *peer.Entry) {
		select {
		case addedToA <- e:
		default:
		}
	}

	cB := coord.New(coord.Config{
		ServerAddr:  serverAddr,
		NetworkID:   "e2e-net",
		Token:       "e2e-token",
		Identity:    idB,
		LocalName:   "node-b",
		PeerTable:   tblB,
		TLSInsecure: true,
	})
	cB.OnPeerAdded = func(e *peer.Entry) {
		select {
		case addedToB <- e:
		default:
		}
	}

	cA.Start()
	defer func() { cA.Stop(); cA.Wait() }()
	cB.Start()
	defer func() { cB.Stop(); cB.Wait() }()

	// Both should register and get valid VPN addresses.
	if !pollUntil(5*time.Second, func() bool {
		return cA.VPNAddr().IsValid() && cB.VPNAddr().IsValid()
	}) {
		t.Fatalf("timeout: A.VPN=%v B.VPN=%v", cA.VPNAddr(), cB.VPNAddr())
	}

	// VPN addresses should be distinct and both within CIDR.
	vpnA := cA.VPNAddr()
	vpnB := cB.VPNAddr()
	if vpnA == vpnB {
		t.Errorf("both peers got same VPN address %v", vpnA)
	}
	if !cidr.Contains(vpnA) || !cidr.Contains(vpnB) {
		t.Errorf("VPN addresses outside CIDR: A=%v B=%v cidr=%v", vpnA, vpnB, cidr)
	}

	// Each client should discover the other peer within 5 seconds.
	// A discovers B (either via seed on start or via JOIN Watch event).
	var bID [32]byte
	copy(bID[:], idB.Ed25519Public)
	if !pollUntil(5*time.Second, func() bool {
		_, ok := tblA.LookupByID(bID)
		return ok
	}) {
		t.Error("timeout: client A did not discover peer B")
	}

	var aID [32]byte
	copy(aID[:], idA.Ed25519Public)
	if !pollUntil(5*time.Second, func() bool {
		_, ok := tblB.LookupByID(aID)
		return ok
	}) {
		t.Error("timeout: client B did not discover peer A")
	}

	// Verify peer B's entry in A's table has the correct VPN address.
	if e, ok := tblA.LookupByID(bID); ok {
		if e.VPNAddr != vpnB {
			t.Errorf("A's view of B: VPNAddr got %v, want %v", e.VPNAddr, vpnB)
		}
	}

	// Verify peer A's entry in B's table has the correct VPN address.
	if e, ok := tblB.LookupByID(aID); ok {
		if e.VPNAddr != vpnA {
			t.Errorf("B's view of A: VPNAddr got %v, want %v", e.VPNAddr, vpnA)
		}
	}
}

// TestCoordClient_LeaveRemovesPeer verifies that when client B stops, client A's
// peer table no longer contains B.
func TestCoordClient_LeaveRemovesPeer(t *testing.T) {
	cidr := netip.MustParsePrefix("10.51.0.0/24")
	serverAddr, stopServer := startCoordServer(t, "e2e-net2", cidr)
	defer stopServer()

	idA, _ := crypto.Generate()
	idB, _ := crypto.Generate()

	tblA := peer.New()
	tblB := peer.New()

	removedFromA := make(chan [32]byte, 1)

	cA := coord.New(coord.Config{
		ServerAddr:  serverAddr,
		NetworkID:   "e2e-net2",
		Token:       "e2e-token",
		Identity:    idA,
		LocalName:   "node-a",
		PeerTable:   tblA,
		TLSInsecure: true,
	})
	cA.OnPeerRemoved = func(id [32]byte) {
		select {
		case removedFromA <- id:
		default:
		}
	}

	cB := coord.New(coord.Config{
		ServerAddr:  serverAddr,
		NetworkID:   "e2e-net2",
		Token:       "e2e-token",
		Identity:    idB,
		LocalName:   "node-b",
		PeerTable:   tblB,
		TLSInsecure: true,
	})

	cA.Start()
	cB.Start()

	// Wait for mutual discovery.
	var bID [32]byte
	copy(bID[:], idB.Ed25519Public)
	if !pollUntil(5*time.Second, func() bool {
		_, ok := tblA.LookupByID(bID)
		return ok
	}) {
		cA.Stop(); cA.Wait()
		cB.Stop(); cB.Wait()
		t.Fatal("timeout: A did not discover B")
	}

	// B stops (sends Leave).
	cB.Stop()
	cB.Wait()

	// A should receive LEAVE and remove B.
	select {
	case id := <-removedFromA:
		if id != bID {
			t.Errorf("OnPeerRemoved: wrong ID")
		}
	case <-time.After(5 * time.Second):
		t.Error("timeout: A did not receive LEAVE event for B")
	}

	if _, ok := tblA.LookupByID(bID); ok {
		t.Error("peer B still in A's table after B sent Leave")
	}

	cA.Stop()
	cA.Wait()
}
