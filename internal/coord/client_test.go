// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: BUSL-1.1
package coord_test

import (
	"context"
	"encoding/base64"
	"net"
	"net/netip"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	coordce "github.com/veldmesh/veld/coord/ce"
	coordcore "github.com/veldmesh/veld/coord/core"
	coordserver "github.com/veldmesh/veld/coord/server"
	coordv1 "github.com/veldmesh/veld/gen/veld/coord/v1"
	"github.com/veldmesh/veld/internal/coord"
	"github.com/veldmesh/veld/internal/crypto"
	"github.com/veldmesh/veld/internal/peer"
)

// testCoordServer starts an in-process gRPC coord server and returns its address.
// The caller is responsible for stopping the gRPC server and closing the registry.
func testCoordServer(t *testing.T) (addr string, grpcSrv *grpc.Server, reg *coordserver.Registry) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	reg, err = coordserver.NewRegistry(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	cidr := netip.MustParsePrefix("10.200.0.0/24")
	net := coordcore.Network{ID: "net-test", CIDR: cidr, Name: "Test"}
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
		coordce.NewRejectSubnetPolicy(),
		coordce.NewNoopHooks(),
	)

	grpcSrv = grpc.NewServer()
	coordv1.RegisterCoordServer(grpcSrv, srv)
	go grpcSrv.Serve(ln)

	return ln.Addr().String(), grpcSrv, reg
}

// makeClient builds a coord.Client with a fresh identity targeting the given server.
func makeClient(t *testing.T, serverAddr string, tbl *peer.Table) (*coord.Client, *crypto.Identity) {
	t.Helper()
	id, err := crypto.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	cfg := coord.Config{
		ServerAddr:  serverAddr,
		NetworkID:   "net-test",
		Token:       "tok",
		Identity:    id,
		LocalName:   "test-node",
		PeerTable:   tbl,
		TLSInsecure: true,
	}
	return coord.New(cfg), id
}

// waitFor polls cond every 5 ms until it returns true or the deadline is exceeded.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

// TestClient_Register_PopulatesVPNAddr verifies that Start registers successfully
// and VPNAddr returns a valid address within the network CIDR.
func TestClient_Register_PopulatesVPNAddr(t *testing.T) {
	addr, grpcSrv, reg := testCoordServer(t)
	defer grpcSrv.Stop()
	defer reg.Close()

	tbl := peer.New()
	c, _ := makeClient(t, addr, tbl)
	c.Start()
	defer func() { c.Stop(); c.Wait() }()

	ok := waitFor(t, 3*time.Second, func() bool { return c.VPNAddr().IsValid() })
	if !ok {
		t.Fatal("timeout: VPNAddr not populated after Start")
	}
	vpn := c.VPNAddr()
	cidr := netip.MustParsePrefix("10.200.0.0/24")
	if !cidr.Contains(vpn) {
		t.Errorf("VPNAddr %v not in CIDR %v", vpn, cidr)
	}
}

// TestClient_SeedsPeerTable verifies that ListPeers is called after Register
// and existing peers are added to the table before Watch starts.
func TestClient_SeedsPeerTable(t *testing.T) {
	addr, grpcSrv, reg := testCoordServer(t)
	defer grpcSrv.Stop()
	defer reg.Close()

	// Register peer B directly via raw gRPC before starting client A.
	grpcConn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer grpcConn.Close()
	rawClient := coordv1.NewCoordClient(grpcConn)

	idB, _ := crypto.Generate()
	_, err = rawClient.Register(context.Background(), &coordv1.RegisterRequest{
		NetworkId:     "net-test",
		Token:         "tok",
		Name:          "peer-B",
		Ed25519Public: base64.StdEncoding.EncodeToString(idB.Ed25519Public),
		X25519Public:  base64.StdEncoding.EncodeToString(idB.X25519Public[:]),
		Endpoint:      "1.2.3.4:51820",
	})
	if err != nil {
		t.Fatalf("Register B: %v", err)
	}

	// Now start client A — it should seed its table with B.
	tblA := peer.New()
	added := make(chan struct{}, 1)
	cA, _ := makeClient(t, addr, tblA)
	cA.OnPeerAdded = func(_ *peer.Entry) {
		select {
		case added <- struct{}{}:
		default:
		}
	}
	cA.Start()
	defer func() { cA.Stop(); cA.Wait() }()

	select {
	case <-added:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout: OnPeerAdded not called for pre-existing peer B")
	}

	var bID [32]byte
	copy(bID[:], idB.Ed25519Public)
	entry, ok := tblA.LookupByID(bID)
	if !ok {
		t.Fatal("peer B not in table after seed")
	}
	if entry.VPNAddr != netip.MustParseAddr("10.200.0.1") {
		t.Errorf("peer B VPNAddr: got %v, want 10.200.0.1", entry.VPNAddr)
	}
}

// TestClient_WatchJoin_UpdatesPeerTable verifies that a JOIN event received over
// the Watch stream causes the new peer to appear in the local peer table.
func TestClient_WatchJoin_UpdatesPeerTable(t *testing.T) {
	addr, grpcSrv, reg := testCoordServer(t)
	defer grpcSrv.Stop()
	defer reg.Close()

	tblA := peer.New()
	added := make(chan *peer.Entry, 1)
	cA, _ := makeClient(t, addr, tblA)
	cA.OnPeerAdded = func(e *peer.Entry) {
		select {
		case added <- e:
		default:
		}
	}
	cA.Start()
	defer func() { cA.Stop(); cA.Wait() }()

	// Wait until A has registered so Watch is active.
	if !waitFor(t, 3*time.Second, func() bool { return cA.VPNAddr().IsValid() }) {
		t.Fatal("timeout: client A did not register")
	}

	// Register peer B — should trigger JOIN event on A's Watch stream.
	grpcConn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer grpcConn.Close()
	rawClient := coordv1.NewCoordClient(grpcConn)

	idB, _ := crypto.Generate()
	_, err = rawClient.Register(context.Background(), &coordv1.RegisterRequest{
		NetworkId:     "net-test",
		Token:         "tok",
		Name:          "peer-B",
		Ed25519Public: base64.StdEncoding.EncodeToString(idB.Ed25519Public),
		X25519Public:  base64.StdEncoding.EncodeToString(idB.X25519Public[:]),
		Endpoint:      "5.5.5.5:51820",
	})
	if err != nil {
		t.Fatalf("Register B: %v", err)
	}

	select {
	case e := <-added:
		if e.VPNAddr != netip.MustParseAddr("10.200.0.2") {
			t.Errorf("peer B VPNAddr: got %v, want 10.200.0.2", e.VPNAddr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout: OnPeerAdded not called for JOIN event")
	}
}

// TestClient_WatchLeave_RemovesPeerFromTable verifies that a LEAVE event causes
// the departing peer to be removed from the local peer table.
func TestClient_WatchLeave_RemovesPeerFromTable(t *testing.T) {
	addr, grpcSrv, reg := testCoordServer(t)
	defer grpcSrv.Stop()
	defer reg.Close()

	grpcConn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer grpcConn.Close()
	rawClient := coordv1.NewCoordClient(grpcConn)

	// Register peer B directly.
	idB, _ := crypto.Generate()
	regResp, err := rawClient.Register(context.Background(), &coordv1.RegisterRequest{
		NetworkId:     "net-test",
		Token:         "tok",
		Name:          "peer-B",
		Ed25519Public: base64.StdEncoding.EncodeToString(idB.Ed25519Public),
		X25519Public:  base64.StdEncoding.EncodeToString(idB.X25519Public[:]),
	})
	if err != nil {
		t.Fatalf("Register B: %v", err)
	}

	// Start client A.
	tblA := peer.New()
	removed := make(chan [32]byte, 1)
	cA, _ := makeClient(t, addr, tblA)
	cA.OnPeerRemoved = func(id [32]byte) {
		select {
		case removed <- id:
		default:
		}
	}
	cA.Start()
	defer func() { cA.Stop(); cA.Wait() }()

	// Wait until A has seeded its table (B should already be there).
	var bID [32]byte
	copy(bID[:], idB.Ed25519Public)
	if !waitFor(t, 3*time.Second, func() bool {
		_, ok := tblA.LookupByID(bID)
		return ok
	}) {
		t.Fatal("timeout: peer B not seeded into table A")
	}

	// B leaves.
	_, err = rawClient.Leave(context.Background(), &coordv1.LeaveRequest{
		Token:  "tok",
		PeerId: regResp.PeerId,
	})
	if err != nil {
		t.Fatalf("Leave B: %v", err)
	}

	select {
	case id := <-removed:
		if id != bID {
			t.Errorf("OnPeerRemoved: got wrong ID")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout: OnPeerRemoved not called for LEAVE event")
	}

	if _, ok := tblA.LookupByID(bID); ok {
		t.Error("peer B still in table after LEAVE")
	}
}

// TestClient_Stop_SendsLeave verifies that stopping the client causes a Leave
// RPC to be sent, removing the peer from the server registry.
func TestClient_Stop_SendsLeave(t *testing.T) {
	addr, grpcSrv, reg := testCoordServer(t)
	defer grpcSrv.Stop()
	defer reg.Close()

	tbl := peer.New()
	c, _ := makeClient(t, addr, tbl)
	c.Start()

	if !waitFor(t, 3*time.Second, func() bool { return c.VPNAddr().IsValid() }) {
		t.Fatal("timeout: client did not register")
	}

	c.Stop()
	c.Wait()

	// After Stop+Wait, the peer should have been removed from the registry.
	grpcConn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer grpcConn.Close()
	rawClient := coordv1.NewCoordClient(grpcConn)

	listResp, err := rawClient.ListPeers(context.Background(), &coordv1.ListPeersRequest{
		NetworkId: "net-test",
		Token:     "tok",
	})
	if err != nil {
		t.Fatalf("ListPeers: %v", err)
	}
	if len(listResp.Peers) != 0 {
		t.Errorf("ListPeers after Stop: got %d peers, want 0", len(listResp.Peers))
	}
}

// TestClient_OnSignal verifies that a signal sent via the coord server is
// delivered to the target client's OnSignal callback.
func TestClient_OnSignal(t *testing.T) {
	addr, grpcSrv, reg := testCoordServer(t)
	defer grpcSrv.Stop()
	defer reg.Close()

	// Start client A.
	tblA := peer.New()
	cA, _ := makeClient(t, addr, tblA)
	cA.Start()
	defer func() { cA.Stop(); cA.Wait() }()

	// Start client B — this is the signal target.
	tblB := peer.New()
	signalReceived := make(chan struct {
		from    string
		payload []byte
	}, 1)
	cB, _ := makeClient(t, addr, tblB)
	cB.OnSignal = func(fromPeerID string, payload []byte) {
		select {
		case signalReceived <- struct {
			from    string
			payload []byte
		}{from: fromPeerID, payload: payload}:
		default:
		}
	}
	cB.Start()
	defer func() { cB.Stop(); cB.Wait() }()

	// Wait until both clients have registered.
	if !waitFor(t, 3*time.Second, func() bool { return cA.VPNAddr().IsValid() && cB.VPNAddr().IsValid() }) {
		t.Fatal("timeout: clients did not register")
	}

	peerIDA := cA.PeerID()
	peerIDB := cB.PeerID()

	// Send a signal from A to B via a raw gRPC call.
	grpcConn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer grpcConn.Close()
	rawClient := coordv1.NewCoordClient(grpcConn)

	wantPayload := []byte("hello from A")
	_, err = rawClient.SendSignal(context.Background(), &coordv1.SendSignalRequest{
		Token:      "tok",
		FromPeerId: peerIDA,
		ToPeerId:   peerIDB,
		Payload:    wantPayload,
	})
	if err != nil {
		t.Fatalf("SendSignal: %v", err)
	}

	select {
	case sig := <-signalReceived:
		if sig.from != peerIDA {
			t.Errorf("OnSignal fromPeerID: got %q, want %q", sig.from, peerIDA)
		}
		if string(sig.payload) != string(wantPayload) {
			t.Errorf("OnSignal payload: got %q, want %q", sig.payload, wantPayload)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout: OnSignal not called within 500ms")
	}
}

// TestClient_Idempotent_Reregistration verifies that starting a client twice
// (simulating a reconnect) does not double-count the peer in the registry.
func TestClient_Idempotent_Reregistration(t *testing.T) {
	addr, grpcSrv, reg := testCoordServer(t)
	defer grpcSrv.Stop()
	defer reg.Close()

	idA, _ := crypto.Generate()
	cfg := coord.Config{
		ServerAddr:  addr,
		NetworkID:   "net-test",
		Token:       "tok",
		Identity:    idA,
		LocalName:   "node-a",
		PeerTable:   peer.New(),
		TLSInsecure: true,
	}

	// First connection.
	c1 := coord.New(cfg)
	c1.Start()
	if !waitFor(t, 3*time.Second, func() bool { return c1.VPNAddr().IsValid() }) {
		t.Fatal("first connection: timeout")
	}
	vpn1 := c1.VPNAddr()

	// Simulate disconnect without Leave (transient error).
	// Start a second client with the same identity — should get same IP back.
	c2 := coord.New(cfg)
	c2.Start()
	if !waitFor(t, 3*time.Second, func() bool { return c2.VPNAddr().IsValid() }) {
		t.Fatal("second connection: timeout")
	}
	vpn2 := c2.VPNAddr()

	if vpn1 != vpn2 {
		t.Errorf("VPNAddr changed on reconnect: first %v, second %v", vpn1, vpn2)
	}

	// Machine count should still be 1 (idempotent re-registration).
	count, err := reg.NetworkMachineCount("net-test")
	if err != nil {
		t.Fatalf("NetworkMachineCount: %v", err)
	}
	if count != 1 {
		t.Errorf("machine count: got %d, want 1", count)
	}

	c1.Stop(); c1.Wait()
	c2.Stop(); c2.Wait()
}
