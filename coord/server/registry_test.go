// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"net/netip"
	"testing"

	coordcore "github.com/veldmesh/veld/coord/core"
)

func TestRegistry_CreateAndGetNetwork(t *testing.T) {
	tmpDir := t.TempDir()
	reg, err := NewRegistry(tmpDir + "/test.db")
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	defer reg.Close()

	cidr := netip.MustParsePrefix("10.0.0.0/24")
	net := coordcore.Network{ID: "net1", CIDR: cidr, Name: "Test Network"}

	if err := reg.CreateNetwork(net, "acc1"); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}

	retrieved, accID, err := reg.GetNetwork("net1")
	if err != nil {
		t.Fatalf("GetNetwork: %v", err)
	}

	if retrieved.ID != "net1" || retrieved.Name != "Test Network" || accID != "acc1" {
		t.Errorf("GetNetwork returned wrong values: %+v, accID=%s", retrieved, accID)
	}

	if retrieved.CIDR != cidr {
		t.Errorf("CIDR mismatch: got %v, want %v", retrieved.CIDR, cidr)
	}
}

func TestRegistry_RegisterPeer_AssignsIP(t *testing.T) {
	tmpDir := t.TempDir()
	reg, err := NewRegistry(tmpDir + "/test.db")
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	defer reg.Close()

	cidr := netip.MustParsePrefix("10.0.0.0/24")
	net := coordcore.Network{ID: "net1", CIDR: cidr, Name: "Test Network"}
	if err := reg.CreateNetwork(net, "acc1"); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}

	rec := peerRecord{
		ID:            "peer1",
		Name:          "Peer 1",
		Ed25519Public: "dGVzdA==",
		X25519Public:  "dGVzdA==",
		Endpoint:      "192.168.1.1:51820",
		RegisteredAt:  0,
		LastSeen:      0,
	}

	vpnAddr, err := reg.RegisterPeer(rec, "net1", 0)
	if err != nil {
		t.Fatalf("RegisterPeer: %v", err)
	}

	if vpnAddr != netip.MustParseAddr("10.0.0.1") {
		t.Errorf("assigned IP: got %v, want 10.0.0.1", vpnAddr)
	}

	if !cidr.Contains(vpnAddr) {
		t.Errorf("assigned IP %v not in CIDR %v", vpnAddr, cidr)
	}
}

func TestRegistry_RegisterPeer_IncrementsMachineCount(t *testing.T) {
	tmpDir := t.TempDir()
	reg, err := NewRegistry(tmpDir + "/test.db")
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	defer reg.Close()

	cidr := netip.MustParsePrefix("10.0.0.0/24")
	net := coordcore.Network{ID: "net1", CIDR: cidr, Name: "Test Network"}
	if err := reg.CreateNetwork(net, "acc1"); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}

	count, err := reg.NetworkMachineCount("net1")
	if err != nil || count != 0 {
		t.Fatalf("initial count: got %d, want 0", count)
	}

	for i := 0; i < 2; i++ {
		rec := peerRecord{
			ID:            "peer" + string(rune('1'+i)),
			Name:          "Peer " + string(rune('1'+i)),
			Ed25519Public: "dGVzdA==",
			X25519Public:  "dGVzdA==",
			RegisteredAt:  0,
			LastSeen:      0,
		}
		if _, err := reg.RegisterPeer(rec, "net1", 0); err != nil {
			t.Fatalf("RegisterPeer %d: %v", i, err)
		}
	}

	count, err = reg.NetworkMachineCount("net1")
	if err != nil || count != 2 {
		t.Errorf("count after 2 registrations: got %d, want 2", count)
	}
}

func TestRegistry_RegisterPeer_AdvancesNextIP(t *testing.T) {
	tmpDir := t.TempDir()
	reg, err := NewRegistry(tmpDir + "/test.db")
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	defer reg.Close()

	cidr := netip.MustParsePrefix("10.0.0.0/24")
	net := coordcore.Network{ID: "net1", CIDR: cidr, Name: "Test Network"}
	if err := reg.CreateNetwork(net, "acc1"); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}

	var ips []netip.Addr
	for i := 0; i < 2; i++ {
		rec := peerRecord{
			ID:            "peer" + string(rune('1'+i)),
			Name:          "Peer " + string(rune('1'+i)),
			Ed25519Public: "dGVzdA==",
			X25519Public:  "dGVzdA==",
			RegisteredAt:  0,
			LastSeen:      0,
		}
		vpnAddr, err := reg.RegisterPeer(rec, "net1", 0)
		if err != nil {
			t.Fatalf("RegisterPeer %d: %v", i, err)
		}
		ips = append(ips, vpnAddr)
	}

	if ips[0] != netip.MustParseAddr("10.0.0.1") {
		t.Errorf("first IP: got %v, want 10.0.0.1", ips[0])
	}
	if ips[1] != netip.MustParseAddr("10.0.0.2") {
		t.Errorf("second IP: got %v, want 10.0.0.2", ips[1])
	}
}

func TestRegistry_RemovePeer_DecrementsMachineCount(t *testing.T) {
	tmpDir := t.TempDir()
	reg, err := NewRegistry(tmpDir + "/test.db")
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	defer reg.Close()

	cidr := netip.MustParsePrefix("10.0.0.0/24")
	net := coordcore.Network{ID: "net1", CIDR: cidr, Name: "Test Network"}
	if err := reg.CreateNetwork(net, "acc1"); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}

	rec := peerRecord{
		ID:            "peer1",
		Name:          "Peer 1",
		Ed25519Public: "dGVzdA==",
		X25519Public:  "dGVzdA==",
		RegisteredAt:  0,
		LastSeen:      0,
	}

	if _, err := reg.RegisterPeer(rec, "net1", 0); err != nil {
		t.Fatalf("RegisterPeer: %v", err)
	}

	count, err := reg.NetworkMachineCount("net1")
	if err != nil || count != 1 {
		t.Fatalf("count after registration: got %d, want 1", count)
	}

	_, err = reg.RemovePeer("peer1")
	if err != nil {
		t.Fatalf("RemovePeer: %v", err)
	}

	count, err = reg.NetworkMachineCount("net1")
	if err != nil || count != 0 {
		t.Errorf("count after removal: got %d, want 0", count)
	}
}

func TestRegistry_ListPeers_FiltersNetwork(t *testing.T) {
	tmpDir := t.TempDir()
	reg, err := NewRegistry(tmpDir + "/test.db")
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	defer reg.Close()

	cidr := netip.MustParsePrefix("10.0.0.0/24")
	net1 := coordcore.Network{ID: "net1", CIDR: cidr, Name: "Test Network 1"}
	net2 := coordcore.Network{ID: "net2", CIDR: cidr, Name: "Test Network 2"}

	if err := reg.CreateNetwork(net1, "acc1"); err != nil {
		t.Fatalf("CreateNetwork net1: %v", err)
	}
	if err := reg.CreateNetwork(net2, "acc1"); err != nil {
		t.Fatalf("CreateNetwork net2: %v", err)
	}

	// Register 2 peers in net1, 1 in net2
	for i := 0; i < 2; i++ {
		rec := peerRecord{
			ID:            "net1_peer" + string(rune('1'+i)),
			Name:          "Peer " + string(rune('1'+i)),
			Ed25519Public: "dGVzdA==",
			X25519Public:  "dGVzdA==",
			RegisteredAt:  0,
			LastSeen:      0,
		}
		if _, err := reg.RegisterPeer(rec, "net1", 0); err != nil {
			t.Fatalf("RegisterPeer net1 %d: %v", i, err)
		}
	}

	rec := peerRecord{
		ID:            "net2_peer1",
		Name:          "Peer 1",
		Ed25519Public: "dGVzdA==",
		X25519Public:  "dGVzdA==",
		RegisteredAt:  0,
		LastSeen:      0,
	}
	if _, err := reg.RegisterPeer(rec, "net2", 0); err != nil {
		t.Fatalf("RegisterPeer net2: %v", err)
	}

	peers1, err := reg.ListPeers("net1")
	if err != nil {
		t.Fatalf("ListPeers net1: %v", err)
	}

	peers2, err := reg.ListPeers("net2")
	if err != nil {
		t.Fatalf("ListPeers net2: %v", err)
	}

	if len(peers1) != 2 {
		t.Errorf("ListPeers net1: got %d peers, want 2", len(peers1))
	}
	if len(peers2) != 1 {
		t.Errorf("ListPeers net2: got %d peers, want 1", len(peers2))
	}

	// Verify filtering
	for _, p := range peers1 {
		if p.NetworkID != "net1" {
			t.Errorf("peer %s has wrong network: %s", p.ID, p.NetworkID)
		}
	}
	for _, p := range peers2 {
		if p.NetworkID != "net2" {
			t.Errorf("peer %s has wrong network: %s", p.ID, p.NetworkID)
		}
	}
}

func TestRegistry_NetworkCount(t *testing.T) {
	tmpDir := t.TempDir()
	reg, err := NewRegistry(tmpDir + "/test.db")
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	defer reg.Close()

	cidr := netip.MustParsePrefix("10.0.0.0/24")

	// Create 2 networks for acc1, 1 for acc2
	net1 := coordcore.Network{ID: "net1", CIDR: cidr, Name: "Test Network 1"}
	net2 := coordcore.Network{ID: "net2", CIDR: cidr, Name: "Test Network 2"}
	net3 := coordcore.Network{ID: "net3", CIDR: cidr, Name: "Test Network 3"}

	if err := reg.CreateNetwork(net1, "acc1"); err != nil {
		t.Fatalf("CreateNetwork net1: %v", err)
	}
	if err := reg.CreateNetwork(net2, "acc1"); err != nil {
		t.Fatalf("CreateNetwork net2: %v", err)
	}
	if err := reg.CreateNetwork(net3, "acc2"); err != nil {
		t.Fatalf("CreateNetwork net3: %v", err)
	}

	count1, err := reg.NetworkCount("acc1")
	if err != nil || count1 != 2 {
		t.Errorf("NetworkCount acc1: got %d, want 2", count1)
	}

	count2, err := reg.NetworkCount("acc2")
	if err != nil || count2 != 1 {
		t.Errorf("NetworkCount acc2: got %d, want 1", count2)
	}
}
