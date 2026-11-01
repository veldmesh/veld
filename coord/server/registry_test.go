// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	coordcore "github.com/veldmesh/veld/coord/core"
	bolt "go.etcd.io/bbolt"
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

func TestRegistry_RegisterPeer_IDTakenInOtherNetwork(t *testing.T) {
	reg := newSweepTestRegistry(t)
	cidr := netip.MustParsePrefix("10.1.0.0/24")
	if err := reg.CreateNetwork(coordcore.Network{ID: "net2", CIDR: cidr, Name: "net2"}, "acc1"); err != nil {
		t.Fatalf("CreateNetwork net2: %v", err)
	}

	rec := peerRecord{
		ID:            "shared-peer",
		Name:          "shared",
		Ed25519Public: "dGVzdA==",
		X25519Public:  base64.StdEncoding.EncodeToString([]byte("x25519-original")),
		Endpoint:      "1.2.3.4:51820",
	}
	vpn, err := reg.RegisterPeer(rec, "net1", 0)
	if err != nil {
		t.Fatalf("RegisterPeer net1: %v", err)
	}

	if _, err := reg.RegisterPeer(rec, "net2", 0); !errors.Is(err, ErrPeerIDTaken) {
		t.Fatalf("RegisterPeer net2: got %v, want ErrPeerIDTaken", err)
	}

	stored, err := reg.GetPeer("shared-peer")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if stored.NetworkID != "net1" || stored.VPNAddr != vpn.String() {
		t.Errorf("record changed: got %+v, want network net1 and VPN %s", stored, vpn)
	}
	if got := inMemoryEndpoint(t, reg, "shared-peer"); got != "1.2.3.4:51820" {
		t.Errorf("endpoint changed: got %q, want 1.2.3.4:51820", got)
	}
	wantCounts := []struct {
		netID string
		want  int
	}{
		{"net1", 1},
		{"net2", 0},
	}
	for _, tc := range wantCounts {
		count, err := reg.NetworkMachineCount(tc.netID)
		if err != nil {
			t.Fatalf("NetworkMachineCount %s: %v", tc.netID, err)
		}
		if count != tc.want {
			t.Errorf("network %s machine count: got %d, want %d", tc.netID, count, tc.want)
		}
	}

	again, err := reg.RegisterPeer(rec, "net1", 0)
	if err != nil {
		t.Fatalf("same-network re-registration: %v", err)
	}
	if again != vpn {
		t.Errorf("re-registration VPN: got %s, want %s", again, vpn)
	}
}

func TestRegistry_RegisterPeer_X25519Mismatch(t *testing.T) {
	reg := newSweepTestRegistry(t)

	first := peerRecord{
		ID:            "p",
		Name:          "p",
		Ed25519Public: "dGVzdA==",
		X25519Public:  base64.StdEncoding.EncodeToString([]byte("x25519-original")),
	}
	vpn, err := reg.RegisterPeer(first, "net1", 0)
	if err != nil {
		t.Fatalf("RegisterPeer: %v", err)
	}

	rotated := first
	rotated.X25519Public = base64.StdEncoding.EncodeToString([]byte("x25519-rotated"))
	if _, err := reg.RegisterPeer(rotated, "net1", 0); !errors.Is(err, ErrPeerKeyMismatch) {
		t.Fatalf("RegisterPeer rotated key: got %v, want ErrPeerKeyMismatch", err)
	}

	stored, err := reg.GetPeer("p")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if stored.X25519Public != first.X25519Public {
		t.Errorf("stored X25519 key: got %q, want %q", stored.X25519Public, first.X25519Public)
	}
	count, err := reg.NetworkMachineCount("net1")
	if err != nil || count != 1 {
		t.Errorf("machine count: got %d (err %v), want 1", count, err)
	}

	if _, err := reg.RegisterPeer(first, "net1", 0); err != nil {
		t.Fatalf("idempotent re-registration: %v", err)
	}
	again, err := reg.RegisterPeer(first, "net1", 0)
	if err != nil {
		t.Fatalf("idempotent re-registration: %v", err)
	}
	if again != vpn {
		t.Errorf("re-registration VPN: got %s, want %s", again, vpn)
	}
}

func TestRegistry_AddressAllocation_PrefersNeverUsed(t *testing.T) {
	tmpDir := t.TempDir()
	reg, err := NewRegistry(tmpDir + "/test.db")
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	defer reg.Close()

	cidr := netip.MustParsePrefix("10.0.0.0/29")
	net := coordcore.Network{ID: "net1", CIDR: cidr, Name: "Test Network"}
	if err := reg.CreateNetwork(net, "acc1"); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}

	var peers []string
	for i := 0; i < 3; i++ {
		rec := peerRecord{
			ID:            "peer" + string(rune('1'+i)),
			Name:          "Peer " + string(rune('1'+i)),
			Ed25519Public: base64.StdEncoding.EncodeToString([]byte("pub" + string(rune('1'+i)) + "xxxxxxxxxxxxxxxxxxxxxxxx")),
			X25519Public:  base64.StdEncoding.EncodeToString([]byte("x25519" + string(rune('1'+i)) + "xxxxxxxxxxxxxxxxxxxxxxxx")),
			RegisteredAt:  0,
			LastSeen:      0,
		}
		vpnAddr, err := reg.RegisterPeer(rec, "net1", 0)
		if err != nil {
			t.Fatalf("RegisterPeer %d: %v", i, err)
		}
		peers = append(peers, vpnAddr.String())
	}

	if peers[0] != "10.0.0.1" || peers[1] != "10.0.0.2" || peers[2] != "10.0.0.3" {
		t.Errorf("initial assignments: got %v, want [10.0.0.1 10.0.0.2 10.0.0.3]", peers)
	}

	if _, err := reg.RemovePeer("peer2"); err != nil {
		t.Fatalf("RemovePeer peer2: %v", err)
	}

	rec := peerRecord{
		ID:            "peer4",
		Name:          "Peer 4",
		Ed25519Public: base64.StdEncoding.EncodeToString([]byte("pub4xxxxxxxxxxxxxxxxxxxxxxxxxx")),
		X25519Public:  base64.StdEncoding.EncodeToString([]byte("x255194xxxxxxxxxxxxxxxxxxxxxxxxx")),
		RegisteredAt:  0,
		LastSeen:      0,
	}
	vpnAddr, err := reg.RegisterPeer(rec, "net1", 0)
	if err != nil {
		t.Fatalf("RegisterPeer peer4: %v", err)
	}

	if vpnAddr.String() != "10.0.0.4" {
		t.Errorf("new peer got %s, want 10.0.0.4 (never-used), not 10.0.0.2 (freed)", vpnAddr)
	}
}

func TestRegistry_AddressAllocation_OldestFreedFirst(t *testing.T) {
	tmpDir := t.TempDir()
	reg, err := NewRegistry(tmpDir + "/test.db")
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	defer reg.Close()

	cidr := netip.MustParsePrefix("10.0.0.0/30")
	net := coordcore.Network{ID: "net1", CIDR: cidr, Name: "Test Network"}
	if err := reg.CreateNetwork(net, "acc1"); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}

	rec1 := peerRecord{
		ID:            "peerA",
		Name:          "Peer A",
		Ed25519Public: base64.StdEncoding.EncodeToString([]byte("pubAxxxxxxxxxxxxxxxxxxxxxxxxxx")),
		X25519Public:  base64.StdEncoding.EncodeToString([]byte("x25519Axxxxxxxxxxxxxxxxxxxxxxxxx")),
		RegisteredAt:  0,
		LastSeen:      0,
	}
	rec2 := peerRecord{
		ID:            "peerB",
		Name:          "Peer B",
		Ed25519Public: base64.StdEncoding.EncodeToString([]byte("pubBxxxxxxxxxxxxxxxxxxxxxxxxxx")),
		X25519Public:  base64.StdEncoding.EncodeToString([]byte("x25519Bxxxxxxxxxxxxxxxxxxxxxxxxx")),
		RegisteredAt:  0,
		LastSeen:      0,
	}

	vpnA, err := reg.RegisterPeer(rec1, "net1", 0)
	if err != nil {
		t.Fatalf("RegisterPeer A: %v", err)
	}
	vpnB, err := reg.RegisterPeer(rec2, "net1", 0)
	if err != nil {
		t.Fatalf("RegisterPeer B: %v", err)
	}

	if vpnA.String() != "10.0.0.1" || vpnB.String() != "10.0.0.2" {
		t.Errorf("initial: got %s, %s, want 10.0.0.1, 10.0.0.2", vpnA, vpnB)
	}

	if _, err := reg.RemovePeer("peerA"); err != nil {
		t.Fatalf("RemovePeer A: %v", err)
	}
	time.Sleep(10 * time.Millisecond)
	if _, err := reg.RemovePeer("peerB"); err != nil {
		t.Fatalf("RemovePeer B: %v", err)
	}

	rec3 := peerRecord{
		ID:            "peerC",
		Name:          "Peer C",
		Ed25519Public: base64.StdEncoding.EncodeToString([]byte("pubCxxxxxxxxxxxxxxxxxxxxxxxxxx")),
		X25519Public:  base64.StdEncoding.EncodeToString([]byte("x25519Cxxxxxxxxxxxxxxxxxxxxxxxxx")),
		RegisteredAt:  0,
		LastSeen:      0,
	}
	vpnC, err := reg.RegisterPeer(rec3, "net1", 0)
	if err != nil {
		t.Fatalf("RegisterPeer C: %v", err)
	}

	if vpnC.String() != "10.0.0.1" {
		t.Errorf("new peer got %s, want 10.0.0.1 (oldest freed)", vpnC)
	}
}

func TestRegistry_AddressAllocation_Exhaustion(t *testing.T) {
	tmpDir := t.TempDir()
	reg, err := NewRegistry(tmpDir + "/test.db")
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	defer reg.Close()

	cidr := netip.MustParsePrefix("10.0.0.0/30")
	net := coordcore.Network{ID: "net1", CIDR: cidr, Name: "Test Network"}
	if err := reg.CreateNetwork(net, "acc1"); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}

	for i := 0; i < 2; i++ {
		rec := peerRecord{
			ID:            "peer" + string(rune('1'+i)),
			Name:          "Peer " + string(rune('1'+i)),
			Ed25519Public: base64.StdEncoding.EncodeToString([]byte("pub" + string(rune('1'+i)) + "xxxxxxxxxxxxxxxxxxxxxxxx")),
			X25519Public:  base64.StdEncoding.EncodeToString([]byte("x25519" + string(rune('1'+i)) + "xxxxxxxxxxxxxxxxxxxxxxxx")),
			RegisteredAt:  0,
			LastSeen:      0,
		}
		if _, err := reg.RegisterPeer(rec, "net1", 0); err != nil {
			t.Fatalf("RegisterPeer %d: %v", i, err)
		}
	}

	rec := peerRecord{
		ID:            "peer3",
		Name:          "Peer 3",
		Ed25519Public: base64.StdEncoding.EncodeToString([]byte("pub3xxxxxxxxxxxxxxxxxxxxxxxxxx")),
		X25519Public:  base64.StdEncoding.EncodeToString([]byte("x255193xxxxxxxxxxxxxxxxxxxxxxxxx")),
		RegisteredAt:  0,
		LastSeen:      0,
	}
	_, err = reg.RegisterPeer(rec, "net1", 0)
	if !errors.Is(err, ErrAddressSpaceExhausted) {
		t.Errorf("expected ErrAddressSpaceExhausted, got %v", err)
	}
}

func TestRegistry_AddressAllocation_BackwardCompatibility(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := tmpDir + "/test.db"

	{
		reg, err := NewRegistry(dbPath)
		if err != nil {
			t.Fatalf("NewRegistry: %v", err)
		}

		cidr := netip.MustParsePrefix("10.0.0.0/24")
		net := coordcore.Network{ID: "net1", CIDR: cidr, Name: "Test Network"}
		if err := reg.CreateNetwork(net, "acc1"); err != nil {
			t.Fatalf("CreateNetwork: %v", err)
		}

		err = reg.db.Update(func(tx *bolt.Tx) error {
			nb := tx.Bucket(bucketNetworks)
			netData := nb.Get([]byte("net1"))
			if netData == nil {
				return fmt.Errorf("network not found")
			}
			var netRec networkRecord
			if err := json.Unmarshal(netData, &netRec); err != nil {
				return err
			}
			netRec.AssignedAddrs = nil
			updated, err := json.Marshal(netRec)
			if err != nil {
				return err
			}
			return nb.Put([]byte("net1"), updated)
		})
		if err != nil {
			t.Fatalf("manual DB update: %v", err)
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
		reg.Close()
	}

	{
		reg, err := NewRegistry(dbPath)
		if err != nil {
			t.Fatalf("NewRegistry (reopen): %v", err)
		}
		defer reg.Close()

		rec := peerRecord{
			ID:            "peer2",
			Name:          "Peer 2",
			Ed25519Public: base64.StdEncoding.EncodeToString([]byte("pub2xxxxxxxxxxxxxxxxxxxxxxxxxx")),
			X25519Public:  base64.StdEncoding.EncodeToString([]byte("x255192xxxxxxxxxxxxxxxxxxxxxxxxx")),
			RegisteredAt:  0,
			LastSeen:      0,
		}
		vpnAddr, err := reg.RegisterPeer(rec, "net1", 0)
		if err != nil {
			t.Fatalf("RegisterPeer after reopen: %v", err)
		}

		if vpnAddr.String() != "10.0.0.2" {
			t.Errorf("after reopen, got %s, want 10.0.0.2", vpnAddr)
		}

		if _, err := reg.RemovePeer("peer1"); err != nil {
			t.Fatalf("RemovePeer: %v", err)
		}
		rec3 := peerRecord{
			ID:            "peer3",
			Name:          "Peer 3",
			Ed25519Public: base64.StdEncoding.EncodeToString([]byte("pub3xxxxxxxxxxxxxxxxxxxxxxxxxx")),
			X25519Public:  base64.StdEncoding.EncodeToString([]byte("x255193xxxxxxxxxxxxxxxxxxxxxxxxx")),
			RegisteredAt:  0,
			LastSeen:      0,
		}
		vpnAddr3, err := reg.RegisterPeer(rec3, "net1", 0)
		if err != nil {
			t.Fatalf("RegisterPeer peer3: %v", err)
		}
		if vpnAddr3.String() != "10.0.0.3" {
			t.Errorf("peer3 got %s, want 10.0.0.3 (never-used)", vpnAddr3)
		}
	}
}

func TestRegistry_AddressAllocation_SurvivesReopen(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := tmpDir + "/test.db"

	{
		reg, err := NewRegistry(dbPath)
		if err != nil {
			t.Fatalf("NewRegistry: %v", err)
		}

		cidr := netip.MustParsePrefix("10.0.0.0/29")
		net := coordcore.Network{ID: "net1", CIDR: cidr, Name: "Test Network"}
		if err := reg.CreateNetwork(net, "acc1"); err != nil {
			t.Fatalf("CreateNetwork: %v", err)
		}

		for i := 0; i < 3; i++ {
			rec := peerRecord{
				ID:            "peer" + string(rune('1'+i)),
				Name:          "Peer " + string(rune('1'+i)),
				Ed25519Public: base64.StdEncoding.EncodeToString([]byte("pub" + string(rune('1'+i)) + "xxxxxxxxxxxxxxxxxxxxxxxx")),
				X25519Public:  base64.StdEncoding.EncodeToString([]byte("x25519" + string(rune('1'+i)) + "xxxxxxxxxxxxxxxxxxxxxxxx")),
				RegisteredAt:  0,
				LastSeen:      0,
			}
			if _, err := reg.RegisterPeer(rec, "net1", 0); err != nil {
				t.Fatalf("RegisterPeer %d: %v", i, err)
			}
		}

		if _, err := reg.RemovePeer("peer2"); err != nil {
			t.Fatalf("RemovePeer peer2: %v", err)
		}

		reg.Close()
	}

	{
		reg, err := NewRegistry(dbPath)
		if err != nil {
			t.Fatalf("NewRegistry (reopen): %v", err)
		}
		defer reg.Close()

		rec := peerRecord{
			ID:            "peer4",
			Name:          "Peer 4",
			Ed25519Public: base64.StdEncoding.EncodeToString([]byte("pub4xxxxxxxxxxxxxxxxxxxxxxxxxx")),
			X25519Public:  base64.StdEncoding.EncodeToString([]byte("x255194xxxxxxxxxxxxxxxxxxxxxxxxx")),
			RegisteredAt:  0,
			LastSeen:      0,
		}
		vpnAddr, err := reg.RegisterPeer(rec, "net1", 0)
		if err != nil {
			t.Fatalf("RegisterPeer peer4: %v", err)
		}

		if vpnAddr.String() != "10.0.0.4" {
			t.Errorf("after reopen, got %s, want 10.0.0.4 (never-used)", vpnAddr)
		}

		for i := 5; i <= 7; i++ {
			rec := peerRecord{
				ID:            "peer" + string(rune('0'+i)),
				Name:          "Peer " + string(rune('0'+i)),
				Ed25519Public: base64.StdEncoding.EncodeToString([]byte("pub" + string(rune('0'+i)) + "xxxxxxxxxxxxxxxxxxxxxxxxx")),
				X25519Public:  base64.StdEncoding.EncodeToString([]byte("x25519" + string(rune('0'+i)) + "xxxxxxxxxxxxxxxxxxxxxxxx")),
				RegisteredAt:  0,
				LastSeen:      0,
			}
			if _, err := reg.RegisterPeer(rec, "net1", 0); err != nil {
				t.Fatalf("RegisterPeer %d: %v", i, err)
			}
		}

		if _, err := reg.RemovePeer("peer1"); err != nil {
			t.Fatalf("RemovePeer peer1: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
		if _, err := reg.RemovePeer("peer3"); err != nil {
			t.Fatalf("RemovePeer peer3: %v", err)
		}

		reg.Close()
	}

	{
		reg, err := NewRegistry(dbPath)
		if err != nil {
			t.Fatalf("NewRegistry (reopen 2): %v", err)
		}
		defer reg.Close()

		rec := peerRecord{
			ID:            "peer8",
			Name:          "Peer 8",
			Ed25519Public: base64.StdEncoding.EncodeToString([]byte("pub8xxxxxxxxxxxxxxxxxxxxxxxxxx")),
			X25519Public:  base64.StdEncoding.EncodeToString([]byte("x255198xxxxxxxxxxxxxxxxxxxxxxxxx")),
			RegisteredAt:  0,
			LastSeen:      0,
		}
		vpnAddr, err := reg.RegisterPeer(rec, "net1", 0)
		if err != nil {
			t.Fatalf("RegisterPeer peer7: %v", err)
		}

		if vpnAddr.String() != "10.0.0.1" {
			t.Errorf("after reopen 2, got %s, want 10.0.0.1 (oldest freed)", vpnAddr)
		}
	}
}

func TestRegistry_ReRegistration_KeepsAddress(t *testing.T) {
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

	vpnAddr, err := reg.RegisterPeer(rec, "net1", 0)
	if err != nil {
		t.Fatalf("RegisterPeer: %v", err)
	}

	rec.Name = "Peer 1 Updated"
	again, err := reg.RegisterPeer(rec, "net1", 0)
	if err != nil {
		t.Fatalf("Re-register: %v", err)
	}
	if again != vpnAddr {
		t.Errorf("re-registration changed address: got %s, want %s", again, vpnAddr)
	}
}
