// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"strings"
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

// TestRegistry_AddressAllocation_PreUpgradeMigration reproduces the bug where
// a pre-upgrade database (with nil AssignedAddrs) that had peers removed
// before the upgrade incorrectly reuses freed addresses.
func TestRegistry_AddressAllocation_PreUpgradeMigration(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := tmpDir + "/test.db"

	// Phase 1: Create network, register p1, p2, p3, then remove p2.
	// This simulates a pre-upgrade database where addresses were assigned and freed.
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

		// Register p1, p2, p3 -> get 10.0.0.1, .2, .3
		for i := 1; i <= 3; i++ {
			rec := peerRecord{
				ID:            fmt.Sprintf("p%d", i),
				Name:          fmt.Sprintf("Peer %d", i),
				Ed25519Public: base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("pub%dxxxxxxxxxxxxxxxxxxxxxxxxx", i))),
				X25519Public:  base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("x25519%dxxxxxxxxxxxxxxxxxxxxxxxx", i))),
				RegisteredAt:  0,
				LastSeen:      0,
			}
			vpnAddr, err := reg.RegisterPeer(rec, "net1", 0)
			if err != nil {
				t.Fatalf("RegisterPeer p%d: %v", i, err)
			}
			if vpnAddr.String() != fmt.Sprintf("10.0.0.%d", i) {
				t.Errorf("p%d got %s, want 10.0.0.%d", i, vpnAddr, i)
			}
		}

		// Remove p2 (10.0.0.2)
		if _, err := reg.RemovePeer("p2"); err != nil {
			t.Fatalf("RemovePeer p2: %v", err)
		}

		// Now simulate pre-upgrade on-disk form: set AssignedAddrs to nil
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

		reg.Close()
	}

	// Phase 2: Reopen registry (simulating upgrade), register p4.
	// p4 must get 10.0.0.4 (never-used), not 10.0.0.2 (freed before upgrade).
	{
		reg, err := NewRegistry(dbPath)
		if err != nil {
			t.Fatalf("NewRegistry (reopen): %v", err)
		}
		defer reg.Close()

		rec := peerRecord{
			ID:            "p4",
			Name:          "Peer 4",
			Ed25519Public: base64.StdEncoding.EncodeToString([]byte("pub4xxxxxxxxxxxxxxxxxxxxxxxxxx")),
			X25519Public:  base64.StdEncoding.EncodeToString([]byte("x255194xxxxxxxxxxxxxxxxxxxxxxxxx")),
			RegisteredAt:  0,
			LastSeen:      0,
		}
		vpnAddr, err := reg.RegisterPeer(rec, "net1", 0)
		if err != nil {
			t.Fatalf("RegisterPeer p4: %v", err)
		}

		if vpnAddr.String() != "10.0.0.4" {
			t.Errorf("p4 got %s, want 10.0.0.4 (never-used), not 10.0.0.2 (freed before upgrade)", vpnAddr)
		}
	}
}

// TestRegistry_AddressAllocation_PreUpgradeMigration_WithGap tests the case
// where NextIP points past a gap (e.g. NextIP .6, peers hold .1 and .4).
// Uses a /29 (usable .1-.6) so the never-used space from NextIP can be exhausted.
// New registrations get .6 first (never-used from NextIP); then .2, .3, .5 (freed, lowest first).
func TestRegistry_AddressAllocation_PreUpgradeMigration_WithGap(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := tmpDir + "/test.db"

	// Phase 1: Create network, register peers to create a gap, then simulate pre-upgrade.
	{
		reg, err := NewRegistry(dbPath)
		if err != nil {
			t.Fatalf("NewRegistry: %v", err)
		}

		// /29: network 10.0.0.0, broadcast 10.0.0.7, usable 10.0.0.1-10.0.0.6 (6 addresses)
		cidr := netip.MustParsePrefix("10.0.0.0/29")
		net := coordcore.Network{ID: "net1", CIDR: cidr, Name: "Test Network"}
		if err := reg.CreateNetwork(net, "acc1"); err != nil {
			t.Fatalf("CreateNetwork: %v", err)
		}

		// Register p1 (10.0.0.1), p2 (10.0.0.2), p3 (10.0.0.3), p4 (10.0.0.4), p5 (10.0.0.5)
		for i := 1; i <= 5; i++ {
			rec := peerRecord{
				ID:            fmt.Sprintf("p%d", i),
				Name:          fmt.Sprintf("Peer %d", i),
				Ed25519Public: base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("pub%dxxxxxxxxxxxxxxxxxxxxxxxxx", i))),
				X25519Public:  base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("x25519%dxxxxxxxxxxxxxxxxxxxxxxxx", i))),
				RegisteredAt:  0,
				LastSeen:      0,
			}
			if _, err := reg.RegisterPeer(rec, "net1", 0); err != nil {
				t.Fatalf("RegisterPeer p%d: %v", i, err)
			}
		}

		// Remove p2 (10.0.0.2), p3 (10.0.0.3), p5 (10.0.0.5)
		// Remaining: p1 (10.0.0.1), p4 (10.0.0.4)
		// NextIP should be 10.0.0.6
		for _, id := range []string{"p2", "p3", "p5"} {
			if _, err := reg.RemovePeer(id); err != nil {
				t.Fatalf("RemovePeer %s: %v", id, err)
			}
		}

		// Verify NextIP is 10.0.0.6
		err = reg.db.View(func(tx *bolt.Tx) error {
			nb := tx.Bucket(bucketNetworks)
			netData := nb.Get([]byte("net1"))
			if netData == nil {
				return fmt.Errorf("network not found")
			}
			var netRec networkRecord
			if err := json.Unmarshal(netData, &netRec); err != nil {
				return err
			}
			if netRec.NextIP != "10.0.0.6" {
				t.Errorf("NextIP is %s, want 10.0.0.6", netRec.NextIP)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("verify NextIP: %v", err)
		}

		// Now simulate pre-upgrade on-disk form: set AssignedAddrs to nil
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

		reg.Close()
	}

	// Phase 2: Reopen registry, register new peers.
	// Never-used from NextIP (.6): only 10.0.0.6 (1 address)
	// Freed: 10.0.0.2, 10.0.0.3, 10.0.0.5
	// Order: .6 (never-used), then .2, .3, .5 (freed, lowest first)
	{
		reg, err := NewRegistry(dbPath)
		if err != nil {
			t.Fatalf("NewRegistry (reopen): %v", err)
		}
		defer reg.Close()

		// First gets never-used 10.0.0.6
		rec := peerRecord{
			ID:            "new1",
			Name:          "New 1",
			Ed25519Public: base64.StdEncoding.EncodeToString([]byte("new1xxxxxxxxxxxxxxxxxxxxxxxxxx")),
			X25519Public:  base64.StdEncoding.EncodeToString([]byte("xnew1xxxxxxxxxxxxxxxxxxxxxxxxx")),
			RegisteredAt:  0,
			LastSeen:      0,
		}
		vpnAddr, err := reg.RegisterPeer(rec, "net1", 0)
		if err != nil {
			t.Fatalf("RegisterPeer new1: %v", err)
		}
		if vpnAddr.String() != "10.0.0.6" {
			t.Errorf("new1 got %s, want 10.0.0.6 (never-used from NextIP)", vpnAddr)
		}

		// Next get freed addresses in order: 10.0.0.2, 10.0.0.3, 10.0.0.5
		expectedFreed := []string{"10.0.0.2", "10.0.0.3", "10.0.0.5"}
		for i, exp := range expectedFreed {
			rec := peerRecord{
				ID:            fmt.Sprintf("new%d", i+2),
				Name:          fmt.Sprintf("New %d", i+2),
				Ed25519Public: base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("new%dxxxxxxxxxxxxxxxxxxxxxxxxx", i+2))),
				X25519Public:  base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("xnew%dxxxxxxxxxxxxxxxxxxxxxxxx", i+2))),
				RegisteredAt:  0,
				LastSeen:      0,
			}
			vpnAddr, err := reg.RegisterPeer(rec, "net1", 0)
			if err != nil {
				t.Fatalf("RegisterPeer new%d: %v", i+2, err)
			}
			if vpnAddr.String() != exp {
				t.Errorf("new%d got %s, want %s (freed, lowest first)", i+2, vpnAddr, exp)
			}
		}

		// Next should exhaust address space
		rec = peerRecord{
			ID:            "new6",
			Name:          "New 6",
			Ed25519Public: base64.StdEncoding.EncodeToString([]byte("new6xxxxxxxxxxxxxxxxxxxxxxxxxx")),
			X25519Public:  base64.StdEncoding.EncodeToString([]byte("xnew6xxxxxxxxxxxxxxxxxxxxxxxxx")),
			RegisteredAt:  0,
			LastSeen:      0,
		}
		_, err = reg.RegisterPeer(rec, "net1", 0)
		if !errors.Is(err, ErrAddressSpaceExhausted) {
			t.Errorf("expected ErrAddressSpaceExhausted, got %v", err)
		}
	}
}

// TestRegistry_AddressAllocation_PreUpgradeMigration_Once tests that
// migration happens once: after the first registration the record has
// assigned_addrs and a reopen of the registry gives the same answers.
func TestRegistry_AddressAllocation_PreUpgradeMigration_Once(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := tmpDir + "/test.db"

	// Phase 1: Create network, register p1, p2, p3, remove p2, set AssignedAddrs to nil.
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

		for i := 1; i <= 3; i++ {
			rec := peerRecord{
				ID:            fmt.Sprintf("p%d", i),
				Name:          fmt.Sprintf("Peer %d", i),
				Ed25519Public: base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("pub%dxxxxxxxxxxxxxxxxxxxxxxxxx", i))),
				X25519Public:  base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("x25519%dxxxxxxxxxxxxxxxxxxxxxxxx", i))),
				RegisteredAt:  0,
				LastSeen:      0,
			}
			if _, err := reg.RegisterPeer(rec, "net1", 0); err != nil {
				t.Fatalf("RegisterPeer p%d: %v", i, err)
			}
		}

		if _, err := reg.RemovePeer("p2"); err != nil {
			t.Fatalf("RemovePeer p2: %v", err)
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

		reg.Close()
	}

	// Phase 2: First registration after upgrade (migration happens).
	{
		reg, err := NewRegistry(dbPath)
		if err != nil {
			t.Fatalf("NewRegistry (reopen): %v", err)
		}

		rec := peerRecord{
			ID:            "p4",
			Name:          "Peer 4",
			Ed25519Public: base64.StdEncoding.EncodeToString([]byte("pub4xxxxxxxxxxxxxxxxxxxxxxxxxx")),
			X25519Public:  base64.StdEncoding.EncodeToString([]byte("x255194xxxxxxxxxxxxxxxxxxxxxxxxx")),
			RegisteredAt:  0,
			LastSeen:      0,
		}
		vpnAddr, err := reg.RegisterPeer(rec, "net1", 0)
		if err != nil {
			t.Fatalf("RegisterPeer p4: %v", err)
		}
		if vpnAddr.String() != "10.0.0.4" {
			t.Errorf("p4 got %s, want 10.0.0.4", vpnAddr)
		}

		// Verify AssignedAddrs is now populated
		err = reg.db.View(func(tx *bolt.Tx) error {
			nb := tx.Bucket(bucketNetworks)
			netData := nb.Get([]byte("net1"))
			if netData == nil {
				return fmt.Errorf("network not found")
			}
			var netRec networkRecord
			if err := json.Unmarshal(netData, &netRec); err != nil {
				return err
			}
			if netRec.AssignedAddrs == nil {
				t.Errorf("AssignedAddrs is nil after migration")
			} else {
				// Should have entries for 10.0.0.1, 10.0.0.3 (assigned), 10.0.0.2 (freed), 10.0.0.4 (assigned)
				if netRec.AssignedAddrs["10.0.0.1"] != 0 {
					t.Errorf("10.0.0.1 should be assigned (0), got %d", netRec.AssignedAddrs["10.0.0.1"])
				}
				if netRec.AssignedAddrs["10.0.0.3"] != 0 {
					t.Errorf("10.0.0.3 should be assigned (0), got %d", netRec.AssignedAddrs["10.0.0.3"])
				}
				if netRec.AssignedAddrs["10.0.0.2"] <= 0 {
					t.Errorf("10.0.0.2 should be freed (>0), got %d", netRec.AssignedAddrs["10.0.0.2"])
				}
				if netRec.AssignedAddrs["10.0.0.4"] != 0 {
					t.Errorf("10.0.0.4 should be assigned (0), got %d", netRec.AssignedAddrs["10.0.0.4"])
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("verify AssignedAddrs: %v", err)
		}

		reg.Close()
	}

	// Phase 3: Reopen again, register p5 - should get 10.0.0.5 (never-used)
	{
		reg, err := NewRegistry(dbPath)
		if err != nil {
			t.Fatalf("NewRegistry (reopen 2): %v", err)
		}
		defer reg.Close()

		rec := peerRecord{
			ID:            "p5",
			Name:          "Peer 5",
			Ed25519Public: base64.StdEncoding.EncodeToString([]byte("pub5xxxxxxxxxxxxxxxxxxxxxxxxxx")),
			X25519Public:  base64.StdEncoding.EncodeToString([]byte("x255195xxxxxxxxxxxxxxxxxxxxxxxxx")),
			RegisteredAt:  0,
			LastSeen:      0,
		}
		vpnAddr, err := reg.RegisterPeer(rec, "net1", 0)
		if err != nil {
			t.Fatalf("RegisterPeer p5: %v", err)
		}
		if vpnAddr.String() != "10.0.0.5" {
			t.Errorf("p5 got %s, want 10.0.0.5 (never-used)", vpnAddr)
		}

		// Verify AssignedAddrs still has the migrated data
		err = reg.db.View(func(tx *bolt.Tx) error {
			nb := tx.Bucket(bucketNetworks)
			netData := nb.Get([]byte("net1"))
			if netData == nil {
				return fmt.Errorf("network not found")
			}
			var netRec networkRecord
			if err := json.Unmarshal(netData, &netRec); err != nil {
				return err
			}
			if netRec.AssignedAddrs == nil {
				t.Errorf("AssignedAddrs is nil after second reopen")
			}
			return nil
		})
		if err != nil {
			t.Fatalf("verify AssignedAddrs second reopen: %v", err)
		}
	}
}

// TestRegistry_AddressAllocation_PreUpgradeMigration_RemovePeerFirst tests the case
// where the first operation after upgrade is RemovePeer of a still-present peer,
// then RegisterPeer of a new peer. The new peer must get the next never-used address
// (at or above NextIP), not an address freed before the upgrade.
func TestRegistry_AddressAllocation_PreUpgradeMigration_RemovePeerFirst(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := tmpDir + "/test.db"

	// Phase 1: Create network, register p1, p2, p3, then remove p2.
	// This simulates a pre-upgrade database where addresses were assigned and freed.
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

		// Register p1, p2, p3 -> get 10.0.0.1, .2, .3
		for i := 1; i <= 3; i++ {
			rec := peerRecord{
				ID:            fmt.Sprintf("p%d", i),
				Name:          fmt.Sprintf("Peer %d", i),
				Ed25519Public: base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("pub%dxxxxxxxxxxxxxxxxxxxxxxxxx", i))),
				X25519Public:  base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("x25519%dxxxxxxxxxxxxxxxxxxxxxxxx", i))),
				RegisteredAt:  0,
				LastSeen:      0,
			}
			vpnAddr, err := reg.RegisterPeer(rec, "net1", 0)
			if err != nil {
				t.Fatalf("RegisterPeer p%d: %v", i, err)
			}
			if vpnAddr.String() != fmt.Sprintf("10.0.0.%d", i) {
				t.Errorf("p%d got %s, want 10.0.0.%d", i, vpnAddr, i)
			}
		}

		// Remove p2 (10.0.0.2)
		if _, err := reg.RemovePeer("p2"); err != nil {
			t.Fatalf("RemovePeer p2: %v", err)
		}

		// Now simulate pre-upgrade on-disk form: set AssignedAddrs to nil
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

		reg.Close()
	}

	// Phase 2: Reopen registry (simulating upgrade), FIRST remove p1, THEN register p4.
	// p4 must get 10.0.0.4 (never-used from NextIP), not 10.0.0.2 (freed before upgrade).
	{
		reg, err := NewRegistry(dbPath)
		if err != nil {
			t.Fatalf("NewRegistry (reopen): %v", err)
		}
		defer reg.Close()

		// First operation after upgrade: remove p1 (10.0.0.1)
		if _, err := reg.RemovePeer("p1"); err != nil {
			t.Fatalf("RemovePeer p1: %v", err)
		}

		// Now register p4 - must get 10.0.0.4 (never-used), not 10.0.0.2
		rec := peerRecord{
			ID:            "p4",
			Name:          "Peer 4",
			Ed25519Public: base64.StdEncoding.EncodeToString([]byte("pub4xxxxxxxxxxxxxxxxxxxxxxxxxx")),
			X25519Public:  base64.StdEncoding.EncodeToString([]byte("x255194xxxxxxxxxxxxxxxxxxxxxxxxx")),
			RegisteredAt:  0,
			LastSeen:      0,
		}
		vpnAddr, err := reg.RegisterPeer(rec, "net1", 0)
		if err != nil {
			t.Fatalf("RegisterPeer p4: %v", err)
		}

		if vpnAddr.String() != "10.0.0.4" {
			t.Errorf("p4 got %s, want 10.0.0.4 (never-used from NextIP), not 10.0.0.2 (freed before upgrade)", vpnAddr)
		}

		// Verify AssignedAddrs has the migrated data
		err = reg.db.View(func(tx *bolt.Tx) error {
			nb := tx.Bucket(bucketNetworks)
			netData := nb.Get([]byte("net1"))
			if netData == nil {
				return fmt.Errorf("network not found")
			}
			var netRec networkRecord
			if err := json.Unmarshal(netData, &netRec); err != nil {
				return err
			}
			if netRec.AssignedAddrs == nil {
				t.Errorf("AssignedAddrs is nil after migration")
			} else {
				// 10.0.0.2 (freed before upgrade) should have timestamp 1
				if netRec.AssignedAddrs["10.0.0.2"] <= 0 {
					t.Errorf("10.0.0.2 should be freed with timestamp 1, got %d", netRec.AssignedAddrs["10.0.0.2"])
				}
				// 10.0.0.3 (still assigned) should have timestamp 0
				if netRec.AssignedAddrs["10.0.0.3"] != 0 {
					t.Errorf("10.0.0.3 should be assigned (0), got %d", netRec.AssignedAddrs["10.0.0.3"])
				}
				// 10.0.0.4 (newly assigned) should have timestamp 0
				if netRec.AssignedAddrs["10.0.0.4"] != 0 {
					t.Errorf("10.0.0.4 should be assigned (0), got %d", netRec.AssignedAddrs["10.0.0.4"])
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("verify AssignedAddrs: %v", err)
		}
	}
}

// TestRegistry_AddressAllocation_PreUpgradeMigration_EmptyNextIP tests the case
// where a pre-upgrade database has an empty NextIP. The migration should log a
// warning and mark all non-held host addresses as freed with timestamp 1.
// Allocation then reuses the oldest-freed address first.
func TestRegistry_AddressAllocation_PreUpgradeMigration_EmptyNextIP(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := tmpDir + "/test.db"

	// Capture log output
	var buf strings.Builder
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })

	// Phase 1: Create network, register p1, p2, then remove p2.
	// Simulate pre-upgrade with empty NextIP.
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

		for i := 1; i <= 2; i++ {
			rec := peerRecord{
				ID:            fmt.Sprintf("p%d", i),
				Name:          fmt.Sprintf("Peer %d", i),
				Ed25519Public: base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("pub%dxxxxxxxxxxxxxxxxxxxxxxxxx", i))),
				X25519Public:  base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("x25519%dxxxxxxxxxxxxxxxxxxxxxxxx", i))),
				RegisteredAt:  0,
				LastSeen:      0,
			}
			if _, err := reg.RegisterPeer(rec, "net1", 0); err != nil {
				t.Fatalf("RegisterPeer p%d: %v", i, err)
			}
		}

		// Remove p2 (10.0.0.2)
		if _, err := reg.RemovePeer("p2"); err != nil {
			t.Fatalf("RemovePeer p2: %v", err)
		}

		// Set AssignedAddrs to nil AND NextIP to empty string
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
			netRec.NextIP = ""
			updated, err := json.Marshal(netRec)
			if err != nil {
				return err
			}
			return nb.Put([]byte("net1"), updated)
		})
		if err != nil {
			t.Fatalf("manual DB update: %v", err)
		}

		reg.Close()
	}

	// Phase 2: Reopen registry (simulating upgrade), register p3.
	// With empty NextIP fallback, all non-held addresses are marked freed (timestamp 1).
	// Allocation picks the oldest freed (lowest address): 10.0.0.2.
	{
		reg, err := NewRegistry(dbPath)
		if err != nil {
			t.Fatalf("NewRegistry (reopen): %v", err)
		}
		defer reg.Close()

		rec := peerRecord{
			ID:            "p3",
			Name:          "Peer 3",
			Ed25519Public: base64.StdEncoding.EncodeToString([]byte("pub3xxxxxxxxxxxxxxxxxxxxxxxxxx")),
			X25519Public:  base64.StdEncoding.EncodeToString([]byte("x255193xxxxxxxxxxxxxxxxxxxxxxxxx")),
			RegisteredAt:  0,
			LastSeen:      0,
		}
		vpnAddr, err := reg.RegisterPeer(rec, "net1", 0)
		if err != nil {
			t.Fatalf("RegisterPeer p3: %v", err)
		}

		// p3 gets the oldest freed address (10.0.0.2) because all non-held
		// addresses were marked freed with timestamp 1.
		if vpnAddr.String() != "10.0.0.2" {
			t.Errorf("p3 got %s, want 10.0.0.2 (oldest freed)", vpnAddr)
		}

		// Verify warning was logged
		output := buf.String()
		if !strings.Contains(output, "network \"net1\" has invalid or empty NextIP") {
			t.Errorf("expected warning about empty NextIP, got: %s", output)
		}

		// Verify AssignedAddrs: p1 (10.0.0.1) = 0, p2 (10.0.0.2) = 0 (now assigned to p3),
		// all other hosts in CIDR (except broadcast) should be marked freed (timestamp 1)
		err = reg.db.View(func(tx *bolt.Tx) error {
			nb := tx.Bucket(bucketNetworks)
			netData := nb.Get([]byte("net1"))
			if netData == nil {
				return fmt.Errorf("network not found")
			}
			var netRec networkRecord
			if err := json.Unmarshal(netData, &netRec); err != nil {
				return err
			}
			if netRec.AssignedAddrs == nil {
				t.Errorf("AssignedAddrs is nil after migration")
			} else {
				if netRec.AssignedAddrs["10.0.0.1"] != 0 {
					t.Errorf("10.0.0.1 should be assigned (0), got %d", netRec.AssignedAddrs["10.0.0.1"])
				}
				if netRec.AssignedAddrs["10.0.0.2"] != 0 {
					t.Errorf("10.0.0.2 should be assigned (0), got %d", netRec.AssignedAddrs["10.0.0.2"])
				}
				// Check a few other addresses are marked freed
				if netRec.AssignedAddrs["10.0.0.3"] != 1 {
					t.Errorf("10.0.0.3 should be freed (1), got %d", netRec.AssignedAddrs["10.0.0.3"])
				}
				if netRec.AssignedAddrs["10.0.0.4"] != 1 {
					t.Errorf("10.0.0.4 should be freed (1), got %d", netRec.AssignedAddrs["10.0.0.4"])
				}
				if netRec.AssignedAddrs["10.0.0.254"] != 1 {
					t.Errorf("10.0.0.254 should be freed (1), got %d", netRec.AssignedAddrs["10.0.0.254"])
				}
				// Broadcast address (10.0.0.255) should not be in the map
				if _, ok := netRec.AssignedAddrs["10.0.0.255"]; ok {
					t.Errorf("10.0.0.255 (broadcast) should not be in AssignedAddrs")
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("verify AssignedAddrs: %v", err)
		}
	}
}

// TestRegistry_AddressAllocation_PreUpgradeMigration_InvalidNextIP tests the case
// where a pre-upgrade database has an unparseable NextIP (e.g., "garbage").
// The migration should log a warning and mark all non-held host addresses as freed with timestamp 1.
func TestRegistry_AddressAllocation_PreUpgradeMigration_InvalidNextIP(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := tmpDir + "/test.db"

	// Capture log output
	var buf strings.Builder
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })

	// Phase 1: Create network, register p1, then simulate pre-upgrade with invalid NextIP.
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

		rec := peerRecord{
			ID:            "p1",
			Name:          "Peer 1",
			Ed25519Public: base64.StdEncoding.EncodeToString([]byte("pub1xxxxxxxxxxxxxxxxxxxxxxxxx")),
			X25519Public:  base64.StdEncoding.EncodeToString([]byte("x255191xxxxxxxxxxxxxxxxxxxxxxxx")),
			RegisteredAt:  0,
			LastSeen:      0,
		}
		if _, err := reg.RegisterPeer(rec, "net1", 0); err != nil {
			t.Fatalf("RegisterPeer p1: %v", err)
		}

		// Set AssignedAddrs to nil AND NextIP to "garbage"
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
			netRec.NextIP = "garbage"
			updated, err := json.Marshal(netRec)
			if err != nil {
				return err
			}
			return nb.Put([]byte("net1"), updated)
		})
		if err != nil {
			t.Fatalf("manual DB update: %v", err)
		}

		reg.Close()
	}

	// Phase 2: Reopen registry (simulating upgrade), register p2.
	{
		reg, err := NewRegistry(dbPath)
		if err != nil {
			t.Fatalf("NewRegistry (reopen): %v", err)
		}
		defer reg.Close()

		rec := peerRecord{
			ID:            "p2",
			Name:          "Peer 2",
			Ed25519Public: base64.StdEncoding.EncodeToString([]byte("pub2xxxxxxxxxxxxxxxxxxxxxxxxxx")),
			X25519Public:  base64.StdEncoding.EncodeToString([]byte("x255192xxxxxxxxxxxxxxxxxxxxxxxxx")),
			RegisteredAt:  0,
			LastSeen:      0,
		}
		vpnAddr, err := reg.RegisterPeer(rec, "net1", 0)
		if err != nil {
			t.Fatalf("RegisterPeer p2: %v", err)
		}

		// p2 gets the oldest freed address (10.0.0.2)
		if vpnAddr.String() != "10.0.0.2" {
			t.Errorf("p2 got %s, want 10.0.0.2 (oldest freed)", vpnAddr)
		}

		// Verify warning was logged
		output := buf.String()
		if !strings.Contains(output, "network \"net1\" has invalid or empty NextIP") {
			t.Errorf("expected warning about invalid NextIP, got: %s", output)
		}
		if !strings.Contains(output, "garbage") {
			t.Errorf("expected warning to contain the bad value 'garbage', got: %s", output)
		}

		// Verify AssignedAddrs: p1 (10.0.0.1) = 0, p2 (10.0.0.2) = 0
		// All other hosts in CIDR should be marked freed (timestamp 1)
		err = reg.db.View(func(tx *bolt.Tx) error {
			nb := tx.Bucket(bucketNetworks)
			netData := nb.Get([]byte("net1"))
			if netData == nil {
				return fmt.Errorf("network not found")
			}
			var netRec networkRecord
			if err := json.Unmarshal(netData, &netRec); err != nil {
				return err
			}
			if netRec.AssignedAddrs == nil {
				t.Errorf("AssignedAddrs is nil after migration")
			} else {
				if netRec.AssignedAddrs["10.0.0.1"] != 0 {
					t.Errorf("10.0.0.1 should be assigned (0), got %d", netRec.AssignedAddrs["10.0.0.1"])
				}
				if netRec.AssignedAddrs["10.0.0.2"] != 0 {
					t.Errorf("10.0.0.2 should be assigned (0), got %d", netRec.AssignedAddrs["10.0.0.2"])
				}
				// Check a few other addresses are marked freed
				if netRec.AssignedAddrs["10.0.0.3"] != 1 {
					t.Errorf("10.0.0.3 should be freed (1), got %d", netRec.AssignedAddrs["10.0.0.3"])
				}
				if netRec.AssignedAddrs["10.0.0.254"] != 1 {
					t.Errorf("10.0.0.254 should be freed (1), got %d", netRec.AssignedAddrs["10.0.0.254"])
				}
				// Broadcast address (10.0.0.255) should not be in the map
				if _, ok := netRec.AssignedAddrs["10.0.0.255"]; ok {
					t.Errorf("10.0.0.255 (broadcast) should not be in AssignedAddrs")
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("verify AssignedAddrs: %v", err)
		}
	}
}

// TestRegistry_AddressAllocation_PreUpgradeMigration_ValidNextIPOutsideCIDR tests the case
// where a pre-upgrade database has a valid NextIP that is outside the network CIDR.
// The migration should log a warning and fall back to marking all non-held host
// addresses as freed with timestamp 1, so allocation reuses addresses oldest-first.
func TestRegistry_AddressAllocation_PreUpgradeMigration_ValidNextIPOutsideCIDR(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := tmpDir + "/test.db"

	// Capture log output
	var buf strings.Builder
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })

	// Phase 1: Create network, register p1, p2, then remove p2.
	// Simulate pre-upgrade with a valid NextIP that is outside the CIDR (numerically before).
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

		for i := 1; i <= 2; i++ {
			rec := peerRecord{
				ID:            fmt.Sprintf("p%d", i),
				Name:          fmt.Sprintf("Peer %d", i),
				Ed25519Public: base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("pub%dxxxxxxxxxxxxxxxxxxxxxxxxx", i))),
				X25519Public:  base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("x25519%dxxxxxxxxxxxxxxxxxxxxxxxx", i))),
				RegisteredAt:  0,
				LastSeen:      0,
			}
			if _, err := reg.RegisterPeer(rec, "net1", 0); err != nil {
				t.Fatalf("RegisterPeer p%d: %v", i, err)
			}
		}

		// Remove p2 (10.0.0.2)
		if _, err := reg.RemovePeer("p2"); err != nil {
			t.Fatalf("RemovePeer p2: %v", err)
		}

		// Set AssignedAddrs to nil AND NextIP to a valid IP outside the CIDR
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
			netRec.NextIP = "192.168.1.1" // Outside 10.0.0.0/24
			updated, err := json.Marshal(netRec)
			if err != nil {
				return err
			}
			return nb.Put([]byte("net1"), updated)
		})
		if err != nil {
			t.Fatalf("manual DB update: %v", err)
		}

		reg.Close()
	}

	// Phase 2: Reopen registry (simulating upgrade), register p3.
	// With NextIP outside CIDR fallback, all non-held addresses are marked freed (timestamp 1).
	// Allocation picks the oldest freed (lowest address): 10.0.0.2.
	{
		reg, err := NewRegistry(dbPath)
		if err != nil {
			t.Fatalf("NewRegistry (reopen): %v", err)
		}
		defer reg.Close()

		rec := peerRecord{
			ID:            "p3",
			Name:          "Peer 3",
			Ed25519Public: base64.StdEncoding.EncodeToString([]byte("pub3xxxxxxxxxxxxxxxxxxxxxxxxxx")),
			X25519Public:  base64.StdEncoding.EncodeToString([]byte("x255193xxxxxxxxxxxxxxxxxxxxxxxxx")),
			RegisteredAt:  0,
			LastSeen:      0,
		}
		vpnAddr, err := reg.RegisterPeer(rec, "net1", 0)
		if err != nil {
			t.Fatalf("RegisterPeer p3: %v", err)
		}

		// p3 gets the oldest freed address (10.0.0.2) because all non-held
		// addresses were marked freed with timestamp 1.
		if vpnAddr.String() != "10.0.0.2" {
			t.Errorf("p3 got %s, want 10.0.0.2 (oldest freed)", vpnAddr)
		}

		// Verify warning was logged
		output := buf.String()
		if !strings.Contains(output, "network \"net1\" has invalid or empty NextIP") {
			t.Errorf("expected warning about NextIP outside CIDR, got: %s", output)
		}
		if !strings.Contains(output, "192.168.1.1") {
			t.Errorf("expected warning to contain the bad value '192.168.1.1', got: %s", output)
		}

		// Verify AssignedAddrs: p1 (10.0.0.1) = 0, p2 (10.0.0.2) = 0 (now assigned to p3),
		// all other hosts in CIDR (except broadcast) should be marked freed (timestamp 1)
		err = reg.db.View(func(tx *bolt.Tx) error {
			nb := tx.Bucket(bucketNetworks)
			netData := nb.Get([]byte("net1"))
			if netData == nil {
				return fmt.Errorf("network not found")
			}
			var netRec networkRecord
			if err := json.Unmarshal(netData, &netRec); err != nil {
				return err
			}
			if netRec.AssignedAddrs == nil {
				t.Errorf("AssignedAddrs is nil after migration")
			} else {
				if netRec.AssignedAddrs["10.0.0.1"] != 0 {
					t.Errorf("10.0.0.1 should be assigned (0), got %d", netRec.AssignedAddrs["10.0.0.1"])
				}
				if netRec.AssignedAddrs["10.0.0.2"] != 0 {
					t.Errorf("10.0.0.2 should be assigned (0), got %d", netRec.AssignedAddrs["10.0.0.2"])
				}
				// Check a few other addresses are marked freed
				if netRec.AssignedAddrs["10.0.0.3"] != 1 {
					t.Errorf("10.0.0.3 should be freed (1), got %d", netRec.AssignedAddrs["10.0.0.3"])
				}
				if netRec.AssignedAddrs["10.0.0.4"] != 1 {
					t.Errorf("10.0.0.4 should be freed (1), got %d", netRec.AssignedAddrs["10.0.0.4"])
				}
				if netRec.AssignedAddrs["10.0.0.254"] != 1 {
					t.Errorf("10.0.0.254 should be freed (1), got %d", netRec.AssignedAddrs["10.0.0.254"])
				}
				// Broadcast address (10.0.0.255) should not be in the map
				if _, ok := netRec.AssignedAddrs["10.0.0.255"]; ok {
					t.Errorf("10.0.0.255 (broadcast) should not be in AssignedAddrs")
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("verify AssignedAddrs: %v", err)
		}
	}
}

// TestRegistry_AddressAllocation_PreUpgradeMigration_LargeCIDRFallback tests the case
// where a pre-upgrade database has an empty NextIP and a CIDR larger than 65536 hosts.
// The migration should log a warning and leave AssignedAddrs with only the held addresses.
func TestRegistry_AddressAllocation_PreUpgradeMigration_LargeCIDRFallback(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := tmpDir + "/test.db"

	// Capture log output
	var buf strings.Builder
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })

	// Phase 1: Create network with /15 CIDR (131070 usable hosts), register p1, then simulate pre-upgrade with empty NextIP.
	{
		reg, err := NewRegistry(dbPath)
		if err != nil {
			t.Fatalf("NewRegistry: %v", err)
		}

		// /15: 131070 usable hosts (exceeds 65536 cap)
		cidr := netip.MustParsePrefix("10.0.0.0/15")
		net := coordcore.Network{ID: "net1", CIDR: cidr, Name: "Test Network"}
		if err := reg.CreateNetwork(net, "acc1"); err != nil {
			t.Fatalf("CreateNetwork: %v", err)
		}

		rec := peerRecord{
			ID:            "p1",
			Name:          "Peer 1",
			Ed25519Public: base64.StdEncoding.EncodeToString([]byte("pub1xxxxxxxxxxxxxxxxxxxxxxxxx")),
			X25519Public:  base64.StdEncoding.EncodeToString([]byte("x255191xxxxxxxxxxxxxxxxxxxxxxxx")),
			RegisteredAt:  0,
			LastSeen:      0,
		}
		if _, err := reg.RegisterPeer(rec, "net1", 0); err != nil {
			t.Fatalf("RegisterPeer p1: %v", err)
		}

		// Set AssignedAddrs to nil AND NextIP to empty string
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
			netRec.NextIP = ""
			updated, err := json.Marshal(netRec)
			if err != nil {
				return err
			}
			return nb.Put([]byte("net1"), updated)
		})
		if err != nil {
			t.Fatalf("manual DB update: %v", err)
		}

		reg.Close()
	}

	// Phase 2: Reopen registry (simulating upgrade), register p2.
	// With large CIDR and empty NextIP, the fallback should be capped.
	// Only held addresses (p1 at 10.0.0.1) should be in AssignedAddrs with timestamp 0.
	// No freed marks should be added.
	{
		reg, err := NewRegistry(dbPath)
		if err != nil {
			t.Fatalf("NewRegistry (reopen): %v", err)
		}
		defer reg.Close()

		rec := peerRecord{
			ID:            "p2",
			Name:          "Peer 2",
			Ed25519Public: base64.StdEncoding.EncodeToString([]byte("pub2xxxxxxxxxxxxxxxxxxxxxxxxxx")),
			X25519Public:  base64.StdEncoding.EncodeToString([]byte("x255192xxxxxxxxxxxxxxxxxxxxxxxxx")),
			RegisteredAt:  0,
			LastSeen:      0,
		}
		vpnAddr, err := reg.RegisterPeer(rec, "net1", 0)
		if err != nil {
			t.Fatalf("RegisterPeer p2: %v", err)
		}

		// p2 gets the next never-used address (10.0.0.2)
		if vpnAddr.String() != "10.0.0.2" {
			t.Errorf("p2 got %s, want 10.0.0.2 (next never-used)", vpnAddr)
		}

		// Verify warning was logged about large CIDR
		output := buf.String()
		if !strings.Contains(output, "network \"net1\" has invalid or empty NextIP") {
			t.Errorf("expected warning about empty NextIP, got: %s", output)
		}
		if !strings.Contains(output, "exceeds 65536 host limit") {
			t.Errorf("expected warning about CIDR exceeding 65536 host limit, got: %s", output)
		}

		// Verify AssignedAddrs only has held addresses (no freed marks)
		err = reg.db.View(func(tx *bolt.Tx) error {
			nb := tx.Bucket(bucketNetworks)
			netData := nb.Get([]byte("net1"))
			if netData == nil {
				return fmt.Errorf("network not found")
			}
			var netRec networkRecord
			if err := json.Unmarshal(netData, &netRec); err != nil {
				return err
			}
			if netRec.AssignedAddrs == nil {
				t.Errorf("AssignedAddrs is nil after migration")
			} else {
				// Only held addresses should be present (timestamp 0)
				if netRec.AssignedAddrs["10.0.0.1"] != 0 {
					t.Errorf("10.0.0.1 should be assigned (0), got %d", netRec.AssignedAddrs["10.0.0.1"])
				}
				if netRec.AssignedAddrs["10.0.0.2"] != 0 {
					t.Errorf("10.0.0.2 should be assigned (0), got %d", netRec.AssignedAddrs["10.0.0.2"])
				}
				// No freed marks should exist
				if len(netRec.AssignedAddrs) != 2 {
					t.Errorf("expected only 2 entries in AssignedAddrs (held addresses only), got %d: %v", len(netRec.AssignedAddrs), netRec.AssignedAddrs)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("verify AssignedAddrs: %v", err)
		}
	}
}
