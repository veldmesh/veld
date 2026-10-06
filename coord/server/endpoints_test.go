// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	coordcore "github.com/veldmesh/veld/coord/core"
)

// registerEndpointPeer registers a peer in network "net1" with the given
// endpoint, failing the test on error.
func registerEndpointPeer(t *testing.T, reg *Registry, id, endpoint string, lastSeen int64) {
	t.Helper()
	rec := peerRecord{
		ID:            id,
		Name:          id,
		Ed25519Public: "dGVzdA==",
		X25519Public:  "dGVzdA==",
		Endpoint:      endpoint,
		LastSeen:      lastSeen,
		RegisteredAt:  lastSeen,
	}
	if _, err := reg.RegisterPeer(rec, "net1", 0); err != nil {
		t.Fatalf("RegisterPeer %s: %v", id, err)
	}
}

// inMemoryEndpoint returns the endpoint the registry currently holds in
// memory for peerID ("" when none is tracked).
func inMemoryEndpoint(t *testing.T, reg *Registry, peerID string) string {
	t.Helper()
	reg.endpointsMu.Lock()
	defer reg.endpointsMu.Unlock()
	return reg.endpoints[peerID]
}

// rawPersistedPeers decodes every record in the on-disk peers bucket as
// generic JSON so tests can assert exactly what is (not) persisted.
func rawPersistedPeers(t *testing.T, reg *Registry) []map[string]any {
	t.Helper()
	var rows []map[string]any
	err := reg.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketPeers).ForEach(func(k, v []byte) error {
			var row map[string]any
			if err := json.Unmarshal(v, &row); err != nil {
				return err
			}
			rows = append(rows, row)
			return nil
		})
	})
	if err != nil {
		t.Fatalf("read peers bucket: %v", err)
	}
	return rows
}

// newEndpointTestDB opens a registry at the given path with network "net1"
// (10.0.0.0/24) pre-created, failing the test on error. On reopen (restart
// scenarios) the network already exists, which is fine.
func newEndpointTestDB(t *testing.T, path string) *Registry {
	t.Helper()
	reg, err := NewRegistry(path)
	if err != nil {
		t.Fatalf("NewRegistry %s: %v", path, err)
	}
	cidr := netip.MustParsePrefix("10.0.0.0/24")
	net := coordcore.Network{ID: "net1", CIDR: cidr, Name: "Test Network"}
	if _, _, err := reg.GetNetwork("net1"); err != nil {
		if err := reg.CreateNetwork(net, "acc1"); err != nil {
			t.Fatalf("CreateNetwork: %v", err)
		}
	}
	return reg
}

func TestRegistry_EndpointNeverPersisted(t *testing.T) {
	reg := newSweepTestRegistry(t)

	registerEndpointPeer(t, reg, "peer1", "203.0.113.7:51820", time.Now().Unix())
	if err := reg.UpdateEndpoint("peer1", "198.51.100.9:12345"); err != nil {
		t.Fatalf("UpdateEndpoint: %v", err)
	}

	// Endpoints are still served to peers — from memory.
	peers, err := reg.ListPeers("net1")
	if err != nil {
		t.Fatalf("ListPeers: %v", err)
	}
	if len(peers) != 1 || peers[0].Endpoint != "198.51.100.9:12345" {
		t.Fatalf("ListPeers: got %+v, want one peer with endpoint 198.51.100.9:12345", peers)
	}

	// The persisted record never contains the endpoint.
	stored, err := reg.GetPeer("peer1")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if stored.Endpoint != "" {
		t.Errorf("persisted record contains endpoint %q", stored.Endpoint)
	}

	// Neither do the raw on-disk bytes.
	for _, row := range rawPersistedPeers(t, reg) {
		if ep, _ := row["endpoint"].(string); ep != "" {
			t.Errorf("on-disk record contains endpoint %q", ep)
		}
	}
}

func TestRegistry_ListPeers_ServesEndpointsFromMemory(t *testing.T) {
	reg := newSweepTestRegistry(t)
	now := time.Now().Unix()

	registerEndpointPeer(t, reg, "p1", "10.1.1.1:1111", now)
	registerEndpointPeer(t, reg, "p2", "10.2.2.2:2222", now)

	peers, err := reg.ListPeers("net1")
	if err != nil {
		t.Fatalf("ListPeers: %v", err)
	}
	if len(peers) != 2 {
		t.Fatalf("ListPeers: got %d peers, want 2", len(peers))
	}
	for _, p := range peers {
		want := map[string]string{"p1": "10.1.1.1:1111", "p2": "10.2.2.2:2222"}[p.ID]
		if p.Endpoint != want {
			t.Errorf("peer %s endpoint: got %q, want %q", p.ID, p.Endpoint, want)
		}
	}

	// An endpoint update is reflected in what peers are served.
	if err := reg.UpdateEndpoint("p1", "10.3.3.3:3333"); err != nil {
		t.Fatalf("UpdateEndpoint: %v", err)
	}
	peers, err = reg.ListPeers("net1")
	if err != nil {
		t.Fatalf("ListPeers: %v", err)
	}
	for _, p := range peers {
		if p.ID == "p1" && p.Endpoint != "10.3.3.3:3333" {
			t.Errorf("peer p1 endpoint after update: got %q, want 10.3.3.3:3333", p.Endpoint)
		}
	}
}

func TestRegistry_RemovePeer_DropsInMemoryEndpoint(t *testing.T) {
	reg := newSweepTestRegistry(t)

	registerEndpointPeer(t, reg, "p1", "10.1.1.1:1111", time.Now().Unix())
	if got := inMemoryEndpoint(t, reg, "p1"); got != "10.1.1.1:1111" {
		t.Fatalf("in-memory endpoint before leave: got %q, want 10.1.1.1:1111", got)
	}

	if _, err := reg.RemovePeer("p1"); err != nil {
		t.Fatalf("RemovePeer: %v", err)
	}
	if got := inMemoryEndpoint(t, reg, "p1"); got != "" {
		t.Errorf("in-memory endpoint after leave: got %q, want empty", got)
	}
}

func TestRegistry_SweepStalePeers_DropsInMemoryEndpoint(t *testing.T) {
	reg := newSweepTestRegistry(t)
	now := time.Now().Unix()

	registerEndpointPeer(t, reg, "fresh", "10.1.1.1:1111", now)
	registerEndpointPeer(t, reg, "stale", "10.2.2.2:2222", now-int64((48*time.Hour).Seconds()))

	removed, err := reg.SweepStalePeers(24*time.Hour, nil)
	if err != nil {
		t.Fatalf("SweepStalePeers: %v", err)
	}
	if len(removed) != 1 || removed[0].ID != "stale" {
		t.Fatalf("sweep removed: %+v, want exactly peer \"stale\"", removed)
	}

	if got := inMemoryEndpoint(t, reg, "stale"); got != "" {
		t.Errorf("swept peer's endpoint still in memory: %q", got)
	}
	if got := inMemoryEndpoint(t, reg, "fresh"); got != "10.1.1.1:1111" {
		t.Errorf("fresh peer's endpoint lost on sweep: got %q, want 10.1.1.1:1111", got)
	}

	// The surviving peer is still served with its endpoint.
	peers, err := reg.ListPeers("net1")
	if err != nil {
		t.Fatalf("ListPeers: %v", err)
	}
	if len(peers) != 1 || peers[0].Endpoint != "10.1.1.1:1111" {
		t.Errorf("ListPeers after sweep: %+v, want one peer with endpoint 10.1.1.1:1111", peers)
	}
}

func TestRegistry_EndpointsEmptyAfterRestartUntilReRegistration(t *testing.T) {
	path := t.TempDir() + "/test.db"

	reg := newEndpointTestDB(t, path)
	registerEndpointPeer(t, reg, "p1", "10.1.1.1:1111", time.Now().Unix())

	peers, err := reg.ListPeers("net1")
	if err != nil {
		t.Fatalf("ListPeers: %v", err)
	}
	if len(peers) != 1 || peers[0].Endpoint != "10.1.1.1:1111" {
		t.Fatalf("ListPeers before restart: %+v, want one peer with endpoint 10.1.1.1:1111", peers)
	}
	if err := reg.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// After a restart nothing is served until daemons re-register. Daemons
	// re-register whenever they (re)connect to the coord server, so the
	// endpoint is re-learned without any extra protocol.
	reg2 := newEndpointTestDB(t, path)
	defer func() { _ = reg2.Close() }()

	peers, err = reg2.ListPeers("net1")
	if err != nil {
		t.Fatalf("ListPeers after restart: %v", err)
	}
	if len(peers) != 1 {
		t.Fatalf("ListPeers after restart: got %d peers, want 1 (peer record persists)", len(peers))
	}
	if peers[0].Endpoint != "" {
		t.Errorf("endpoint served after restart before re-registration: got %q, want empty", peers[0].Endpoint)
	}

	registerEndpointPeer(t, reg2, "p1", "10.1.1.1:1111", time.Now().Unix())
	peers, err = reg2.ListPeers("net1")
	if err != nil {
		t.Fatalf("ListPeers after re-registration: %v", err)
	}
	if len(peers) != 1 || peers[0].Endpoint != "10.1.1.1:1111" {
		t.Errorf("endpoint not re-learned on re-registration: %+v", peers)
	}
}

func TestRegistry_MigrationBlanksPersistedEndpoints(t *testing.T) {
	path := t.TempDir() + "/test.db"

	reg := newEndpointTestDB(t, path)

	// Write a legacy record the way an older build did: with a persisted
	// endpoint.
	legacy := peerRecord{
		ID:            "legacy",
		NetworkID:     "net1",
		Name:          "legacy",
		VPNAddr:       "10.0.0.1",
		Ed25519Public: "dGVzdA==",
		X25519Public:  "dGVzdA==",
		Endpoint:      "192.0.2.1:51820",
		RegisteredAt:  time.Now().Unix(),
		LastSeen:      time.Now().Unix(),
	}
	data, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("marshal legacy record: %v", err)
	}
	if err := reg.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketPeers).Put([]byte(legacy.ID), data)
	}); err != nil {
		t.Fatalf("write legacy record: %v", err)
	}
	if err := reg.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Startup migration blanks the endpoint and keeps everything else.
	reg2 := newEndpointTestDB(t, path)
	rec, err := reg2.GetPeer("legacy")
	if err != nil {
		t.Fatalf("GetPeer after migration: %v", err)
	}
	if rec.Endpoint != "" {
		t.Errorf("migration left endpoint in persisted record: %q", rec.Endpoint)
	}
	if rec.Name != "legacy" || rec.VPNAddr != "10.0.0.1" || rec.NetworkID != "net1" {
		t.Errorf("migration damaged legacy record: %+v", rec)
	}
	if got := inMemoryEndpoint(t, reg2, "legacy"); got != "" {
		t.Errorf("migrated endpoint resurrected in memory: %q", got)
	}
	if err := reg2.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// The migration is idempotent: reopening changes nothing.
	reg3 := newEndpointTestDB(t, path)
	defer func() { _ = reg3.Close() }()
	rec, err = reg3.GetPeer("legacy")
	if err != nil {
		t.Fatalf("GetPeer after second migration: %v", err)
	}
	if rec.Endpoint != "" {
		t.Errorf("second migration changed endpoint to %q", rec.Endpoint)
	}
	if rec.Name != "legacy" || rec.VPNAddr != "10.0.0.1" {
		t.Errorf("second migration damaged record: %+v", rec)
	}
}

func TestRegistry_PersistedLastSeenRoundedToHour(t *testing.T) {
	reg := newSweepTestRegistry(t)
	now := time.Now().Unix()

	registerEndpointPeer(t, reg, "p1", "10.1.1.1:1111", now)

	rec, err := reg.GetPeer("p1")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if rec.LastSeen%3600 != 0 {
		t.Errorf("persisted LastSeen not rounded to the hour: got %d", rec.LastSeen)
	}
	if rec.LastSeen > now {
		t.Errorf("persisted LastSeen rounded up: got %d, registered at %d", rec.LastSeen, now)
	}

	// Endpoint updates and heartbeats keep the persisted value coarse.
	if err := reg.UpdateEndpoint("p1", "10.9.9.9:9999"); err != nil {
		t.Fatalf("UpdateEndpoint: %v", err)
	}
	if err := reg.TouchPeer("p1"); err != nil {
		t.Fatalf("TouchPeer: %v", err)
	}
	rec, err = reg.GetPeer("p1")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if rec.LastSeen%3600 != 0 {
		t.Errorf("LastSeen after touch not rounded to the hour: got %d", rec.LastSeen)
	}

	// Re-registration (idempotent path) rounds before persisting too.
	registerEndpointPeer(t, reg, "p1", "10.1.1.1:1111", now+1800)
	rec, err = reg.GetPeer("p1")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if rec.LastSeen%3600 != 0 {
		t.Errorf("LastSeen after re-registration not rounded to the hour: got %d", rec.LastSeen)
	}
}
