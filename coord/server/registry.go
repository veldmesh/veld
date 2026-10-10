// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
	coordcore "github.com/veldmesh/veld/coord/core"
)

// Registry is a bbolt-backed persistent store for networks and peers.
type Registry struct {
	db *bolt.DB

	// endpoints holds each peer's last advertised public endpoint
	// ("ip:port") in memory only. Endpoints are deliberately never
	// written to disk: after a restart the map starts empty and is
	// re-learned as daemons re-register (they re-register whenever
	// they reconnect to the coord server).
	endpointsMu sync.Mutex
	endpoints   map[string]string
}

// Bucket names
var (
	bucketNetworks = []byte("networks")
	bucketPeers    = []byte("peers")
)

// networkRecord is the on-disk representation of a network.
type networkRecord struct {
	ID           string `json:"id"`
	CIDR         string `json:"cidr"`
	Name         string `json:"name"`
	AccountID    string `json:"account_id"`
	NextIP       string `json:"next_ip"` // next IP to assign (e.g. "10.0.0.2")
	MachineCount int    `json:"machine_count"`
	CreatedAt    int64  `json:"created_at"`
}

// peerRecord is the on-disk representation of a peer.
type peerRecord struct {
	ID            string   `json:"id"`    // Ed25519 hex
	NetworkID     string   `json:"network_id"`
	Name          string   `json:"name"`
	VPNAddr       string   `json:"vpn_addr"`
	Ed25519Public string   `json:"ed25519_public"` // base64
	X25519Public  string   `json:"x25519_public"`  // base64
	Endpoint      string   `json:"endpoint"`       // "ip:port"; in-memory only, persisted as ""
	SubnetRoutes  []string `json:"subnet_routes"` // CIDR prefixes; nil = none
	LastSeen      int64    `json:"last_seen"`      // unix seconds, rounded to the hour on disk
	RegisteredAt  int64    `json:"registered_at"`
}

// lastSeenGranularity is the coarseness, in seconds, of persisted
// last-seen timestamps: they are rounded down to the hour so the
// registry does not retain more detail about a machine's online
// activity than the TTL sweep needs.
const lastSeenGranularity = int64(time.Hour / time.Second)

// roundToHour rounds a unix timestamp in seconds down to the hour. Zero
// (never seen) is preserved: the sweep treats it as "no heartbeat" and
// falls back to RegisteredAt.
// Callers should pass the raw, unrounded timestamp (e.g. time.Now().Unix());
// the function is idempotent, so an already hour-rounded value — as can
// happen on re-registration — passes through unchanged at the cost of one
// redundant modulo.
func roundToHour(secs int64) int64 {
	if secs <= 0 {
		return secs
	}
	return secs - secs%lastSeenGranularity
}

// NewRegistry opens or creates a bbolt database at path and ensures buckets
// exist. As a one-time, idempotent migration it also blanks the endpoint
// field of any peer record persisted by an older build: endpoints are now
// kept in memory only and are re-learned when daemons re-register.
func NewRegistry(path string) (*Registry, error) {
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open bbolt: %w", err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{bucketNetworks, bucketPeers} {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return err
			}
		}
		return blankPersistedEndpoints(tx)
	})
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init buckets: %w", err)
	}
	return &Registry{db: db, endpoints: make(map[string]string)}, nil
}

// blankPersistedEndpoints is the startup half of "endpoints live in memory
// only": older builds persisted each peer's public endpoint, and those
// stored values are blanked here. It is idempotent — records written by
// current code never carry an endpoint, so the rewrite becomes a no-op.
func blankPersistedEndpoints(tx *bolt.Tx) error {
	pb := tx.Bucket(bucketPeers)
	// Collect first; mutating a bucket mid-cursor is unsafe.
	var legacy []peerRecord
	if err := pb.ForEach(func(_, v []byte) error {
		var rec peerRecord
		if err := json.Unmarshal(v, &rec); err != nil {
			return nil // skip undecodable legacy rows; never block startup
		}
		if rec.Endpoint != "" {
			legacy = append(legacy, rec)
		}
		return nil
	}); err != nil {
		return err
	}
	for _, rec := range legacy {
		rec.Endpoint = ""
		updated, err := json.Marshal(rec)
		if err != nil {
			continue // leave the row untouched rather than fail startup
		}
		if err := pb.Put([]byte(rec.ID), updated); err != nil {
			return err
		}
	}
	return nil
}

// setEndpoint records a peer's advertised endpoint in memory only. It has
// no failure path — the map is created in NewRegistry and every access
// holds endpointsMu, so the plain assignment cannot panic — which is why
// callers commit their bbolt write first and call this only on success:
// a failed write never touches the map, and a committed write cannot be
// followed by a failure here, so the persisted records and the in-memory
// map cannot diverge.
func (r *Registry) setEndpoint(peerID, endpoint string) {
	r.endpointsMu.Lock()
	defer r.endpointsMu.Unlock()
	r.endpoints[peerID] = endpoint
}

// dropEndpoint forgets a peer's in-memory endpoint (peer left or was swept).
func (r *Registry) dropEndpoint(peerID string) {
	r.endpointsMu.Lock()
	defer r.endpointsMu.Unlock()
	delete(r.endpoints, peerID)
}

// applyEndpoints fills each record's Endpoint field from the in-memory map.
func (r *Registry) applyEndpoints(peers []peerRecord) {
	r.endpointsMu.Lock()
	defer r.endpointsMu.Unlock()
	for i := range peers {
		peers[i].Endpoint = r.endpoints[peers[i].ID]
	}
}

// Close releases the bbolt database.
func (r *Registry) Close() error { return r.db.Close() }

// CreateNetwork stores a new network. Returns error if networkID already exists.
func (r *Registry) CreateNetwork(net coordcore.Network, accountID string) error {
	return r.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketNetworks)
		key := []byte(net.ID)
		if b.Get(key) != nil {
			return fmt.Errorf("network %q already exists", net.ID)
		}
		// First assignable IP is network address + 1 (skip network address itself)
		firstIP := nextIPAfterNetwork(net.CIDR)
		rec := networkRecord{
			ID:           net.ID,
			CIDR:         net.CIDR.String(),
			Name:         net.Name,
			AccountID:    accountID,
			NextIP:       firstIP.String(),
			MachineCount: 0,
			CreatedAt:    time.Now().Unix(),
		}
		data, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		return b.Put(key, data)
	})
}

// GetNetwork returns the network record by ID.
func (r *Registry) GetNetwork(networkID string) (coordcore.Network, string, error) {
	var net coordcore.Network
	var accountID string
	err := r.db.View(func(tx *bolt.Tx) error {
		data := tx.Bucket(bucketNetworks).Get([]byte(networkID))
		if data == nil {
			return fmt.Errorf("network %q not found", networkID)
		}
		var rec networkRecord
		if err := json.Unmarshal(data, &rec); err != nil {
			return err
		}
		cidr, err := netip.ParsePrefix(rec.CIDR)
		if err != nil {
			return err
		}
		net = coordcore.Network{ID: rec.ID, CIDR: cidr, Name: rec.Name}
		accountID = rec.AccountID
		return nil
	})
	return net, accountID, err
}

// NetworkMachineCount returns the current registered machine count for a network.
func (r *Registry) NetworkMachineCount(networkID string) (int, error) {
	var count int
	err := r.db.View(func(tx *bolt.Tx) error {
		data := tx.Bucket(bucketNetworks).Get([]byte(networkID))
		if data == nil {
			return fmt.Errorf("network %q not found", networkID)
		}
		var rec networkRecord
		if err := json.Unmarshal(data, &rec); err != nil {
			return err
		}
		count = rec.MachineCount
		return nil
	})
	return count, err
}

// ErrMachineLimit is returned by RegisterPeer when the network is at capacity.
var ErrMachineLimit = fmt.Errorf("machine limit reached")

// ErrPeerIDTaken is returned by RegisterPeer when the peer ID (the Ed25519
// public key) is already registered in a different network: peer IDs live
// in one global namespace, so an existing registration is never moved to
// another network or overwritten.
var ErrPeerIDTaken = fmt.Errorf("peer id already registered in another network")

// ErrPeerKeyMismatch is returned by RegisterPeer when a same-network
// re-registration presents a different X25519 public key than the one
// stored for the peer. Re-registering daemons keep their identity; key
// rotation needs a signed flow, so the stored key is never overwritten.
var ErrPeerKeyMismatch = fmt.Errorf("peer x25519 public key mismatch")

// RegisterPeer adds a peer to the registry and returns its assigned VPN address.
// maxMachines is checked atomically inside the write transaction; pass 0 for unlimited.
// Idempotent: if the peer is already registered in the same network, updates
// mutable fields (name, last_seen) and returns the existing IP without
// incrementing the machine count. This allows daemons to reconnect cleanly.
// The peer ID (the Ed25519 public key) is globally unique: an ID already
// registered in another network is rejected with ErrPeerIDTaken, and a
// same-network re-registration presenting a different X25519 key than the
// stored one is rejected with ErrPeerKeyMismatch. Both rejections change
// nothing — no record, endpoint, machine count or JOIN event.
// The peer's endpoint is kept in memory only — it is never persisted.
// Pass p.LastSeen as the raw, unrounded unix timestamp; it is rounded down
// to the hour before being persisted.
func (r *Registry) RegisterPeer(p peerRecord, networkID string, maxMachines int) (netip.Addr, error) {
	endpoint := p.Endpoint
	p.Endpoint = "" // endpoints are in-memory only; never persist
	var assigned netip.Addr
	err := r.db.Update(func(tx *bolt.Tx) error {
		pb := tx.Bucket(bucketPeers)

		// The peer ID is globally unique. If it already exists, only a
		// same-network re-registration presenting the same X25519 key is
		// accepted; anything else is rejected without touching the stored
		// record.
		if existing := pb.Get([]byte(p.ID)); existing != nil {
			var rec peerRecord
			if err := json.Unmarshal(existing, &rec); err != nil {
				return fmt.Errorf("peer %q exists but its record is unreadable: %w", p.ID, err)
			}
			if rec.NetworkID != networkID {
				return ErrPeerIDTaken
			}
			if rec.X25519Public != p.X25519Public {
				return ErrPeerKeyMismatch
			}
			addr, err := netip.ParseAddr(rec.VPNAddr)
			if err != nil {
				return fmt.Errorf("peer %q has unreadable vpn_addr %q: %w", p.ID, rec.VPNAddr, err)
			}
			rec.LastSeen = roundToHour(p.LastSeen)
			rec.Name = p.Name
			rec.SubnetRoutes = p.SubnetRoutes
			updated, err := json.Marshal(rec)
			if err != nil {
				return err
			}
			if err := pb.Put([]byte(p.ID), updated); err != nil {
				return err
			}
			assigned = addr
			return nil
		}

		// New peer: check limit, assign next IP, increment machine count — all atomic.
		nb := tx.Bucket(bucketNetworks)
		netData := nb.Get([]byte(networkID))
		if netData == nil {
			return fmt.Errorf("network %q not found", networkID)
		}
		var netRec networkRecord
		if err := json.Unmarshal(netData, &netRec); err != nil {
			return err
		}

		if maxMachines > 0 && netRec.MachineCount >= maxMachines {
			return ErrMachineLimit
		}

		ip, err := netip.ParseAddr(netRec.NextIP)
		if err != nil {
			return fmt.Errorf("parse next_ip: %w", err)
		}
		assigned = ip

		cidr, _ := netip.ParsePrefix(netRec.CIDR)
		next := ip.Next()
		if !cidr.Contains(next) {
			return fmt.Errorf("network %q address space exhausted", networkID)
		}
		netRec.NextIP = next.String()
		netRec.MachineCount++

		updatedNet, err := json.Marshal(netRec)
		if err != nil {
			return err
		}
		if err := nb.Put([]byte(networkID), updatedNet); err != nil {
			return err
		}

		p.VPNAddr = assigned.String()
		p.NetworkID = networkID
		p.LastSeen = roundToHour(p.LastSeen)
		data, err := json.Marshal(p)
		if err != nil {
			return err
		}
		return pb.Put([]byte(p.ID), data)
	})
	if err == nil {
		r.setEndpoint(p.ID, endpoint)
	}
	return assigned, err
}

// GetPeer returns the persisted peer record by Ed25519 ID (hex string). The
// record's Endpoint is always empty: endpoints live in memory only and are
// served through ListPeers.
func (r *Registry) GetPeer(peerID string) (peerRecord, error) {
	var rec peerRecord
	err := r.db.View(func(tx *bolt.Tx) error {
		data := tx.Bucket(bucketPeers).Get([]byte(peerID))
		if data == nil {
			return fmt.Errorf("peer %q not found", peerID)
		}
		return json.Unmarshal(data, &rec)
	})
	return rec, err
}

// ListPeers returns all peers in a network, with each peer's current
// endpoint filled in from the in-memory endpoint map.
func (r *Registry) ListPeers(networkID string) ([]peerRecord, error) {
	var peers []peerRecord
	err := r.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketPeers).ForEach(func(k, v []byte) error {
			var rec peerRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			if rec.NetworkID == networkID {
				peers = append(peers, rec)
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	r.applyEndpoints(peers)
	return peers, nil
}

// UpdateEndpoint updates a peer's endpoint in memory and refreshes the
// persisted (hour-rounded) last-seen timestamp. The endpoint itself is
// never written to disk.
func (r *Registry) UpdateEndpoint(peerID, endpoint string) error {
	err := r.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketPeers)
		data := b.Get([]byte(peerID))
		if data == nil {
			return fmt.Errorf("peer %q not found", peerID)
		}
		var rec peerRecord
		if err := json.Unmarshal(data, &rec); err != nil {
			return err
		}
		rec.LastSeen = roundToHour(time.Now().Unix())
		updated, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		return b.Put([]byte(peerID), updated)
	})
	if err != nil {
		return err
	}
	r.setEndpoint(peerID, endpoint)
	return nil
}

// RemovePeer deletes a peer and decrements the network machine count.
// The peer's in-memory endpoint, if any, is dropped.
func (r *Registry) RemovePeer(peerID string) (peerRecord, error) {
	var removed peerRecord
	err := r.db.Update(func(tx *bolt.Tx) error {
		pb := tx.Bucket(bucketPeers)
		data := pb.Get([]byte(peerID))
		if data == nil {
			return fmt.Errorf("peer %q not found", peerID)
		}
		if err := json.Unmarshal(data, &removed); err != nil {
			return err
		}
		if err := pb.Delete([]byte(peerID)); err != nil {
			return err
		}

		// Decrement machine count.
		nb := tx.Bucket(bucketNetworks)
		netData := nb.Get([]byte(removed.NetworkID))
		if netData != nil {
			var netRec networkRecord
			if err := json.Unmarshal(netData, &netRec); err == nil {
				if netRec.MachineCount > 0 {
					netRec.MachineCount--
				}
				updated, err := json.Marshal(netRec)
				if err == nil {
					if err := nb.Put([]byte(removed.NetworkID), updated); err != nil {
						return err
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		return removed, err
	}
	r.dropEndpoint(peerID)
	return removed, nil
}

// NetworkCount returns the total number of networks for an account.
func (r *Registry) NetworkCount(accountID string) (int, error) {
	var count int
	err := r.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketNetworks).ForEach(func(k, v []byte) error {
			var rec networkRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			if rec.AccountID == accountID {
				count++
			}
			return nil
		})
	})
	return count, err
}

// nextIPAfterNetwork returns the first usable host IP in a prefix (network+1).
func nextIPAfterNetwork(prefix netip.Prefix) netip.Addr {
	return prefix.Addr().Next()
}

// TouchPeer refreshes a peer's LastSeen timestamp without changing any other
// field. The persisted value is rounded down to the hour. Used to keep the
// registration of a currently-connected daemon fresh so the TTL sweep never
// considers it stale.
func (r *Registry) TouchPeer(peerID string) error {
	return r.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketPeers)
		data := b.Get([]byte(peerID))
		if data == nil {
			return fmt.Errorf("peer %q not found", peerID)
		}
		var rec peerRecord
		if err := json.Unmarshal(data, &rec); err != nil {
			return err
		}
		rec.LastSeen = roundToHour(time.Now().Unix())
		updated, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		return b.Put([]byte(peerID), updated)
	})
}
