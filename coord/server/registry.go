// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"time"

	bolt "go.etcd.io/bbolt"
	coordcore "github.com/veldmesh/veld/coord/core"
)

// Registry is a bbolt-backed persistent store for networks and peers.
type Registry struct {
	db *bolt.DB
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
	Ed25519Public string   `json:"ed25519_public"`   // base64
	X25519Public  string   `json:"x25519_public"`    // base64
	Endpoint      string   `json:"endpoint"`         // "ip:port" or ""
	SubnetRoutes  []string `json:"subnet_routes"`    // CIDR prefixes; nil = none
	LastSeen      int64    `json:"last_seen"`
	RegisteredAt  int64    `json:"registered_at"`
}

// NewRegistry opens or creates a bbolt database at path and ensures buckets exist.
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
		return nil
	})
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init buckets: %w", err)
	}
	return &Registry{db: db}, nil
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

// RegisterPeer adds a peer to the registry and returns its assigned VPN address.
// maxMachines is checked atomically inside the write transaction; pass 0 for unlimited.
// Idempotent: if the peer is already registered in the same network, updates
// mutable fields (endpoint, name, last_seen) and returns the existing IP without
// incrementing the machine count. This allows daemons to reconnect cleanly.
func (r *Registry) RegisterPeer(p peerRecord, networkID string, maxMachines int) (netip.Addr, error) {
	var assigned netip.Addr
	err := r.db.Update(func(tx *bolt.Tx) error {
		pb := tx.Bucket(bucketPeers)

		// Idempotent re-registration: peer exists in the same network → reuse IP.
		if existing := pb.Get([]byte(p.ID)); existing != nil {
			var rec peerRecord
			if err := json.Unmarshal(existing, &rec); err == nil && rec.NetworkID == networkID {
				addr, err := netip.ParseAddr(rec.VPNAddr)
				if err == nil {
					rec.Endpoint = p.Endpoint
					rec.LastSeen = p.LastSeen
					rec.Name = p.Name
					rec.SubnetRoutes = p.SubnetRoutes
					if updated, err := json.Marshal(rec); err == nil {
						_ = pb.Put([]byte(p.ID), updated)
					}
					assigned = addr
					return nil
				}
			}
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
		data, err := json.Marshal(p)
		if err != nil {
			return err
		}
		return pb.Put([]byte(p.ID), data)
	})
	return assigned, err
}

// GetPeer returns the peer record by Ed25519 ID (hex string).
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

// ListPeers returns all peers in a network.
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
	return peers, err
}

// UpdateEndpoint updates a peer's last-seen endpoint.
func (r *Registry) UpdateEndpoint(peerID, endpoint string) error {
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
		rec.Endpoint = endpoint
		rec.LastSeen = time.Now().Unix()
		updated, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		return b.Put([]byte(peerID), updated)
	})
}

// RemovePeer deletes a peer and decrements the network machine count.
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
	return removed, err
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
