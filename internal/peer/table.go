// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package peer

import (
	"net/netip"
	"strings"
	"sync"
)

// Table is a concurrent in-memory peer routing table.
// It maintains four lookup indexes for O(1) access by Ed25519 ID, VPN address,
// UDP endpoint, and peer name.
type Table struct {
	mu         sync.RWMutex
	byID       map[[32]byte]*Entry
	byVPN      map[netip.Addr]*Entry
	byEndpoint map[netip.AddrPort]*Entry
	byName     map[string]*Entry // keyed by strings.ToLower(entry.Name)
}

// New returns an empty Table.
func New() *Table {
	return &Table{
		byID:       make(map[[32]byte]*Entry),
		byVPN:      make(map[netip.Addr]*Entry),
		byEndpoint: make(map[netip.AddrPort]*Entry),
		byName:     make(map[string]*Entry),
	}
}

// Upsert inserts or replaces the peer entry identified by e.ID.
// If a previous entry with the same ID exists its index slots are removed first.
// The caller must not modify e after calling Upsert.
func (t *Table) Upsert(e *Entry) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if old, ok := t.byID[e.ID]; ok {
		delete(t.byVPN, old.VPNAddr)
		if ep := old.GetEndpoint(); ep.IsValid() {
			delete(t.byEndpoint, ep)
		}
		if old.Name != "" {
			delete(t.byName, strings.ToLower(old.Name))
		}
	}

	t.byID[e.ID] = e
	if e.VPNAddr.IsValid() {
		t.byVPN[e.VPNAddr] = e
	}
	if ep := e.GetEndpoint(); ep.IsValid() {
		t.byEndpoint[ep] = e
	}
	if e.Name != "" {
		t.byName[strings.ToLower(e.Name)] = e
	}
}

// UpdateEndpoint atomically re-indexes the peer's UDP endpoint.
// Returns false if no peer with id exists.
func (t *Table) UpdateEndpoint(id [32]byte, ep netip.AddrPort) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	e, ok := t.byID[id]
	if !ok {
		return false
	}

	if old := e.GetEndpoint(); old.IsValid() {
		delete(t.byEndpoint, old)
	}
	e.SetEndpoint(ep)
	if ep.IsValid() {
		t.byEndpoint[ep] = e
	}
	return true
}

// LookupByID returns the entry for the given Ed25519 public key.
func (t *Table) LookupByID(id [32]byte) (*Entry, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	e, ok := t.byID[id]
	return e, ok
}

// LookupByVPN returns the entry whose VPN address matches addr.
func (t *Table) LookupByVPN(addr netip.Addr) (*Entry, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	e, ok := t.byVPN[addr]
	return e, ok
}

// LookupByEndpoint returns the entry whose UDP endpoint matches ep.
func (t *Table) LookupByEndpoint(ep netip.AddrPort) (*Entry, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	e, ok := t.byEndpoint[ep]
	return e, ok
}

// LookupByName returns the entry whose Name field matches name (case-insensitive).
func (t *Table) LookupByName(name string) (*Entry, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	e, ok := t.byName[strings.ToLower(name)]
	return e, ok
}

// Remove deletes the peer with the given Ed25519 ID from all indexes.
// No-op if the ID is not present.
func (t *Table) Remove(id [32]byte) {
	t.mu.Lock()
	defer t.mu.Unlock()

	e, ok := t.byID[id]
	if !ok {
		return
	}
	delete(t.byID, id)
	delete(t.byVPN, e.VPNAddr)
	if ep := e.GetEndpoint(); ep.IsValid() {
		delete(t.byEndpoint, ep)
	}
	if e.Name != "" {
		delete(t.byName, strings.ToLower(e.Name))
	}
}

// Len returns the number of peers in the table.
func (t *Table) Len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.byID)
}

// List returns a snapshot of all entries currently in the table.
func (t *Table) List() []*Entry {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]*Entry, 0, len(t.byID))
	for _, e := range t.byID {
		out = append(out, e)
	}
	return out
}

// PeerLookupFn returns a function matching the crypto.PeerLookupFn signature.
// It looks up a peer by their Ed25519 public key and returns their X25519 key.
func (t *Table) PeerLookupFn() func(ed25519Pub []byte) ([32]byte, bool) {
	return func(ed25519Pub []byte) ([32]byte, bool) {
		if len(ed25519Pub) != 32 {
			return [32]byte{}, false
		}
		var id [32]byte
		copy(id[:], ed25519Pub)
		t.mu.RLock()
		defer t.mu.RUnlock()
		e, ok := t.byID[id]
		if !ok {
			return [32]byte{}, false
		}
		return e.X25519Pub, true
	}
}
