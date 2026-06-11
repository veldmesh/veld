// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package peer

import (
	"net/netip"
	"sync"
	"testing"
)

func makeID(b byte) [32]byte {
	var id [32]byte
	id[0] = b
	return id
}

func makeAddr(s string) netip.Addr {
	a, _ := netip.ParseAddr(s)
	return a
}

func makeAddrPort(s string) netip.AddrPort {
	ap, _ := netip.ParseAddrPort(s)
	return ap
}

func newEntry(id byte, vpn string, ep string) *Entry {
	e := &Entry{
		ID:        makeID(id),
		X25519Pub: makeID(id + 100),
		VPNAddr:   makeAddr(vpn),
	}
	if ep != "" {
		e.endpoint = makeAddrPort(ep)
	}
	return e
}

func TestTable_Upsert_LookupByID(t *testing.T) {
	tbl := New()
	e := newEntry(1, "10.0.0.1", "")
	tbl.Upsert(e)

	got, ok := tbl.LookupByID(makeID(1))
	if !ok {
		t.Fatal("LookupByID: not found")
	}
	if got != e {
		t.Error("LookupByID: returned wrong entry")
	}
}

func TestTable_Upsert_LookupByVPN(t *testing.T) {
	tbl := New()
	e := newEntry(2, "10.0.0.2", "")
	tbl.Upsert(e)

	got, ok := tbl.LookupByVPN(makeAddr("10.0.0.2"))
	if !ok {
		t.Fatal("LookupByVPN: not found")
	}
	if got != e {
		t.Error("LookupByVPN: returned wrong entry")
	}
}

func TestTable_Upsert_LookupByEndpoint(t *testing.T) {
	tbl := New()
	e := newEntry(3, "10.0.0.3", "1.2.3.4:5000")
	tbl.Upsert(e)

	got, ok := tbl.LookupByEndpoint(makeAddrPort("1.2.3.4:5000"))
	if !ok {
		t.Fatal("LookupByEndpoint: not found")
	}
	if got != e {
		t.Error("LookupByEndpoint: returned wrong entry")
	}
}

func TestTable_LookupMiss(t *testing.T) {
	tbl := New()

	if _, ok := tbl.LookupByID(makeID(99)); ok {
		t.Error("LookupByID should miss on empty table")
	}
	if _, ok := tbl.LookupByVPN(makeAddr("10.0.0.99")); ok {
		t.Error("LookupByVPN should miss on empty table")
	}
	if _, ok := tbl.LookupByEndpoint(makeAddrPort("9.9.9.9:9999")); ok {
		t.Error("LookupByEndpoint should miss on empty table")
	}
}

func TestTable_Remove(t *testing.T) {
	tbl := New()
	e := newEntry(4, "10.0.0.4", "1.2.3.4:4000")
	tbl.Upsert(e)

	tbl.Remove(makeID(4))

	if _, ok := tbl.LookupByID(makeID(4)); ok {
		t.Error("LookupByID should miss after Remove")
	}
	if _, ok := tbl.LookupByVPN(makeAddr("10.0.0.4")); ok {
		t.Error("LookupByVPN should miss after Remove")
	}
	if _, ok := tbl.LookupByEndpoint(makeAddrPort("1.2.3.4:4000")); ok {
		t.Error("LookupByEndpoint should miss after Remove")
	}
}

func TestTable_Remove_NoOp(t *testing.T) {
	tbl := New()
	// Should not panic
	tbl.Remove(makeID(99))
}

func TestTable_Upsert_Replace(t *testing.T) {
	tbl := New()
	e1 := newEntry(5, "10.0.0.5", "1.1.1.1:5001")
	tbl.Upsert(e1)

	// Replace with new entry at same ID but different VPN and endpoint
	e2 := &Entry{
		ID:        makeID(5),
		X25519Pub: makeID(105),
		VPNAddr:   makeAddr("10.0.0.55"),
	}
	e2.endpoint = makeAddrPort("2.2.2.2:5002")
	tbl.Upsert(e2)

	// Old indexes should be gone
	if _, ok := tbl.LookupByVPN(makeAddr("10.0.0.5")); ok {
		t.Error("old VPN index should be cleared after replace")
	}
	if _, ok := tbl.LookupByEndpoint(makeAddrPort("1.1.1.1:5001")); ok {
		t.Error("old endpoint index should be cleared after replace")
	}

	// New indexes should work
	got, ok := tbl.LookupByVPN(makeAddr("10.0.0.55"))
	if !ok || got != e2 {
		t.Error("new VPN index should be set after replace")
	}
}

func TestTable_UpdateEndpoint(t *testing.T) {
	tbl := New()
	e := newEntry(6, "10.0.0.6", "1.1.1.1:6000")
	tbl.Upsert(e)

	newEP := makeAddrPort("3.3.3.3:6001")
	if !tbl.UpdateEndpoint(makeID(6), newEP) {
		t.Fatal("UpdateEndpoint should return true for known peer")
	}

	// Old endpoint should be gone
	if _, ok := tbl.LookupByEndpoint(makeAddrPort("1.1.1.1:6000")); ok {
		t.Error("old endpoint should be removed")
	}
	// New endpoint should work
	got, ok := tbl.LookupByEndpoint(newEP)
	if !ok || got != e {
		t.Error("new endpoint should be indexed")
	}
}

func TestTable_UpdateEndpoint_Miss(t *testing.T) {
	tbl := New()
	if tbl.UpdateEndpoint(makeID(99), makeAddrPort("1.1.1.1:9999")) {
		t.Error("UpdateEndpoint should return false for unknown peer")
	}
}

func TestTable_Len(t *testing.T) {
	tbl := New()
	if tbl.Len() != 0 {
		t.Errorf("Len: got %d, want 0", tbl.Len())
	}
	tbl.Upsert(newEntry(1, "10.0.0.1", ""))
	tbl.Upsert(newEntry(2, "10.0.0.2", ""))
	if tbl.Len() != 2 {
		t.Errorf("Len: got %d, want 2", tbl.Len())
	}
	tbl.Remove(makeID(1))
	if tbl.Len() != 1 {
		t.Errorf("Len after remove: got %d, want 1", tbl.Len())
	}
}

func TestTable_PeerLookupFn(t *testing.T) {
	tbl := New()
	e := newEntry(7, "10.0.0.7", "")
	tbl.Upsert(e)

	fn := tbl.PeerLookupFn()

	id7 := makeID(7)
	x25519, ok := fn(id7[:])
	if !ok {
		t.Fatal("PeerLookupFn: not found")
	}
	if x25519 != makeID(107) {
		t.Errorf("PeerLookupFn: wrong X25519 key")
	}

	// Unknown peer
	id99 := makeID(99)
	if _, ok := fn(id99[:]); ok {
		t.Error("PeerLookupFn: should return false for unknown peer")
	}

	// Wrong-length input
	if _, ok := fn([]byte{1, 2, 3}); ok {
		t.Error("PeerLookupFn: should return false for wrong-length input")
	}
}

func TestTable_Concurrent(t *testing.T) {
	tbl := New()
	const goroutines = 20
	const ops = 100

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		g := g
		wg.Add(1)
		go func() {
			defer wg.Done()
			id := makeID(byte(g))
			vpn := netip.AddrFrom4([4]byte{10, 0, byte(g), 1})
			for i := 0; i < ops; i++ {
				e := &Entry{ID: id, X25519Pub: makeID(byte(g + 100)), VPNAddr: vpn}
				tbl.Upsert(e)
				tbl.LookupByID(id)
				tbl.LookupByVPN(vpn)
				if i%10 == 0 {
					tbl.Remove(id)
				}
			}
		}()
	}
	wg.Wait()
}
