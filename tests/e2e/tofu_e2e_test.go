// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package e2e_test

import (
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/veldmesh/veld/internal/crypto"
	"github.com/veldmesh/veld/internal/handshake"
	"github.com/veldmesh/veld/internal/peer"
	"github.com/veldmesh/veld/internal/tofu"
)

// tofuConn is a minimal net.PacketConn used in TOFU e2e tests.
type tofuConn struct {
	out    chan tofuMsg
	once   sync.Once
	closed chan struct{}
}

type tofuMsg struct {
	data []byte
	addr net.Addr
}

func newTOFUConn() *tofuConn {
	return &tofuConn{
		out:    make(chan tofuMsg, 32),
		closed: make(chan struct{}),
	}
}

func (c *tofuConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}
func (c *tofuConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	buf := make([]byte, len(p))
	copy(buf, p)
	select {
	case c.out <- tofuMsg{data: buf, addr: addr}:
	default:
	}
	return len(p), nil
}
func (c *tofuConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}
func (c *tofuConn) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (c *tofuConn) SetDeadline(t time.Time) error      { return nil }
func (c *tofuConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *tofuConn) SetWriteDeadline(t time.Time) error { return nil }

func doHandshake(t *testing.T,
	mgrA, mgrB *handshake.Manager,
	connA, connB *tofuConn,
	entryB *peer.Entry,
	addrA, addrB net.Addr,
) {
	t.Helper()
	mgrA.Initiate(entryB)
	select {
	case initPkt := <-connA.out:
		mgrB.HandlePacket(initPkt.data, addrA)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for init packet")
	}
	select {
	case respPkt := <-connB.out:
		mgrA.HandlePacket(respPkt.data, addrB)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for resp packet")
	}
}

// TestTOFU_E2E_FirstConnect_Pinned verifies that after a successful handshake
// the peer's fingerprint appears in the TOFU store.
func TestTOFU_E2E_FirstConnect_Pinned(t *testing.T) {
	idA, _ := crypto.Generate()
	idB, _ := crypto.Generate()

	store, _ := tofu.New(t.TempDir() + "/tofu.json")

	tblA := peer.New()
	entryBinA := makeEntry(idB, "10.0.0.2", netip.MustParseAddrPort("2.2.2.2:2000"))
	tblA.Upsert(entryBinA)

	tblB := peer.New()
	tblB.Upsert(makeEntry(idA, "10.0.0.1", netip.MustParseAddrPort("1.1.1.1:1000")))

	connA, connB := newTOFUConn(), newTOFUConn()

	sessEstA := make(chan struct{}, 1)
	mgrA := handshake.New(idA, [16]byte{}, tblA, connA)
	mgrA.TOFUCheck = store.Check
	mgrA.OnSessionEstablished = func(*peer.Entry) { sessEstA <- struct{}{} }

	mgrB := handshake.New(idB, [16]byte{}, tblB, connB)
	mgrB.OnSessionEstablished = func(*peer.Entry) {}

	addrA := &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1000}
	addrB := &net.UDPAddr{IP: net.ParseIP("2.2.2.2"), Port: 2000}
	doHandshake(t, mgrA, mgrB, connA, connB, entryBinA, addrA, addrB)

	select {
	case <-sessEstA:
	case <-time.After(2 * time.Second):
		t.Fatal("session not established")
	}

	pins := store.List()
	if _, ok := pins["10.0.0.2"]; !ok {
		t.Error("B's fingerprint not pinned after successful handshake")
	}
}

// TestTOFU_E2E_SameKey_Accepted verifies that a second handshake with the same
// identity succeeds (no false positives).
func TestTOFU_E2E_SameKey_Accepted(t *testing.T) {
	idA, _ := crypto.Generate()
	idB, _ := crypto.Generate()

	store, _ := tofu.New(t.TempDir() + "/tofu.json")

	tblA := peer.New()
	entryBinA := makeEntry(idB, "10.0.0.2", netip.MustParseAddrPort("2.2.2.2:2000"))
	tblA.Upsert(entryBinA)

	tblB := peer.New()
	tblB.Upsert(makeEntry(idA, "10.0.0.1", netip.MustParseAddrPort("1.1.1.1:1000")))

	connA, connB := newTOFUConn(), newTOFUConn()

	established := make(chan struct{}, 4)
	mgrA := handshake.New(idA, [16]byte{}, tblA, connA)
	mgrA.TOFUCheck = store.Check
	mgrA.OnSessionEstablished = func(*peer.Entry) { established <- struct{}{} }

	mgrB := handshake.New(idB, [16]byte{}, tblB, connB)
	mgrB.OnSessionEstablished = func(*peer.Entry) {}

	addrA := &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1000}
	addrB := &net.UDPAddr{IP: net.ParseIP("2.2.2.2"), Port: 2000}

	// First handshake.
	doHandshake(t, mgrA, mgrB, connA, connB, entryBinA, addrA, addrB)
	select {
	case <-established:
	case <-time.After(2 * time.Second):
		t.Fatal("first handshake: session not established")
	}

	// Second handshake with same key — should also succeed.
	doHandshake(t, mgrA, mgrB, connA, connB, entryBinA, addrA, addrB)
	select {
	case <-established:
	case <-time.After(2 * time.Second):
		t.Fatal("second handshake: session not established (same key should be accepted)")
	}
}

// TestTOFU_E2E_KeyChange_Rejected verifies that an attacker presenting a different
// Ed25519 key at the same VPN address is silently rejected after the first connect.
//
// Scenario: A has already connected to B (10.0.0.2) once; the coord server is later
// compromised and advertises an evil identity at 10.0.0.2. A's peer table is updated
// with the evil keys, but TOFU should block the handshake.
func TestTOFU_E2E_KeyChange_Rejected(t *testing.T) {
	idA, _ := crypto.Generate()
	idB_real, _ := crypto.Generate()
	idB_evil, _ := crypto.Generate()

	store, _ := tofu.New(t.TempDir() + "/tofu.json")

	// Simulate a prior successful connection by pre-pinning idB_real's fingerprint.
	// This is what would have happened after the first legitimate connect.
	store.Check("10.0.0.2", idB_real.Ed25519Public) //nolint:errcheck

	// Coord server is now compromised: A's peer table has evil's keys for 10.0.0.2.
	tblA := peer.New()
	entryEvil := makeEntry(idB_evil, "10.0.0.2", netip.MustParseAddrPort("2.2.2.2:2000"))
	tblA.Upsert(entryEvil)

	// Evil's responder table knows A.
	tblEvil := peer.New()
	tblEvil.Upsert(makeEntry(idA, "10.0.0.1", netip.MustParseAddrPort("1.1.1.1:1000")))

	connA, connEvil := newTOFUConn(), newTOFUConn()

	sessionOnA := make(chan struct{}, 1)
	mgrA := handshake.New(idA, [16]byte{}, tblA, connA)
	mgrA.TOFUCheck = store.Check
	mgrA.OnSessionEstablished = func(*peer.Entry) { sessionOnA <- struct{}{} }

	mgrEvil := handshake.New(idB_evil, [16]byte{}, tblEvil, connEvil)
	mgrEvil.OnSessionEstablished = func(*peer.Entry) {}

	addrA := &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1000}
	addrEvil := &net.UDPAddr{IP: net.ParseIP("2.2.2.2"), Port: 2000}
	doHandshake(t, mgrA, mgrEvil, connA, connEvil, entryEvil, addrA, addrEvil)

	// TOFU should have blocked the session on A's side.
	select {
	case <-sessionOnA:
		t.Error("session established despite TOFU mismatch — attacker's substitution succeeded")
	case <-time.After(100 * time.Millisecond):
		// Expected: no session.
	}
	if entryEvil.GetSession() != nil {
		t.Error("session was set on entry despite TOFU mismatch")
	}
}
