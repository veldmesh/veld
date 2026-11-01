// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package handshake

import (
	"encoding/hex"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/veldmesh/veld/internal/crypto"
	"github.com/veldmesh/veld/internal/peer"
)


// testConn is a minimal net.PacketConn for testing.
type testConn struct {
	out    chan testMsg
	once   sync.Once
	closed chan struct{}
}

type testMsg struct {
	data []byte
	addr net.Addr
}

func newTestConn() *testConn {
	return &testConn{
		out:    make(chan testMsg, 32),
		closed: make(chan struct{}),
	}
}

func (c *testConn) ReadFrom(p []byte) (int, net.Addr, error) {
	<-c.closed
	return 0, nil, net.ErrClosed
}

func (c *testConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	buf := make([]byte, len(p))
	copy(buf, p)
	select {
	case c.out <- testMsg{data: buf, addr: addr}:
	default:
	}
	return len(p), nil
}

func (c *testConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *testConn) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (c *testConn) SetDeadline(t time.Time) error      { return nil }
func (c *testConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *testConn) SetWriteDeadline(t time.Time) error { return nil }

func makeTestEntry(id *crypto.Identity, vpn string, ep string) *peer.Entry {
	var peerID [32]byte
	copy(peerID[:], id.Ed25519Public)

	e := &peer.Entry{
		ID:        peerID,
		X25519Pub: id.X25519Public,
		VPNAddr:   netip.MustParseAddr(vpn),
	}
	if ep != "" {
		e.SetEndpoint(netip.MustParseAddrPort(ep))
	}
	return e
}

func TestManager_Initiate_SendsInit(t *testing.T) {
	idA, _ := crypto.Generate()
	idB, _ := crypto.Generate()

	tbl := peer.New()
	entryB := makeTestEntry(idB, "10.0.0.2", "1.2.3.4:5000")
	tbl.Upsert(entryB)

	conn := newTestConn()
	mgr := New(idA, [16]byte{}, tbl, conn)
	mgr.Initiate(entryB)

	select {
	case msg := <-conn.out:
		if len(msg.data) < headerSize {
			t.Fatalf("packet too short: %d", len(msg.data))
		}
		pktType := uint32(msg.data[0])<<24 | uint32(msg.data[1])<<16 | uint32(msg.data[2])<<8 | uint32(msg.data[3])
		if pktType != typeHandshakeInit {
			t.Errorf("pktType: got %d, want %d (typeHandshakeInit)", pktType, typeHandshakeInit)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout: no init packet sent")
	}
}

func TestManager_Initiate_Deduplication(t *testing.T) {
	idA, _ := crypto.Generate()
	idB, _ := crypto.Generate()

	tbl := peer.New()
	entryB := makeTestEntry(idB, "10.0.0.2", "1.2.3.4:5000")
	tbl.Upsert(entryB)

	conn := newTestConn()
	mgr := New(idA, [16]byte{}, tbl, conn)

	mgr.Initiate(entryB)
	mgr.Initiate(entryB) // second call should be no-op

	// Drain the first packet.
	<-conn.out

	select {
	case <-conn.out:
		t.Error("second Initiate should not send a second packet")
	case <-time.After(20 * time.Millisecond):
	}
}

// TestManager_Initiate_RetryAfterTimeout verifies that a pending handshake
// older than handshakeRetryTimeout (5s) allows a fresh Initiate to send a new Init.
func TestManager_Initiate_RetryAfterTimeout(t *testing.T) {
	idA, _ := crypto.Generate()
	idB, _ := crypto.Generate()

	tbl := peer.New()
	entryB := makeTestEntry(idB, "10.0.0.2", "1.2.3.4:5000")
	tbl.Upsert(entryB)

	conn := newTestConn()
	mgr := New(idA, [16]byte{}, tbl, conn)

	// First Initiate sends an Init.
	mgr.Initiate(entryB)
	select {
	case <-conn.out:
	case <-time.After(time.Second):
		t.Fatal("timeout: first init not sent")
	}

	// Manually expire the pending handshake by advancing createdAt.
	mgr.mu.Lock()
	if phs, ok := mgr.pending[entryB.ID]; ok {
		phs.createdAt = time.Now().Add(-handshakeRetryTimeout - time.Second)
	}
	mgr.mu.Unlock()

	// Second Initiate should send a new Init (retry after timeout).
	mgr.Initiate(entryB)
	select {
	case <-conn.out:
		// Success: new Init sent.
	case <-time.After(time.Second):
		t.Fatal("timeout: retry init not sent after timeout")
	}
}

// TestManager_Initiate_RetryBounded verifies that retries are bounded to maxHandshakeRetries.
func TestManager_Initiate_RetryBounded(t *testing.T) {
	idA, _ := crypto.Generate()
	idB, _ := crypto.Generate()

	tbl := peer.New()
	entryB := makeTestEntry(idB, "10.0.0.2", "1.2.3.4:5000")
	tbl.Upsert(entryB)

	conn := newTestConn()
	mgr := New(idA, [16]byte{}, tbl, conn)

	// First Initiate.
	mgr.Initiate(entryB)
	<-conn.out

	// Expire and retry up to maxHandshakeRetries times.
	for i := 0; i < maxHandshakeRetries; i++ {
		mgr.mu.Lock()
		if phs, ok := mgr.pending[entryB.ID]; ok {
			phs.createdAt = time.Now().Add(-handshakeRetryTimeout - time.Second)
		}
		mgr.mu.Unlock()

		mgr.Initiate(entryB)
		select {
		case <-conn.out:
		case <-time.After(time.Second):
			t.Fatalf("retry %d: timeout", i+1)
		}
	}

	// One more retry should be blocked (exceeds maxHandshakeRetries).
	mgr.mu.Lock()
	if phs, ok := mgr.pending[entryB.ID]; ok {
		phs.createdAt = time.Now().Add(-handshakeRetryTimeout - time.Second)
	}
	mgr.mu.Unlock()

	mgr.Initiate(entryB)
	select {
	case <-conn.out:
		t.Error("Initiate should be blocked after maxHandshakeRetries")
	case <-time.After(20 * time.Millisecond):
		// Expected: no packet sent.
	}
}

// TestManager_Initiate_RetryResetAfterExhaustion verifies that after retries
// are exhausted and the pending entry is cleaned up, a future Initiate can
// start a fresh handshake (e.g., after network recovery).
func TestManager_Initiate_RetryResetAfterExhaustion(t *testing.T) {
	idA, _ := crypto.Generate()
	idB, _ := crypto.Generate()

	tbl := peer.New()
	entryB := makeTestEntry(idB, "10.0.0.2", "1.2.3.4:5000")
	tbl.Upsert(entryB)

	conn := newTestConn()
	mgr := New(idA, [16]byte{}, tbl, conn)

	// First Initiate.
	mgr.Initiate(entryB)
	<-conn.out

	// Expire and retry up to maxHandshakeRetries times.
	for i := 0; i < maxHandshakeRetries; i++ {
		mgr.mu.Lock()
		if phs, ok := mgr.pending[entryB.ID]; ok {
			phs.createdAt = time.Now().Add(-handshakeRetryTimeout - time.Second)
		}
		mgr.mu.Unlock()

		mgr.Initiate(entryB)
		select {
		case <-conn.out:
		case <-time.After(time.Second):
			t.Fatalf("retry %d: timeout", i+1)
		}
	}

	// One more retry attempt (exceeds maxHandshakeRetries) -- should be blocked
	// and the pending entry should be cleaned up.
	mgr.mu.Lock()
	if phs, ok := mgr.pending[entryB.ID]; ok {
		phs.createdAt = time.Now().Add(-handshakeRetryTimeout - time.Second)
	}
	mgr.mu.Unlock()

	mgr.Initiate(entryB)
	select {
	case <-conn.out:
		t.Error("Initiate should be blocked after maxHandshakeRetries")
	case <-time.After(20 * time.Millisecond):
		// Expected: no packet sent.
	}

	// Verify pending entry was cleaned up.
	mgr.mu.Lock()
	_, exists := mgr.pending[entryB.ID]
	mgr.mu.Unlock()
	if exists {
		t.Error("pending entry should be cleaned up after retries exhausted")
	}

	// Now a new Initiate should start a fresh handshake (retries reset).
	mgr.Initiate(entryB)
	select {
	case <-conn.out:
		// Success: fresh Init sent.
	case <-time.After(time.Second):
		t.Fatal("timeout: fresh init not sent after retries exhausted and cleaned up")
	}
}

func TestManager_FullHandshake(t *testing.T) {
	idA, _ := crypto.Generate()
	idB, _ := crypto.Generate()

	var netID [16]byte

	// A's table: knows B.
	tblA := peer.New()
	entryBinA := makeTestEntry(idB, "10.0.0.2", "2.2.2.2:2000")
	tblA.Upsert(entryBinA)

	// B's table: knows A.
	tblB := peer.New()
	entryAinB := makeTestEntry(idA, "10.0.0.1", "1.1.1.1:1000")
	tblB.Upsert(entryAinB)

	connA := newTestConn()
	connB := newTestConn()

	sessEstA := make(chan struct{}, 1)
	// B's session is established lazily (on first data packet), so we don't
	// wait for OnSessionEstablished here. We verify the pending session exists.
	mgrA := New(idA, netID, tblA, connA)
	mgrA.OnSessionEstablished = func(*peer.Entry) { sessEstA <- struct{}{} }

	mgrB := New(idB, netID, tblB, connB)

	// A initiates.
	mgrA.Initiate(entryBinA)

	// Get init packet from A.
	var initPkt testMsg
	select {
	case initPkt = <-connA.out:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for init packet")
	}

	// Feed init packet to B (as if received from 1.1.1.1:1000 = A's addr).
	addrA := &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1000}
	mgrB.HandlePacket(initPkt.data, addrA)

	// Expect B to have sent a resp.
	var respPkt testMsg
	select {
	case respPkt = <-connB.out:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for resp packet")
	}

	// B should have a pending session now (not yet confirmed).
	if entryAinB.GetPendingSession() == nil {
		t.Error("B should have a pending session after processing Init")
	}

	// Feed resp packet to A (as if received from 2.2.2.2:2000 = B's addr).
	addrB := &net.UDPAddr{IP: net.ParseIP("2.2.2.2"), Port: 2000}
	mgrA.HandlePacket(respPkt.data, addrB)

	select {
	case <-sessEstA:
	case <-time.After(time.Second):
		t.Fatal("timeout: A session not established")
	}

	// Verify A's session is set (initiator confirms immediately on Resp).
	if entryBinA.GetSession() == nil {
		t.Error("A's session for B should be set")
	}
	// B still has pending session until first data packet arrives.
	if entryAinB.GetPendingSession() == nil {
		t.Error("B should still have pending session")
	}

	// Simulate A sending a data packet to B to confirm the handshake.
	// Encrypt a dummy packet with A's session and feed it to B via HandleDataPacket.
	sessA := entryBinA.GetSession()
	if sessA == nil {
		t.Fatal("A session is nil")
	}
	nonce, ct, err := sessA.Encrypt([]byte("test"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Use HandleDataPacket to process the data packet and promote pending session.
	plain, promoted := mgrB.HandleDataPacket(entryAinB, nonce, ct)
	if !promoted {
		t.Error("HandleDataPacket should promote pending session")
	}
	if plain == nil {
		t.Error("HandleDataPacket should return decrypted plaintext")
	}

	// Now B should have promoted the pending session to active.
	if entryAinB.GetSession() == nil {
		t.Error("B's session should be promoted after receiving data packet")
	}
	if entryAinB.GetPendingSession() != nil {
		t.Error("B's pending session should be cleared after promotion")
	}
}

func TestManager_HandleInit_UnknownPeer_SilentDrop(t *testing.T) {
	idA, _ := crypto.Generate()
	idB, _ := crypto.Generate()

	// B's table is empty -- does not know A.
	tblB := peer.New()
	connB := newTestConn()
	mgrB := New(idB, [16]byte{}, tblB, connB)

	// Build a valid init packet from A.
	connA := newTestConn()
	tblA := peer.New()
	entryBinA := makeTestEntry(idB, "10.0.0.2", "2.2.2.2:2000")
	tblA.Upsert(entryBinA)
	mgrA := New(idA, [16]byte{}, tblA, connA)
	mgrA.Initiate(entryBinA)

	var initPkt testMsg
	select {
	case initPkt = <-connA.out:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for init packet from A")
	}

	// B processes it -- should be silently dropped (no resp).
	addrA := &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1000}
	mgrB.HandlePacket(initPkt.data, addrA)

	select {
	case <-connB.out:
		t.Error("unknown peer should be silently dropped")
	case <-time.After(20 * time.Millisecond):
	}
}

// TestManager_HandleInit_ReplayRejection verifies that processing the same
// Init message twice results in the second being rejected (replay protection).
func TestManager_HandleInit_ReplayRejection(t *testing.T) {
	idA, _ := crypto.Generate()
	idB, _ := crypto.Generate()

	var netID [16]byte

	// B's table knows A.
	tblB := peer.New()
	entryAinB := makeTestEntry(idA, "10.0.0.1", "1.1.1.1:1000")
	tblB.Upsert(entryAinB)

	connB := newTestConn()
	mgrB := New(idB, netID, tblB, connB)

	// Build a valid init packet from A.
	connA := newTestConn()
	tblA := peer.New()
	entryBinA := makeTestEntry(idB, "10.0.0.2", "2.2.2.2:2000")
	tblA.Upsert(entryBinA)
	mgrA := New(idA, netID, tblA, connA)
	mgrA.Initiate(entryBinA)

	var initPkt testMsg
	select {
	case initPkt = <-connA.out:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for init packet from A")
	}

	// Feed init packet to B (first time -- should succeed).
	addrA := &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1000}
	mgrB.HandlePacket(initPkt.data, addrA)

	// B should have a pending session now.
	if entryAinB.GetPendingSession() == nil {
		t.Fatal("pending session should be created after first Init")
	}
	firstPending := entryAinB.GetPendingSession()

	// Drain the first response packet from connB.
	select {
	case <-connB.out:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for first response")
	}

	// Feed the SAME init packet again (replay) -- should be rejected.
	// The pending session pointer should remain unchanged.
	mgrB.HandlePacket(initPkt.data, addrA)

	select {
	case <-connB.out:
		t.Error("replayed Init should not trigger a second response")
	case <-time.After(20 * time.Millisecond):
	}

	// Pending session should be unchanged.
	if entryAinB.GetPendingSession() != firstPending {
		t.Error("replayed Init should not replace existing pending session")
	}
}

// TestManager_HandleInit_StaleTimestampRejection verifies that an Init with
// a timestamp <= the previously accepted timestamp is rejected.
func TestManager_HandleInit_StaleTimestampRejection(t *testing.T) {
	idA, _ := crypto.Generate()
	idB, _ := crypto.Generate()

	var netID [16]byte

	// B's table knows A.
	tblB := peer.New()
	entryAinB := makeTestEntry(idA, "10.0.0.1", "1.1.1.1:1000")
	tblB.Upsert(entryAinB)

	connB := newTestConn()
	mgrB := New(idB, netID, tblB, connB)

	// Build a valid init packet from A with a specific timestamp.
	hs, err := crypto.NewInitiatorHS(idA, idB.X25519Public, netID)
	if err != nil {
		t.Fatalf("NewInitiatorHS: %v", err)
	}
	ts := time.Now().UnixNano()
	initMsg, err := hs.BuildMessage1(ts)
	if err != nil {
		t.Fatalf("BuildMessage1: %v", err)
	}
	initPkt := buildPacket(typeHandshakeInit, initMsg)

	// Feed init packet to B (first time -- should succeed).
	addrA := &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1000}
	mgrB.HandlePacket(initPkt, addrA)

	// B should have a pending session.
	if entryAinB.GetPendingSession() == nil {
		t.Fatal("pending session should be created after first Init")
	}
	firstPending := entryAinB.GetPendingSession()

	// Drain the first response packet from connB.
	select {
	case <-connB.out:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for first response")
	}

	// Now send another Init with the SAME timestamp (stale) -- must be rejected.
	mgrB.HandlePacket(initPkt, addrA)

	select {
	case <-connB.out:
		t.Error("stale timestamp Init should not trigger a response")
	case <-time.After(20 * time.Millisecond):
	}

	// Pending session should be unchanged.
	if entryAinB.GetPendingSession() != firstPending {
		t.Error("stale timestamp Init should not replace existing pending session")
	}

	// Send an Init with a newer timestamp (should succeed).
	// Build it with a fresh initiator HS: a Noise handshake state is single-shot.
	newerTS := ts + 1_000_000 // 1ms later
	hs2, err := crypto.NewInitiatorHS(idA, idB.X25519Public, netID)
	if err != nil {
		t.Fatalf("NewInitiatorHS: %v", err)
	}
	initMsg2, err := hs2.BuildMessage1(newerTS)
	if err != nil {
		t.Fatalf("BuildMessage1: %v", err)
	}
	initPkt2 := buildPacket(typeHandshakeInit, initMsg2)

	mgrB.HandlePacket(initPkt2, addrA)

	select {
	case <-connB.out:
		// Expected: new response sent.
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for response to newer Init")
	}

	// New pending session should be created.
	if entryAinB.GetPendingSession() == firstPending {
		t.Error("newer Init should create a new pending session")
	}
}

// TestManager_PendingSessionPromotion verifies that a pending session is
// promoted to active when a data packet decrypts successfully with it.
func TestManager_PendingSessionPromotion(t *testing.T) {
	idA, _ := crypto.Generate()
	idB, _ := crypto.Generate()

	var netID [16]byte

	// B's table knows A.
	tblB := peer.New()
	entryAinB := makeTestEntry(idA, "10.0.0.1", "1.1.1.1:1000")
	tblB.Upsert(entryAinB)

	connB := newTestConn()
	mgrB := New(idB, netID, tblB, connB)

	// Build a valid init packet from A.
	connA := newTestConn()
	tblA := peer.New()
	entryBinA := makeTestEntry(idB, "10.0.0.2", "2.2.2.2:2000")
	tblA.Upsert(entryBinA)
	mgrA := New(idA, netID, tblA, connA)
	mgrA.Initiate(entryBinA)

	var initPkt testMsg
	select {
	case initPkt = <-connA.out:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for init packet from A")
	}

	// Feed init packet to B.
	addrA := &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1000}
	mgrB.HandlePacket(initPkt.data, addrA)

	// B has pending session.
	pending := entryAinB.GetPendingSession()
	if pending == nil {
		t.Fatal("pending session should exist")
	}

	// Drain the response.
	select {
	case respPkt := <-connB.out:
		// Feed resp to A to complete A's side.
		addrB := &net.UDPAddr{IP: net.ParseIP("2.2.2.2"), Port: 2000}
		mgrA.HandlePacket(respPkt.data, addrB)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for response")
	}

	// A now has active session.
	sessA := entryBinA.GetSession()
	if sessA == nil {
		t.Fatal("A should have active session")
	}

	// Encrypt a data packet with A's session and send to B via HandleDataPacket.
	nonce, ct, err := sessA.Encrypt([]byte("confirmation packet"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Use HandleDataPacket to process the data packet and promote pending session.
	plain, promoted := mgrB.HandleDataPacket(entryAinB, nonce, ct)
	if !promoted {
		t.Error("HandleDataPacket should promote pending session")
	}
	if plain == nil {
		t.Error("HandleDataPacket should return decrypted plaintext")
	}

	// B should have promoted the session.
	if entryAinB.GetSession() == nil {
		t.Error("session should be promoted after valid data packet")
	}
	if entryAinB.GetPendingSession() != nil {
		t.Error("pending session should be cleared after promotion")
	}
	// The promoted session should be the same as the pending one.
	if entryAinB.GetSession() != pending {
		t.Error("promoted session should be the same as pending session")
	}
}
// TestManager_SimultaneousInitiation covers both sides initiating at once (as
// happens at startup): each ends up with its own initiator session active,
// and the session it responded to must stay available so the two converge.
func TestManager_SimultaneousInitiation(t *testing.T) {
	idA, _ := crypto.Generate()
	idB, _ := crypto.Generate()
	var netID [16]byte

	tblA := peer.New()
	entryBinA := makeTestEntry(idB, "10.0.0.2", "2.2.2.2:2000")
	tblA.Upsert(entryBinA)
	tblB := peer.New()
	entryAinB := makeTestEntry(idA, "10.0.0.1", "1.1.1.1:1000")
	tblB.Upsert(entryAinB)

	connA, connB := newTestConn(), newTestConn()
	mgrA := New(idA, netID, tblA, connA)
	mgrB := New(idB, netID, tblB, connB)
	addrA := &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1000}
	addrB := &net.UDPAddr{IP: net.ParseIP("2.2.2.2"), Port: 2000}

	recv := func(c *testConn) []byte {
		t.Helper()
		select {
		case m := <-c.out:
			return m.data
		case <-time.After(time.Second):
			t.Fatal("timeout waiting for packet")
			return nil
		}
	}

	mgrA.Initiate(entryBinA)
	mgrB.Initiate(entryAinB)
	initA, initB := recv(connA), recv(connB)

	mgrB.HandlePacket(initA, addrA)
	mgrA.HandlePacket(initB, addrB)
	respB, respA := recv(connB), recv(connA)

	mgrA.HandlePacket(respB, addrB)
	mgrB.HandlePacket(respA, addrA)

	// A sends with its active session; B only has it as pending.
	n, ct, err := entryBinA.GetSession().Encrypt([]byte("a->b"))
	if err != nil {
		t.Fatal(err)
	}
	if plain, _ := entryAinB.GetSession().Decrypt(n, ct); plain != nil {
		t.Fatal("expected B's active session to differ from A's")
	}
	if plain, ok := mgrB.HandleDataPacket(entryAinB, n, ct); !ok || string(plain) != "a->b" {
		t.Fatalf("B could not decrypt A's packet: %q", plain)
	}

	// B has promoted A's session, so B's reply decrypts at A.
	n, ct, err = entryAinB.GetSession().Encrypt([]byte("b->a"))
	if err != nil {
		t.Fatal(err)
	}
	if plain, _ := entryBinA.GetSession().Decrypt(n, ct); string(plain) != "b->a" {
		t.Fatalf("A could not decrypt B's reply: %q", plain)
	}
}

func TestManager_HandleInit_WrongNetworkDropped(t *testing.T) {
	idA, _ := crypto.Generate()
	idB, _ := crypto.Generate()

	tblA := peer.New()
	entryBinA := makeTestEntry(idB, "10.0.0.2", "2.2.2.2:2000")
	tblA.Upsert(entryBinA)
	tblB := peer.New()
	tblB.Upsert(makeTestEntry(idA, "10.0.0.1", "1.1.1.1:1000"))

	connA, connB := newTestConn(), newTestConn()
	mgrA := New(idA, [16]byte{1}, tblA, connA)
	mgrB := New(idB, [16]byte{2}, tblB, connB)

	mgrA.Initiate(entryBinA)
	var init testMsg
	select {
	case init = <-connA.out:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for init")
	}
	mgrB.HandlePacket(init.data, &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1000})
	select {
	case <-connB.out:
		t.Fatal("responder answered an Init for another network")
	case <-time.After(100 * time.Millisecond):
	}
}

// A forged Resp from the peer's address must not cancel the pending
// handshake: the genuine Resp that follows still establishes the session.
func TestManager_ForgedRespKeepsHandshake(t *testing.T) {
	idA, _ := crypto.Generate()
	idB, _ := crypto.Generate()
	var netID [16]byte

	tblA := peer.New()
	entryBinA := makeTestEntry(idB, "10.0.0.2", "2.2.2.2:2000")
	tblA.Upsert(entryBinA)
	tblB := peer.New()
	tblB.Upsert(makeTestEntry(idA, "10.0.0.1", "1.1.1.1:1000"))

	connA, connB := newTestConn(), newTestConn()
	established := make(chan struct{}, 1)
	mgrA := New(idA, netID, tblA, connA)
	mgrA.OnSessionEstablished = func(*peer.Entry) { established <- struct{}{} }
	mgrB := New(idB, netID, tblB, connB)

	mgrA.Initiate(entryBinA)
	initPkt := <-connA.out
	mgrB.HandlePacket(initPkt.data, &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1000})
	var respPkt testMsg
	select {
	case respPkt = <-connB.out:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for resp packet")
	}

	addrB := &net.UDPAddr{IP: net.ParseIP("2.2.2.2"), Port: 2000}
	forged := append([]byte(nil), respPkt.data...)
	for i := headerSize; i < len(forged); i++ {
		forged[i] = byte(i)
	}
	mgrA.HandlePacket(forged, addrB)
	if entryBinA.GetSession() != nil {
		t.Fatal("forged Resp must not establish a session")
	}

	mgrA.HandlePacket(respPkt.data, addrB)
	select {
	case <-established:
	case <-time.After(time.Second):
		t.Fatal("genuine Resp after a forged one did not establish the session")
	}

	// The handshake is complete: replaying the Resp does nothing.
	mgrA.HandlePacket(respPkt.data, addrB)
	select {
	case <-established:
		t.Error("replayed Resp established a second session")
	case <-time.After(20 * time.Millisecond):
	}
}

// Init timestamps survive a restart: a new manager using the same replay
// state file rejects an Init the previous one accepted.
func TestManager_ReplayStateSurvivesRestart(t *testing.T) {
	idA, _ := crypto.Generate()
	idB, _ := crypto.Generate()
	var netID [16]byte
	path := filepath.Join(t.TempDir(), "handshake-replay.json")

	tblA := peer.New()
	entryBinA := makeTestEntry(idB, "10.0.0.2", "2.2.2.2:2000")
	tblA.Upsert(entryBinA)
	connA := newTestConn()
	New(idA, netID, tblA, connA).Initiate(entryBinA)
	initPkt := <-connA.out
	addrA := &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1000}

	run := func() (*Manager, *testConn) {
		tblB := peer.New()
		tblB.Upsert(makeTestEntry(idA, "10.0.0.1", "1.1.1.1:1000"))
		connB := newTestConn()
		mgrB := New(idB, netID, tblB, connB)
		if err := mgrB.UseReplayState(path); err != nil {
			t.Fatalf("UseReplayState: %v", err)
		}
		return mgrB, connB
	}

	mgr1, conn1 := run()
	mgr1.HandlePacket(initPkt.data, addrA)
	select {
	case <-conn1.out:
	case <-time.After(time.Second):
		t.Fatal("first Init was not answered")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("replay state not saved: %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Errorf("replay state mode = %o, want 600", info.Mode().Perm())
	}

	mgr2, conn2 := run()
	mgr2.HandlePacket(initPkt.data, addrA)
	select {
	case <-conn2.out:
		t.Fatal("Init replayed after a restart was answered")
	case <-time.After(20 * time.Millisecond):
	}
}

func TestManager_UseReplayState_DropsOldAndDamaged(t *testing.T) {
	dir := t.TempDir()
	var fresh, old [32]byte
	fresh[0], old[0] = 1, 2
	now := time.Now().UnixNano()
	data, _ := json.Marshal(replayFile{Version: 1, Peers: map[string]int64{
		hex.EncodeToString(fresh[:]): now,
		hex.EncodeToString(old[:]):   now - int64(time.Hour),
		"not-hex":                    now,
	}})
	path := filepath.Join(dir, "replay.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	m := New(nil, [16]byte{}, peer.New(), newTestConn())
	if err := m.UseReplayState(path); err != nil {
		t.Fatal(err)
	}
	if len(m.initTimestamps) != 1 || m.initTimestamps[fresh] != now {
		t.Errorf("loaded %v, want only the fresh entry", m.initTimestamps)
	}

	damaged := filepath.Join(dir, "damaged.json")
	if err := os.WriteFile(damaged, []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := New(nil, [16]byte{}, peer.New(), newTestConn()).UseReplayState(damaged); err != nil {
		t.Errorf("damaged file should not be fatal: %v", err)
	}
}
