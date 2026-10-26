// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package handshake

import (
	"net"
	"net/netip"
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
	sessEstB := make(chan struct{}, 1)

	mgrA := New(idA, netID, tblA, connA)
	mgrA.OnSessionEstablished = func(*peer.Entry) { sessEstA <- struct{}{} }

	mgrB := New(idB, netID, tblB, connB)
	mgrB.OnSessionEstablished = func(*peer.Entry) { sessEstB <- struct{}{} }

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

	// Expect B to have sent a resp and established its session.
	var respPkt testMsg
	select {
	case respPkt = <-connB.out:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for resp packet")
	}
	select {
	case <-sessEstB:
	case <-time.After(time.Second):
		t.Fatal("timeout: B session not established")
	}

	// Feed resp packet to A (as if received from 2.2.2.2:2000 = B's addr).
	addrB := &net.UDPAddr{IP: net.ParseIP("2.2.2.2"), Port: 2000}
	mgrA.HandlePacket(respPkt.data, addrB)

	select {
	case <-sessEstA:
	case <-time.After(time.Second):
		t.Fatal("timeout: A session not established")
	}

	// Verify sessions are set on both sides.
	if entryBinA.GetSession() == nil {
		t.Error("A's session for B should be set")
	}
	if entryAinB.GetSession() == nil {
		t.Error("B's session for A should be set")
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
	sessEstB := make(chan struct{}, 1)
	mgrB.OnSessionEstablished = func(*peer.Entry) { sessEstB <- struct{}{} }

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

	select {
	case <-sessEstB:
	case <-time.After(time.Second):
		t.Fatal("first handshake: B session not established")
	}

	// Verify session is established.
	if entryAinB.GetSession() == nil {
		t.Fatal("session should be established after first Init")
	}
	firstSession := entryAinB.GetSession()

	// Drain the first response packet from connB.
	select {
	case <-connB.out:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for first response")
	}

	// Feed the SAME init packet again (replay) -- should be rejected.
	// The session pointer should remain unchanged.
	mgrB.HandlePacket(initPkt.data, addrA)

	select {
	case <-connB.out:
		t.Error("replayed Init should not trigger a second response")
	case <-time.After(20 * time.Millisecond):
	}

	// Session should be unchanged.
	if entryAinB.GetSession() != firstSession {
		t.Error("replayed Init should not replace existing session")
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
	sessEstB := make(chan struct{}, 1)
	mgrB.OnSessionEstablished = func(*peer.Entry) { sessEstB <- struct{}{} }

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

	select {
	case <-sessEstB:
	case <-time.After(time.Second):
		t.Fatal("first handshake: B session not established")
	}

	if entryAinB.GetSession() == nil {
		t.Fatal("session should be established after first Init")
	}

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

	// Session should be unchanged.
	if entryAinB.GetSession() == nil {
		t.Error("session should still exist")
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
}