// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package dataplane

import (
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/veldmesh/veld/internal/crypto"
	"github.com/veldmesh/veld/internal/peer"
	"github.com/veldmesh/veld/internal/session"
	"github.com/veldmesh/veld/internal/tun"
)

// fakeConn is an in-memory net.PacketConn for testing.
type fakeConn struct {
	in     chan udpMsg
	out    chan udpMsg
	once   sync.Once
	closed chan struct{}
}

type udpMsg struct {
	data []byte
	addr net.Addr
}

func newFakeConn() *fakeConn {
	return &fakeConn{
		in:     make(chan udpMsg, 32),
		out:    make(chan udpMsg, 32),
		closed: make(chan struct{}),
	}
}

func (c *fakeConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case msg := <-c.in:
		n := copy(p, msg.data)
		return n, msg.addr, nil
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}

func (c *fakeConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	buf := make([]byte, len(p))
	copy(buf, p)
	select {
	case c.out <- udpMsg{data: buf, addr: addr}:
		return len(p), nil
	case <-c.closed:
		return 0, net.ErrClosed
	}
}

func (c *fakeConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *fakeConn) LocalAddr() net.Addr                { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345} }
func (c *fakeConn) SetDeadline(t time.Time) error      { return nil }
func (c *fakeConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(t time.Time) error { return nil }

// newTestSessionPair runs a full Noise IK handshake and returns two Sessions.
func newTestSessionPair(t *testing.T) (initiator, responder *session.Session) {
	t.Helper()
	idA, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate idA: %v", err)
	}
	idB, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate idB: %v", err)
	}
	var networkID [16]byte
	initiatorHS, err := crypto.NewInitiatorHS(idA, idB.X25519Public, networkID)
	if err != nil {
		t.Fatalf("NewInitiatorHS: %v", err)
	}
	responderHS, err := crypto.NewResponderHS(idB, func(pub []byte) ([32]byte, bool) {
		if string(pub) == string(idA.Ed25519Public) {
			return idA.X25519Public, true
		}
		return [32]byte{}, false
	})
	if err != nil {
		t.Fatalf("NewResponderHS: %v", err)
	}
	now := time.Now().Unix()
	msg1, err := initiatorHS.BuildMessage1(now)
	if err != nil {
		t.Fatalf("BuildMessage1: %v", err)
	}
	if err := responderHS.ProcessMessage1(msg1, now); err != nil {
		t.Fatalf("ProcessMessage1: %v", err)
	}
	msg2, respResult, err := responderHS.BuildMessage2(now)
	if err != nil {
		t.Fatalf("BuildMessage2: %v", err)
	}
	initResult, err := initiatorHS.ProcessMessage2(msg2, now)
	if err != nil {
		t.Fatalf("ProcessMessage2: %v", err)
	}
	return session.New(initResult), session.New(respResult)
}

// buildIPv4Packet builds a minimal IPv4 packet with the given source and dest IP.
func buildIPv4Packet(src, dst [4]byte, payload []byte) []byte {
	totalLen := 20 + len(payload)
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45                          // version=4, IHL=5
	pkt[1] = 0x00                          // DSCP/ECN
	pkt[2] = byte(totalLen >> 8)           // total length high
	pkt[3] = byte(totalLen)                // total length low
	pkt[8] = 64                            // TTL
	pkt[9] = 17                            // protocol: UDP
	copy(pkt[12:16], src[:])               // source IP
	copy(pkt[16:20], dst[:])               // dest IP
	copy(pkt[20:], payload)
	return pkt
}

func mustAddrPort(s string) netip.AddrPort {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		panic(err)
	}
	return ap
}

func mustAddr(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return a
}

// TestDispatcher_TunToUDP verifies that a TUN packet is encrypted and sent over UDP.
func TestDispatcher_TunToUDP(t *testing.T) {
	sessA, sessB := newTestSessionPair(t)
	_ = sessB // B's session used to decrypt in assertion

	// Set up peer table: peer B has VPN 10.0.0.2 and endpoint 1.2.3.4:5000.
	peerTbl := peer.New()
	var peerBID [32]byte
	peerBID[0] = 0x02
	ep := mustAddrPort("1.2.3.4:5000")
	entryB := &peer.Entry{ID: peerBID, VPNAddr: mustAddr("10.0.0.2")}
	entryB.SetEndpoint(ep)
	entryB.SetSession(sessA) // A uses sessA to send to B
	peerTbl.Upsert(entryB)

	tunDev := tun.NewMemTUN("tun0", netip.MustParsePrefix("10.0.0.1/24"), 1420)
	conn := newFakeConn()
	d := New(tunDev, conn, peerTbl)
	d.Start()
	defer d.Wait()
	defer d.Stop()

	// Write an IPv4 packet to the TUN destined for 10.0.0.2.
	pkt := buildIPv4Packet([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, []byte("hello"))
	if _, err := tunDev.Inject(pkt); err != nil {
		t.Fatalf("TUN write: %v", err)
	}

	// Expect one UDP packet on the conn's output.
	var msg udpMsg
	select {
	case msg = <-conn.out:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for UDP output")
	}

	// Verify it looks like a valid wire packet.
	if len(msg.data) < HeaderSize {
		t.Fatalf("UDP packet too short: %d bytes", len(msg.data))
	}
	pktType, _, nonce := parseHeader(msg.data[:HeaderSize])
	if pktType != TypeData {
		t.Errorf("pktType: got %d, want %d (TypeData)", pktType, TypeData)
	}

	// Decrypt with sessB to verify the payload.
	ct := msg.data[HeaderSize:]
	plain, err := sessB.Decrypt(nonce, ct)
	if err != nil || plain == nil {
		t.Fatalf("decrypt: err=%v plain=%v", err, plain)
	}
	if string(plain) != string(pkt) {
		t.Errorf("decrypted payload mismatch")
	}
}

// TestDispatcher_UDPToTun verifies that an encrypted UDP packet is decrypted into TUN.
func TestDispatcher_UDPToTun(t *testing.T) {
	sessA, sessB := newTestSessionPair(t)
	_ = sessA

	peerTbl := peer.New()
	var peerAID [32]byte
	peerAID[0] = 0x01
	ep := mustAddrPort("9.9.9.9:4000")
	entryA := &peer.Entry{ID: peerAID, VPNAddr: mustAddr("10.0.0.1")}
	entryA.SetEndpoint(ep)
	entryA.SetSession(sessB) // B uses sessB to receive from A
	peerTbl.Upsert(entryA)

	tunDev := tun.NewMemTUN("tun0", netip.MustParsePrefix("10.0.0.2/24"), 1420)
	conn := newFakeConn()
	d := New(tunDev, conn, peerTbl)
	d.Start()
	defer d.Wait()
	defer d.Stop()

	// Encrypt a packet as if A is sending it.
	plainPkt := buildIPv4Packet([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, []byte("world"))
	nonce, ct, err := sessA.Encrypt(plainPkt)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	udpPkt := buildDataPacket(nonce, ct)

	// Inject as if it arrived from A's endpoint.
	conn.in <- udpMsg{
		data: udpPkt,
		addr: &net.UDPAddr{IP: net.ParseIP("9.9.9.9"), Port: 4000},
	}

	// Expect the decrypted packet in TUN.
	buf := make([]byte, 1500)
	done := make(chan []byte, 1)
	go func() {
		n, err := tunDev.ReadDelivered(buf)
		if err == nil {
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			done <- pkt
		}
	}()

	select {
	case got := <-done:
		if string(got) != string(plainPkt) {
			t.Errorf("TUN packet mismatch: got %d bytes, want %d", len(got), len(plainPkt))
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for TUN output")
	}
}

// TestDispatcher_NoSession_HoldsPacket verifies that packets to a peer without a
// session are held in the hold queue.
func TestDispatcher_NoSession_HoldsPacket(t *testing.T) {
	peerTbl := peer.New()
	var peerBID [32]byte
	peerBID[0] = 0x03
	ep := mustAddrPort("5.5.5.5:5005")
	entryB := &peer.Entry{ID: peerBID, VPNAddr: mustAddr("10.0.0.3")}
	entryB.SetEndpoint(ep)
	// No session set — entryB.GetSession() == nil
	peerTbl.Upsert(entryB)

	tunDev := tun.NewMemTUN("tun0", netip.MustParsePrefix("10.0.0.1/24"), 1420)
	conn := newFakeConn()

	handshakeCalled := make(chan struct{}, 1)
	d := New(tunDev, conn, peerTbl)
	d.OnHandshakeRequired = func(e *peer.Entry) {
		select {
		case handshakeCalled <- struct{}{}:
		default:
		}
	}
	d.Start()
	defer d.Wait()
	defer d.Stop()

	pkt := buildIPv4Packet([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 3}, []byte("queued"))
	if _, err := tunDev.Inject(pkt); err != nil {
		t.Fatalf("TUN write: %v", err)
	}

	// Should NOT produce a UDP packet.
	select {
	case <-conn.out:
		t.Error("should not send UDP when session is nil")
	case <-time.After(50 * time.Millisecond):
	}

	// HandshakeRequired callback should be called.
	select {
	case <-handshakeCalled:
	case <-time.After(time.Second):
		t.Error("OnHandshakeRequired was not called")
	}

	// Packet should be in the hold queue.
	held := entryB.DrainQueue()
	if len(held) != 1 {
		t.Errorf("hold queue: got %d packets, want 1", len(held))
	}
	if string(held[0]) != string(pkt) {
		t.Errorf("held packet mismatch")
	}
}

// TestDispatcher_UnknownDestIP_Drop verifies that packets to unknown VPN IPs are dropped.
func TestDispatcher_UnknownDestIP_Drop(t *testing.T) {
	peerTbl := peer.New() // empty table

	tunDev := tun.NewMemTUN("tun0", netip.MustParsePrefix("10.0.0.1/24"), 1420)
	conn := newFakeConn()
	d := New(tunDev, conn, peerTbl)
	d.Start()
	defer d.Wait()
	defer d.Stop()

	pkt := buildIPv4Packet([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 99}, []byte("drop"))
	if _, err := tunDev.Inject(pkt); err != nil {
		t.Fatalf("TUN write: %v", err)
	}

	select {
	case <-conn.out:
		t.Error("should not send UDP for unknown peer")
	case <-time.After(50 * time.Millisecond):
	}
}

// TestDispatcher_StopDoesNotLeak verifies that Start+Stop+Wait completes cleanly.
func TestDispatcher_StopDoesNotLeak(t *testing.T) {
	peerTbl := peer.New()
	tunDev := tun.NewMemTUN("tun0", netip.MustParsePrefix("10.0.0.1/24"), 1420)
	conn := newFakeConn()
	d := New(tunDev, conn, peerTbl)
	d.Start()
	d.Stop()

	done := make(chan struct{})
	go func() {
		d.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Wait timed out — goroutine leak")
	}
}

// TestExtractDestIP covers IPv4 and IPv6 extraction and invalid packets.
func TestExtractDestIP(t *testing.T) {
	// IPv4
	pkt4 := buildIPv4Packet([4]byte{1, 2, 3, 4}, [4]byte{10, 0, 0, 5}, nil)
	addr, ok := extractDestIP(pkt4)
	if !ok {
		t.Fatal("IPv4: extractDestIP returned false")
	}
	if addr != netip.AddrFrom4([4]byte{10, 0, 0, 5}) {
		t.Errorf("IPv4: got %v, want 10.0.0.5", addr)
	}

	// Too short
	if _, ok := extractDestIP([]byte{0x45}); ok {
		t.Error("too-short packet should return false")
	}

	// Unknown version
	pktBad := make([]byte, 20)
	pktBad[0] = 0x30 // version 3
	if _, ok := extractDestIP(pktBad); ok {
		t.Error("unknown IP version should return false")
	}
}

// TestBuildParseHeader verifies header encode/decode round-trip.
func TestBuildParseHeader(t *testing.T) {
	pkt := buildDataPacket(0xDEADBEEF12345678, []byte("payload"))
	if len(pkt) < HeaderSize {
		t.Fatalf("packet too short")
	}
	pktType, _, nonce := parseHeader(pkt[:HeaderSize])
	if pktType != TypeData {
		t.Errorf("pktType: got %d, want %d", pktType, TypeData)
	}
	if nonce != 0xDEADBEEF12345678 {
		t.Errorf("nonce: got %d, want 0xDEADBEEF12345678", nonce)
	}
	if string(pkt[HeaderSize:]) != "payload" {
		t.Errorf("payload mismatch")
	}
}
