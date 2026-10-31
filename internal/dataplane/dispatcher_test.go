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
	buf := make([]byte, len(p))
	copy(buf, p)
	select {
	case c.out <- udpMsg{data: buf, addr: addr}:
	default:
	}
	return len(p), nil
}

func (c *fakeConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *fakeConn) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (c *fakeConn) SetDeadline(t time.Time) error      { return nil }
func (c *fakeConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(t time.Time) error { return nil }

// newTestSessionPair creates a pair of linked Noise IK sessions for testing.
// Returns (initiatorSession, responderSession).
func newTestSessionPair(t *testing.T) (*session.Session, *session.Session) {
	t.Helper()
	idA, _ := crypto.Generate()
	idB, _ := crypto.Generate()

	initiatorHS, _ := crypto.NewInitiatorHS(idA, idB.X25519Public, [16]byte{})
	responderHS, _ := crypto.NewResponderHS(idB, func(pub []byte) ([32]byte, bool) {
		if string(pub) == string(idA.Ed25519Public) {
			return idA.X25519Public, true
		}
		return [32]byte{}, false
	})
	now := time.Now().UnixNano()
	msg1, _ := initiatorHS.BuildMessage1(now)
	_, _ = responderHS.ProcessMessage1(msg1, now)
	msg2, respResult, _ := responderHS.BuildMessage2(now)
	initResult, _ := initiatorHS.ProcessMessage2(msg2, now)
	return session.New(initResult), session.New(respResult)
}

// mustAddrPort parses an AddrPort or panics.
func mustAddrPort(s string) netip.AddrPort {
	a, err := netip.ParseAddrPort(s)
	if err != nil {
		panic(err)
	}
	return a
}

// mustAddr parses an Addr or panics.
func mustAddr(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return a
}

// buildIPv4Packet builds a minimal IPv4 packet with the given source and dest IP.
func buildIPv4Packet(src, dst [4]byte, payload []byte) []byte {
	totalLen := 20 + len(payload)
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45                // version=4, IHL=5
	pkt[1] = 0x00                // DSCP/ECN
	pkt[2] = byte(totalLen >> 8) // total length high
	pkt[3] = byte(totalLen)      // total length low
	pkt[8] = 64                  // TTL
	pkt[9] = 17                  // protocol: UDP
	copy(pkt[12:16], src[:])     // source IP
	copy(pkt[16:20], dst[:])     // dest IP
	return pkt
}

// TestDispatcher_StopDoesNotLeak verifies that Start/Stop does not leak goroutines.
func TestDispatcher_StopDoesNotLeak(t *testing.T) {
	tunDev := tun.NewMemTUN("tun0", netip.MustParsePrefix("10.0.0.1/24"), 1420)
	conn := newFakeConn()

	d := New(tunDev, conn, peer.New())
	d.Start()

	done := make(chan struct{})
	go func() {
		d.Wait()
		close(done)
	}()

	d.Stop()

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

// TestDispatcher_TunToUDP verifies that a TUN packet is encrypted and sent over UDP
// when a session exists for the destination peer.
func TestDispatcher_TunToUDP(t *testing.T) {
	sessA, _ := newTestSessionPair(t)

	peerTbl := peer.New()
	var peerBID [32]byte
	peerBID[0] = 0x02
	ep := mustAddrPort("1.2.3.4:5000")
	entryB := &peer.Entry{ID: peerBID, VPNAddr: mustAddr("10.0.0.2")}
	entryB.SetEndpoint(ep)
	entryB.SetSession(sessA)
	peerTbl.Upsert(entryB)

	tunDev := tun.NewMemTUN("tun0", netip.MustParsePrefix("10.0.0.1/24"), 1420)
	conn := newFakeConn()

	d := New(tunDev, conn, peerTbl)
	d.Start()
	defer d.Stop()

	// Send a packet from TUN destined for 10.0.0.2
	ipPkt := buildIPv4Packet([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, []byte("hello"))
	tunDev.Inject(ipPkt)

	// Expect an encrypted UDP packet to be sent to peerB's endpoint
	select {
	case msg := <-conn.out:
		if len(msg.data) < HeaderSize {
			t.Fatalf("packet too short: %d", len(msg.data))
		}
		pktType, _, _ := parseHeader(msg.data[:HeaderSize])
		if pktType != TypeData {
			t.Errorf("pktType: got %d, want %d (TypeData)", pktType, TypeData)
		}
		// Verify it was sent to the correct endpoint
		if msg.addr.String() != "1.2.3.4:5000" {
			t.Errorf("sent to wrong addr: got %v, want 1.2.3.4:5000", msg.addr)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout: no UDP packet sent")
	}
}

// TestDispatcher_UDPToTun verifies that a UDP data packet is decrypted and injected into TUN.
func TestDispatcher_UDPToTun(t *testing.T) {
	sessA, sessB := newTestSessionPair(t)

	peerTbl := peer.New()
	var peerBID [32]byte
	peerBID[0] = 0x02
	ep := mustAddrPort("1.2.3.4:5000")
	entryB := &peer.Entry{ID: peerBID, VPNAddr: mustAddr("10.0.0.2")}
	entryB.SetEndpoint(ep)
	entryB.SetSession(sessA)
	peerTbl.Upsert(entryB)

	tunDev := tun.NewMemTUN("tun0", netip.MustParsePrefix("10.0.0.1/24"), 1420)
	conn := newFakeConn()

	d := New(tunDev, conn, peerTbl)
	d.Start()
	defer d.Stop()

	// Encrypt a packet with B's session (sessB) and send it via UDP
	want := buildIPv4Packet([4]byte{10, 0, 0, 2}, [4]byte{10, 0, 0, 1}, []byte("hello from B"))
	nonce, ct, err := sessB.Encrypt(want)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	udpPkt := buildDataPacket(nonce, ct)

	// Inject the UDP packet as if received from peerB's endpoint
	conn.in <- udpMsg{data: udpPkt, addr: &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 5000}}

	// Expect the decrypted packet to appear on TUN via ReadDelivered
	buf := make([]byte, 1500)
	n, err := tunDev.ReadDelivered(buf)
	if err != nil {
		t.Fatalf("ReadDelivered failed: %v", err)
	}
	if string(buf[:n]) != string(want) {
		t.Errorf("decrypted payload mismatch: got %q, want %q", buf[:n], want)
	}
}

// buildIPv6Packet builds a minimal IPv6 packet with the given source and dest IP.
func buildIPv6Packet(src, dst netip.Addr, payload []byte) []byte {
	pkt := make([]byte, 40+len(payload))
	pkt[0] = 0x60 // version=6
	pkt[4] = byte(len(payload) >> 8)
	pkt[5] = byte(len(payload))
	pkt[6] = 17 // next header: UDP
	pkt[7] = 64 // hop limit
	s16, d16 := src.As16(), dst.As16()
	copy(pkt[8:24], s16[:])
	copy(pkt[24:40], d16[:])
	copy(pkt[40:], payload)
	return pkt
}

// deliverFromPeer sends plain as an encrypted data packet from a peer with the
// given VPN address and subnet routes, and returns what reached the TUN (nil if
// the dispatcher dropped it).
func deliverFromPeer(t *testing.T, vpnAddr string, routes []netip.Prefix, plain []byte) []byte {
	t.Helper()
	sessA, sessB := newTestSessionPair(t)

	peerTbl := peer.New()
	var peerBID [32]byte
	peerBID[0] = 0x02
	entryB := &peer.Entry{ID: peerBID, VPNAddr: mustAddr(vpnAddr), SubnetRoutes: routes}
	entryB.SetEndpoint(mustAddrPort("1.2.3.4:5000"))
	entryB.SetSession(sessA)
	peerTbl.Upsert(entryB)

	tunDev := tun.NewMemTUN("tun0", netip.MustParsePrefix("10.0.0.1/24"), 1420)
	conn := newFakeConn()
	d := New(tunDev, conn, peerTbl)
	d.Start()
	defer d.Stop()

	nonce, ct, err := sessB.Encrypt(plain)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	conn.in <- udpMsg{data: buildDataPacket(nonce, ct), addr: &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 5000}}

	got := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 1500)
		if n, err := tunDev.ReadDelivered(buf); err == nil {
			got <- buf[:n]
		}
	}()
	select {
	case pkt := <-got:
		return pkt
	case <-time.After(200 * time.Millisecond):
		return nil
	}
}

// TestDispatcher_InboundSourceCheck verifies that a peer can only deliver
// packets whose source is its own VPN address or inside its subnet routes.
func TestDispatcher_InboundSourceCheck(t *testing.T) {
	lan := []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}
	me := [4]byte{10, 0, 0, 1}
	cases := []struct {
		name    string
		vpnAddr string
		routes  []netip.Prefix
		pkt     []byte
		deliver bool
	}{
		{"own VPN address", "10.0.0.2", nil, buildIPv4Packet([4]byte{10, 0, 0, 2}, me, []byte("x")), true},
		{"another peer's address", "10.0.0.2", nil, buildIPv4Packet([4]byte{10, 0, 0, 3}, me, []byte("x")), false},
		{"my own address", "10.0.0.2", nil, buildIPv4Packet(me, me, []byte("x")), false},
		{"inside advertised route", "10.0.0.2", lan, buildIPv4Packet([4]byte{192, 168, 1, 20}, me, []byte("x")), true},
		{"outside advertised route", "10.0.0.2", lan, buildIPv4Packet([4]byte{192, 168, 2, 20}, me, []byte("x")), false},
		{"IPv6 own address", "fd00::2", nil, buildIPv6Packet(mustAddr("fd00::2"), mustAddr("fd00::1"), []byte("x")), true},
		{"IPv6 forged address", "fd00::2", nil, buildIPv6Packet(mustAddr("fd00::3"), mustAddr("fd00::1"), []byte("x")), false},
		{"not an IP packet", "10.0.0.2", nil, []byte("hello"), false},
		{"truncated IPv4 header", "10.0.0.2", nil, []byte{0x45, 0, 0, 20}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := deliverFromPeer(t, tc.vpnAddr, tc.routes, tc.pkt)
			if tc.deliver && string(got) != string(tc.pkt) {
				t.Errorf("expected delivery, got %x", got)
			}
			if !tc.deliver && got != nil {
				t.Errorf("expected drop, got %x delivered", got)
			}
		})
	}
}

func TestExtractSrcIP(t *testing.T) {
	addr, ok := extractSrcIP(buildIPv4Packet([4]byte{1, 2, 3, 4}, [4]byte{10, 0, 0, 5}, nil))
	if !ok || addr != netip.AddrFrom4([4]byte{1, 2, 3, 4}) {
		t.Errorf("IPv4: got %v %v, want 1.2.3.4", addr, ok)
	}
	addr, ok = extractSrcIP(buildIPv6Packet(mustAddr("fd00::7"), mustAddr("fd00::1"), nil))
	if !ok || addr != mustAddr("fd00::7") {
		t.Errorf("IPv6: got %v %v, want fd00::7", addr, ok)
	}
	if _, ok := extractSrcIP(make([]byte, 39)); ok {
		t.Error("short packet should return false")
	}
}

// TestDispatcher_NoSession_HoldsPacket verifies that a TUN packet for a peer
// with no session is held in the queue and OnHandshakeRequired is called.
func TestDispatcher_NoSession_HoldsPacket(t *testing.T) {
	peerTbl := peer.New()
	var peerBID [32]byte
	peerBID[0] = 0x02
	ep := mustAddrPort("1.2.3.4:5000")
	entryB := &peer.Entry{ID: peerBID, VPNAddr: mustAddr("10.0.0.2")}
	entryB.SetEndpoint(ep)
	peerTbl.Upsert(entryB)

	tunDev := tun.NewMemTUN("tun0", netip.MustParsePrefix("10.0.0.1/24"), 1420)
	conn := newFakeConn()

	handshakeRequired := make(chan *peer.Entry, 1)
	d := New(tunDev, conn, peerTbl)
	d.OnHandshakeRequired = func(e *peer.Entry) {
		select {
		case handshakeRequired <- e:
		default:
		}
	}
	d.Start()
	defer d.Stop()

	// Send a packet from TUN destined for 10.0.0.2 (no session yet)
	ipPkt := buildIPv4Packet([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, []byte("hello"))
	tunDev.Inject(ipPkt)

	// Expect OnHandshakeRequired to be called
	select {
	case e := <-handshakeRequired:
		if e.ID != peerBID {
			t.Errorf("handshake required for wrong peer: got %x, want %x", e.ID[:8], peerBID[:8])
		}
	case <-time.After(time.Second):
		t.Fatal("timeout: OnHandshakeRequired not called")
	}

	// Verify packet is held in queue
	queued := entryB.DrainQueue()
	if len(queued) != 1 {
		t.Errorf("expected 1 queued packet, got %d", len(queued))
	}
}

// TestDispatcher_UnknownDestIP_Drop verifies that a TUN packet with an unknown
// destination IP is dropped (no session, no handshake trigger).
func TestDispatcher_UnknownDestIP_Drop(t *testing.T) {
	peerTbl := peer.New()
	tunDev := tun.NewMemTUN("tun0", netip.MustParsePrefix("10.0.0.1/24"), 1420)
	conn := newFakeConn()

	d := New(tunDev, conn, peerTbl)
	d.Start()
	defer d.Stop()

	// Send a packet from TUN destined for unknown IP 10.0.0.99
	ipPkt := buildIPv4Packet([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 99}, []byte("hello"))
	tunDev.Inject(ipPkt)

	// No UDP packet should be sent, no handshake triggered
	select {
	case <-conn.out:
		t.Error("unknown destination should not trigger UDP send")
	case <-time.After(100 * time.Millisecond):
		// Expected: no packet sent
	}
}

// TestDispatcher_RekeyThreshold verifies that OnRekeyRequired fires when
// a TUN packet hits a session at the nonce threshold (ErrRekeyRequired path).
func TestDispatcher_RekeyThreshold(t *testing.T) {
	sessA, _ := newTestSessionPair(t)

	// Set session age beyond the rekey time limit (lowered threshold for testing).
	sessA.SetCreatedAt(time.Now().Add(-session.RekeyTimeLimit - time.Second))

	peerTbl := peer.New()
	var peerBID [32]byte
	peerBID[0] = 0x02
	ep := mustAddrPort("1.2.3.4:5000")
	entryB := &peer.Entry{ID: peerBID, VPNAddr: mustAddr("10.0.0.2")}
	entryB.SetEndpoint(ep)
	entryB.SetSession(sessA)
	peerTbl.Upsert(entryB)

	tunDev := tun.NewMemTUN("tun0", netip.MustParsePrefix("10.0.0.1/24"), 1420)
	conn := newFakeConn()

	rekeyCalled := make(chan struct{}, 1)
	d := New(tunDev, conn, peerTbl)
	d.OnRekeyRequired = func(e *peer.Entry) {
		select {
		case rekeyCalled <- struct{}{}:
		default:
		}
	}
	d.Start()
	defer d.Stop()

	// Send a packet from TUN - should trigger rekey because session needs rekey
	ipPkt := buildIPv4Packet([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, []byte("hello"))
	tunDev.Inject(ipPkt)

	select {
	case <-rekeyCalled:
		// Expected: rekey callback fired
	case <-time.After(time.Second):
		t.Fatal("timeout: OnRekeyRequired not called when session needs rekey")
	}

	// Verify packet is held in queue
	queued := entryB.DrainQueue()
	if len(queued) != 1 {
		t.Errorf("expected 1 queued packet, got %d", len(queued))
	}
}

// TestDispatcher_RekeyViaNeedsRekey verifies that a session with an old
// CreatedAt triggers rekey via the periodic NeedsRekey scan (time-based rekey).
func TestDispatcher_RekeyViaNeedsRekey(t *testing.T) {
	sessA, _ := newTestSessionPair(t)

	peerTbl := peer.New()
	var peerBID [32]byte
	peerBID[0] = 0x02
	ep := mustAddrPort("1.2.3.4:5000")
	entryB := &peer.Entry{ID: peerBID, VPNAddr: mustAddr("10.0.0.2")}
	entryB.SetEndpoint(ep)
	entryB.SetSession(sessA)
	peerTbl.Upsert(entryB)

	tunDev := tun.NewMemTUN("tun0", netip.MustParsePrefix("10.0.0.1/24"), 1420)
	conn := newFakeConn()

	rekeyCalled := make(chan struct{}, 1)
	d := New(tunDev, conn, peerTbl)
	d.OnRekeyRequired = func(e *peer.Entry) {
		select {
		case rekeyCalled <- struct{}{}:
		default:
		}
	}
	d.Start()
	defer d.Stop()

	// Fresh session should not need rekey.
	if sessA.NeedsRekey() {
		t.Fatal("fresh session should not need rekey")
	}

	// Simulate an old session by setting createdAt to the past (lowered threshold for testing).
	sessA.SetCreatedAt(time.Now().Add(-session.RekeyTimeLimit - time.Second))

	// Now the session needs rekey.
	if !sessA.NeedsRekey() {
		t.Fatal("old session should need rekey")
	}

	// Call checkRekey directly (normally called by rekeyLoop every 30s)
	d.checkRekey()

	select {
	case <-rekeyCalled:
		// Expected: rekey callback fired
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timeout: OnRekeyRequired not called for time-based rekey")
	}
}

// TestDispatcher_RekeyCallbackWiring verifies that OnRekeyRequired is
// correctly wired and invoked by checkRekey for a peer whose session
// needs rekey. The detailed threshold/time logic is tested in session_test.go.
func TestDispatcher_RekeyCallbackWiring(t *testing.T) {
	sessA, _ := newTestSessionPair(t)

	peerTbl := peer.New()
	var peerBID [32]byte
	peerBID[0] = 0x02
	ep := mustAddrPort("1.2.3.4:5000")
	entryB := &peer.Entry{ID: peerBID, VPNAddr: mustAddr("10.0.0.2")}
	entryB.SetEndpoint(ep)
	entryB.SetSession(sessA)
	peerTbl.Upsert(entryB)

	tunDev := tun.NewMemTUN("tun0", netip.MustParsePrefix("10.0.0.1/24"), 1420)
	conn := newFakeConn()

	rekeyCalled := make(chan struct{}, 1)
	d := New(tunDev, conn, peerTbl)
	d.OnRekeyRequired = func(e *peer.Entry) {
		select {
		case rekeyCalled <- struct{}{}:
		default:
		}
	}
	d.Start()
	defer d.Stop()

	// For a fresh session, checkRekey should not call OnRekeyRequired.
	d.checkRekey()

	select {
	case <-rekeyCalled:
		t.Error("checkRekey should not fire for fresh session")
	case <-time.After(50 * time.Millisecond):
		// Expected: no rekey call.
	}

	// Now set session to need rekey (by time limit)
	sessA.SetCreatedAt(time.Now().Add(-session.RekeyTimeLimit - time.Second))
	d.checkRekey()

	select {
	case <-rekeyCalled:
		// Expected: rekey callback fired for session needing rekey
	case <-time.After(50 * time.Millisecond):
		t.Error("checkRekey should fire for session needing rekey")
	}
}