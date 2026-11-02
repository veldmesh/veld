// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package dataplane

import (
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/veldmesh/veld/internal/acl"
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

func mustAddrPort(s string) netip.AddrPort {
	a, err := netip.ParseAddrPort(s)
	if err != nil {
		panic(err)
	}
	return a
}

func mustAddr(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return a
}

// buildIPv4Packet builds a minimal IPv4 packet with the given source and dest IP.
// Protocol is set to UDP (17) but no UDP header is included.
// Use for testing IP extraction functions only.
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

// buildUDPv4Packet builds an IPv4 packet with a UDP header.
func buildUDPv4Packet(src, dst [4]byte, srcPort, dstPort uint16, payload []byte) []byte {
	udpLen := 8 + len(payload)
	totalLen := 20 + udpLen
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45
	pkt[1] = 0x00
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[4] = 0x00
	pkt[5] = 0x00
	pkt[6] = 0x00
	pkt[7] = 0x00
	pkt[8] = 64
	pkt[9] = 17 // UDP
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])
	binary.BigEndian.PutUint16(pkt[20:22], srcPort)
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)
	binary.BigEndian.PutUint16(pkt[24:26], uint16(udpLen))
	// UDP checksum = 0 (optional)
	copy(pkt[28:], payload)
	return pkt
}

// buildTCPSYNPacket builds an IPv4 packet with a TCP SYN header.
func buildTCPSYNPacket(src, dst [4]byte, srcPort, dstPort uint16) []byte {
	totalLen := 20 + 20
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45
	pkt[1] = 0x00
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[4] = 0x00
	pkt[5] = 0x00
	pkt[6] = 0x00
	pkt[7] = 0x00
	pkt[8] = 64
	pkt[9] = 6 // TCP
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])
	binary.BigEndian.PutUint16(pkt[20:22], srcPort)
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)
	binary.BigEndian.PutUint32(pkt[24:28], 0)
	binary.BigEndian.PutUint32(pkt[28:32], 0)
	pkt[32] = 0x50
	pkt[33] = 0x02 // SYN
	return pkt
}

// buildTCPACKPacket builds an IPv4 packet with a TCP ACK header (no SYN).
func buildTCPACKPacket(src, dst [4]byte, srcPort, dstPort uint16) []byte {
	totalLen := 20 + 20
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45
	pkt[1] = 0x00
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[4] = 0x00
	pkt[5] = 0x00
	pkt[6] = 0x00
	pkt[7] = 0x00
	pkt[8] = 64
	pkt[9] = 6 // TCP
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])
	binary.BigEndian.PutUint16(pkt[20:22], srcPort)
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)
	binary.BigEndian.PutUint32(pkt[24:28], 1)
	binary.BigEndian.PutUint32(pkt[28:32], 1)
	pkt[32] = 0x50
	pkt[33] = 0x10 // ACK
	return pkt
}

// buildIPv4Fragment builds an IPv4 fragment without transport header.
func buildIPv4Fragment(src, dst [4]byte) []byte {
	pkt := make([]byte, 20+8) // IPv4 header + 8 bytes fragment data
	pkt[0] = 0x45
	pkt[1] = 0x00
	binary.BigEndian.PutUint16(pkt[2:4], 28)
	pkt[4] = 0x00
	pkt[5] = 0x00
	binary.BigEndian.PutUint16(pkt[6:8], 0x2000) // MF flag set, offset=0
	pkt[8] = 64
	pkt[9] = 6 // TCP
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])
	return pkt
}

// buildICMPErrorPacket builds an ICMP error packet quoting the original packet.
func buildICMPErrorPacket(original []byte) []byte {
	// ICMP Destination Unreachable (type 3, code 13)
	maxQuoted := 548
	if maxQuoted > len(original) {
		maxQuoted = len(original)
	}
	pkt := make([]byte, 20+8+maxQuoted)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(20+8+maxQuoted))
	pkt[4] = 0x00
	pkt[5] = 0x00
	pkt[6] = 0x00
	pkt[7] = 0x00
	pkt[8] = 64
	pkt[9] = 1
	copy(pkt[12:16], original[16:20]) // swap src/dst
	copy(pkt[16:20], original[12:16])
	pkt[20] = 3  // Destination Unreachable
	pkt[21] = 13 // Admin Prohibited
	copy(pkt[28:], original[:maxQuoted])
	return pkt
}

// makeDispatcherWithPolicy creates a dispatcher with the given peer IDs and policy.
// Returns the dispatcher, fakeConn, and the peer entry.
func makeDispatcherWithPolicy(t *testing.T, peerAID, peerBID [32]byte, policySrc string) (*Dispatcher, *fakeConn, *peer.Entry) {
	t.Helper()

	sessA, _ := newTestSessionPair(t)

	peerTbl := peer.New()
	ep := mustAddrPort("1.2.3.4:5000")
	entryB := &peer.Entry{ID: peerBID, VPNAddr: mustAddr("10.0.0.2")}
	entryB.SetEndpoint(ep)
	entryB.SetSession(sessA)
	peerTbl.Upsert(entryB)
	peerTbl.Upsert(&peer.Entry{ID: [32]byte{0x03}, VPNAddr: mustAddr("192.168.1.99")})

	tunDev := tun.NewMemTUN("tun0", netip.MustParsePrefix("10.0.0.1/24"), 1420)
	conn := newFakeConn()

	d := New(tunDev, conn, peerTbl)

	// Parse and set policy
	p, _, err := acl.ParsePolicy(policySrc)
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	compiled := p.Compile()
	d.SetPolicyDecider(compiled)
	d.SetSelfPeerID(peerAID)

	d.Start()

	return d, conn, entryB
}
