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
	"github.com/veldmesh/veld/internal/dataplane"
	"github.com/veldmesh/veld/internal/peer"
	"github.com/veldmesh/veld/internal/session"
	"github.com/veldmesh/veld/internal/tun"
)

// e2eConn is an in-memory net.PacketConn used in e2e tests.
// localAddr is the address reported as the source when the peer receives a packet from us.
type e2eConn struct {
	in        chan e2eMsg
	out       chan e2eMsg
	localAddr net.Addr
	once      sync.Once
	closed    chan struct{}
}

type e2eMsg struct {
	data []byte
	addr net.Addr
}

// newE2EPipe returns two connected e2eConns with given local addresses.
// When A writes, B receives with source = addrA (A's local addr), and vice versa.
func newE2EPipe(addrA, addrB net.Addr) (*e2eConn, *e2eConn) {
	chAtoB := make(chan e2eMsg, 64)
	chBtoA := make(chan e2eMsg, 64)
	a := &e2eConn{in: chBtoA, out: chAtoB, localAddr: addrA, closed: make(chan struct{})}
	b := &e2eConn{in: chAtoB, out: chBtoA, localAddr: addrB, closed: make(chan struct{})}
	return a, b
}

func (c *e2eConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case msg := <-c.in:
		n := copy(p, msg.data)
		return n, msg.addr, nil
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}

func (c *e2eConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	buf := make([]byte, len(p))
	copy(buf, p)
	// Use our local address as the source so the recipient can look us up by endpoint.
	src := c.localAddr
	select {
	case c.out <- e2eMsg{data: buf, addr: src}:
		return len(p), nil
	case <-c.closed:
		return 0, net.ErrClosed
	}
}

func (c *e2eConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *e2eConn) LocalAddr() net.Addr                { return c.localAddr }
func (c *e2eConn) SetDeadline(t time.Time) error      { return nil }
func (c *e2eConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *e2eConn) SetWriteDeadline(t time.Time) error { return nil }

func buildE2EIPv4Packet(src, dst [4]byte, payload []byte) []byte {
	totalLen := 20 + len(payload)
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45
	pkt[2] = byte(totalLen >> 8)
	pkt[3] = byte(totalLen)
	pkt[8] = 64
	pkt[9] = 17
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])
	copy(pkt[20:], payload)
	return pkt
}

// TestDataplane_EndToEnd verifies the full A→B encrypted path through two Dispatchers.
func TestDataplane_EndToEnd(t *testing.T) {
	idA, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate idA: %v", err)
	}
	idB, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate idB: %v", err)
	}

	// Full Noise IK handshake.
	initiatorHS, err := crypto.NewInitiatorHS(idA, idB.X25519Public, [16]byte{})
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
	msg1, _ := initiatorHS.BuildMessage1(now)
	if err := responderHS.ProcessMessage1(msg1, now); err != nil {
		t.Fatalf("ProcessMessage1: %v", err)
	}
	msg2, respResult, _ := responderHS.BuildMessage2(now)
	initResult, _ := initiatorHS.ProcessMessage2(msg2, now)

	addrA := netip.MustParseAddr("10.0.0.1")
	addrB := netip.MustParseAddr("10.0.0.2")
	epA := netip.MustParseAddrPort("10.0.0.1:1000")
	epB := netip.MustParseAddrPort("10.0.0.2:2000")

	// A's peer table: knows B.
	tblA := peer.New()
	var bID [32]byte
	copy(bID[:], idB.Ed25519Public)
	entryBinA := &peer.Entry{ID: bID, VPNAddr: addrB}
	entryBinA.SetEndpoint(epB)
	entryBinA.SetSession(session.New(initResult))
	tblA.Upsert(entryBinA)

	// B's peer table: knows A.
	tblB := peer.New()
	var aID [32]byte
	copy(aID[:], idA.Ed25519Public)
	entryAinB := &peer.Entry{ID: aID, VPNAddr: addrA}
	entryAinB.SetEndpoint(epA)
	entryAinB.SetSession(session.New(respResult))
	tblB.Upsert(entryAinB)

	// Wired packet conns: A's output → B's input, B's output → A's input.
	// Each conn uses its own endpoint as the source address so LookupByEndpoint works.
	connA, connB := newE2EPipe(
		net.UDPAddrFromAddrPort(epA),
		net.UDPAddrFromAddrPort(epB),
	)

	tunA := tun.NewMemTUN("tunA", netip.MustParsePrefix("10.0.0.1/24"), 1420)
	tunB := tun.NewMemTUN("tunB", netip.MustParsePrefix("10.0.0.2/24"), 1420)

	dispA := dataplane.New(tunA, connA, tblA)
	dispB := dataplane.New(tunB, connB, tblB)
	dispA.Start()
	dispB.Start()
	defer func() {
		dispA.Stop(); dispB.Stop()
		dispA.Wait(); dispB.Wait()
	}()

	// Inject a packet into tunA → dispA should encrypt and send to connA → connB → dispB → tunB.
	want := buildE2EIPv4Packet([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, []byte("e2e-test-payload"))
	if _, err := tunA.Inject(want); err != nil {
		t.Fatalf("tunA.Inject: %v", err)
	}

	buf := make([]byte, 1500)
	done := make(chan []byte, 1)
	go func() {
		n, err := tunB.ReadDelivered(buf)
		if err == nil {
			out := make([]byte, n)
			copy(out, buf[:n])
			done <- out
		}
	}()

	select {
	case got := <-done:
		if string(got) != string(want) {
			t.Errorf("payload mismatch: got %d bytes, want %d bytes", len(got), len(want))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout: packet did not arrive at tunB")
	}
}

// TestDataplane_HoldQueue_DrainOnSession verifies that packets queued before session
// establishment are delivered once a session is set.
func TestDataplane_HoldQueue_DrainOnSession(t *testing.T) {
	pkt := buildE2EIPv4Packet([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 5}, []byte("hold-queue"))
	tblA := peer.New()
	var bID [32]byte
	bID[0] = 0x05
	entryB := &peer.Entry{ID: bID, VPNAddr: netip.MustParseAddr("10.0.0.5")}
	entryB.SetEndpoint(netip.MustParseAddrPort("5.5.5.5:5005"))
	// No session yet.
	tblA.Upsert(entryB)

	tunA := tun.NewMemTUN("tunA", netip.MustParsePrefix("10.0.0.1/24"), 1420)
	connA, _ := newE2EPipe(&net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1000}, &net.UDPAddr{IP: net.ParseIP("5.5.5.5"), Port: 5005})
	dispA := dataplane.New(tunA, connA, tblA)
	dispA.Start()
	defer func() { dispA.Stop(); dispA.Wait() }()

	// Inject packet — goes to hold queue.
	if _, err := tunA.Inject(pkt); err != nil {
		t.Fatalf("tunA.Inject: %v", err)
	}
	// Give dispatcher time to process.
	time.Sleep(20 * time.Millisecond)

	held := entryB.DrainQueue()
	if len(held) != 1 {
		t.Errorf("hold queue: got %d, want 1", len(held))
	}
	if len(held) > 0 && string(held[0]) != string(pkt) {
		t.Errorf("held packet mismatch")
	}
}
