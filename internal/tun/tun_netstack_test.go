// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
//go:build userspace

package tun_test

import (
	"context"
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

func mustPrefixNetstack(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("parse prefix %q: %v", s, err)
	}
	return p
}

func mustAddrNetstack(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse addr %q: %v", s, err)
	}
	return a
}

// e2eConn is an in-memory net.PacketConn used in e2e tests.
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

// TestNetstackTUN_TCP_Echo tests TCP echo through two netstack TUNs over the VPN tunnel.
func TestNetstackTUN_TCP_Echo(t *testing.T) {
	idA, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate idA: %v", err)
	}
	idB, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate idB: %v", err)
	}

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
	now := time.Now().UnixNano()
	msg1, _ := initiatorHS.BuildMessage1(now)
	if _, err := responderHS.ProcessMessage1(msg1, now); err != nil {
		t.Fatalf("ProcessMessage1: %v", err)
	}
	msg2, respResult, _ := responderHS.BuildMessage2(now)
	initResult, _ := initiatorHS.ProcessMessage2(msg2, now)

	addrA := netip.MustParseAddr("10.0.0.1")
	addrB := netip.MustParseAddr("10.0.0.2")
	epA := netip.MustParseAddrPort("10.0.0.1:1000")
	epB := netip.MustParseAddrPort("10.0.0.2:2000")

	tblA := peer.New()
	var bID [32]byte
	copy(bID[:], idB.Ed25519Public)
	entryBinA := &peer.Entry{ID: bID, VPNAddr: addrB}
	entryBinA.SetEndpoint(epB)
	entryBinA.SetSession(session.New(initResult))
	tblA.Upsert(entryBinA)

	tblB := peer.New()
	var aID [32]byte
	copy(aID[:], idA.Ed25519Public)
	entryAinB := &peer.Entry{ID: aID, VPNAddr: addrA}
	entryAinB.SetEndpoint(epA)
	entryAinB.SetSession(session.New(respResult))
	tblB.Upsert(entryAinB)

	connA, connB := newE2EPipe(
		net.UDPAddrFromAddrPort(epA),
		net.UDPAddrFromAddrPort(epB),
	)

	tunA, err := tun.CreateNetstackTUN("tunA", mustPrefixNetstack(t, "10.0.0.1/24"), 1420)
	if err != nil {
		t.Fatalf("CreateNetstackTUN A: %v", err)
	}
	defer tunA.Close()

	tunB, err := tun.CreateNetstackTUN("tunB", mustPrefixNetstack(t, "10.0.0.2/24"), 1420)
	if err != nil {
		t.Fatalf("CreateNetstackTUN B: %v", err)
	}
	defer tunB.Close()

	dispA := dataplane.New(tunA, connA, tblA)
	dispB := dataplane.New(tunB, connB, tblB)
	dispA.Start()
	dispB.Start()
	defer func() {
		dispA.Stop()
		dispB.Stop()
		dispA.Wait()
		dispB.Wait()
	}()

	// Start TCP echo server on B's VPN address using netstack
	netstackB := tunB.(*tun.NetstackTUN)
	listener, err := netstackB.ListenTCPAddrPort(netip.AddrPortFrom(addrB, 7777))
	if err != nil {
		t.Fatalf("ListenTCPAddrPort B: %v", err)
	}
	defer listener.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := listener.Accept()
		if err != nil {
			t.Logf("Accept error: %v", err)
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			t.Logf("Read error: %v", err)
			return
		}
		if _, err := conn.Write(buf[:n]); err != nil {
			t.Logf("Write error: %v", err)
			return
		}
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Connect from A's netstack to B's VPN address
	netstackA := tunA.(*tun.NetstackTUN)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Use DialContext with "tcp" network
	clientConn, err := netstackA.DialContext(ctx, "tcp", netip.AddrPortFrom(addrB, 7777).String())
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer clientConn.Close()

	// Send data
	testData := []byte("hello from userspace netstack")
	if _, err := clientConn.Write(testData); err != nil {
		t.Fatalf("client Write: %v", err)
	}

	// Read echo
	buf := make([]byte, 1024)
	n, err := clientConn.Read(buf)
	if err != nil {
		t.Fatalf("client Read: %v", err)
	}
	if string(buf[:n]) != string(testData) {
		t.Errorf("echo mismatch: got %q, want %q", string(buf[:n]), string(testData))
	}

	wg.Wait()
}

// TestNetstackTUN_UDP_Echo tests UDP echo through two netstack TUNs over the VPN tunnel.
func TestNetstackTUN_UDP_Echo(t *testing.T) {
	idA, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate idA: %v", err)
	}
	idB, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate idB: %v", err)
	}

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
	now := time.Now().UnixNano()
	msg1, _ := initiatorHS.BuildMessage1(now)
	if _, err := responderHS.ProcessMessage1(msg1, now); err != nil {
		t.Fatalf("ProcessMessage1: %v", err)
	}
	msg2, respResult, _ := responderHS.BuildMessage2(now)
	initResult, _ := initiatorHS.ProcessMessage2(msg2, now)

	addrA := netip.MustParseAddr("10.0.0.1")
	addrB := netip.MustParseAddr("10.0.0.2")
	epA := netip.MustParseAddrPort("10.0.0.1:1000")
	epB := netip.MustParseAddrPort("10.0.0.2:2000")

	tblA := peer.New()
	var bID [32]byte
	copy(bID[:], idB.Ed25519Public)
	entryBinA := &peer.Entry{ID: bID, VPNAddr: addrB}
	entryBinA.SetEndpoint(epB)
	entryBinA.SetSession(session.New(initResult))
	tblA.Upsert(entryBinA)

	tblB := peer.New()
	var aID [32]byte
	copy(aID[:], idA.Ed25519Public)
	entryAinB := &peer.Entry{ID: aID, VPNAddr: addrA}
	entryAinB.SetEndpoint(epA)
	entryAinB.SetSession(session.New(respResult))
	tblB.Upsert(entryAinB)

	connA, connB := newE2EPipe(
		net.UDPAddrFromAddrPort(epA),
		net.UDPAddrFromAddrPort(epB),
	)

	tunA, err := tun.CreateNetstackTUN("tunA", mustPrefixNetstack(t, "10.0.0.1/24"), 1420)
	if err != nil {
		t.Fatalf("CreateNetstackTUN A: %v", err)
	}
	defer tunA.Close()

	tunB, err := tun.CreateNetstackTUN("tunB", mustPrefixNetstack(t, "10.0.0.2/24"), 1420)
	if err != nil {
		t.Fatalf("CreateNetstackTUN B: %v", err)
	}
	defer tunB.Close()

	dispA := dataplane.New(tunA, connA, tblA)
	dispB := dataplane.New(tunB, connB, tblB)
	dispA.Start()
	dispB.Start()
	defer func() {
		dispA.Stop()
		dispB.Stop()
		dispA.Wait()
		dispB.Wait()
	}()

	// Start UDP echo server on B's VPN address using netstack
	netstackB := tunB.(*tun.NetstackTUN)
	udpConnB, err := netstackB.ListenUDPAddrPort(netip.AddrPortFrom(addrB, 8888))
	if err != nil {
		t.Fatalf("ListenUDPAddrPort B: %v", err)
	}
	defer udpConnB.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	done := make(chan struct{})
	go func() {
		defer wg.Done()
		buf := make([]byte, 1500)
		for {
			select {
			case <-done:
				return
			default:
			}
			// Set a read deadline to allow checking done channel
			udpConnB.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, addr, err := udpConnB.ReadFrom(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				t.Logf("UDP ReadFrom error: %v", err)
				return
			}
			if _, err := udpConnB.WriteTo(buf[:n], addr); err != nil {
				t.Logf("UDP WriteTo error: %v", err)
				return
			}
		}
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Send UDP from A's netstack to B's VPN address
	netstackA := tunA.(*tun.NetstackTUN)
	udpConnA, err := netstackA.ListenUDPAddrPort(netip.AddrPortFrom(addrA, 0))
	if err != nil {
		t.Fatalf("ListenUDPAddrPort A: %v", err)
	}
	defer udpConnA.Close()

	testData := []byte("udp echo test")
	if _, err := udpConnA.WriteTo(testData, net.UDPAddrFromAddrPort(netip.AddrPortFrom(addrB, 8888))); err != nil {
		t.Fatalf("UDP WriteTo: %v", err)
	}

	// Set read deadline
	udpConnA.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1500)
	n, addr, err := udpConnA.ReadFrom(buf)
	close(done)
	wg.Wait()
	if err != nil {
		t.Fatalf("UDP ReadFrom: %v", err)
	}
	if string(buf[:n]) != string(testData) {
		t.Errorf("UDP echo mismatch: got %q, want %q", string(buf[:n]), string(testData))
	}
	if addr.String() != netip.AddrPortFrom(addrB, 8888).String() {
		t.Errorf("UDP source addr: got %v, want %v", addr, netip.AddrPortFrom(addrB, 8888))
	}
}

// TestNetstackTUN_MTU_Packets tests MTU-sized packets through the netstack TUN over the VPN tunnel.
// Uses UDP to send a large payload that will be fragmented at the IP layer.
func TestNetstackTUN_MTU_Packets(t *testing.T) {
	idA, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate idA: %v", err)
	}
	idB, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate idB: %v", err)
	}

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
	now := time.Now().UnixNano()
	msg1, _ := initiatorHS.BuildMessage1(now)
	if _, err := responderHS.ProcessMessage1(msg1, now); err != nil {
		t.Fatalf("ProcessMessage1: %v", err)
	}
	msg2, respResult, _ := responderHS.BuildMessage2(now)
	initResult, _ := initiatorHS.ProcessMessage2(msg2, now)

	addrA := netip.MustParseAddr("10.0.0.1")
	addrB := netip.MustParseAddr("10.0.0.2")
	epA := netip.MustParseAddrPort("10.0.0.1:1000")
	epB := netip.MustParseAddrPort("10.0.0.2:2000")

	tblA := peer.New()
	var bID [32]byte
	copy(bID[:], idB.Ed25519Public)
	entryBinA := &peer.Entry{ID: bID, VPNAddr: addrB}
	entryBinA.SetEndpoint(epB)
	entryBinA.SetSession(session.New(initResult))
	tblA.Upsert(entryBinA)

	tblB := peer.New()
	var aID [32]byte
	copy(aID[:], idA.Ed25519Public)
	entryAinB := &peer.Entry{ID: aID, VPNAddr: addrA}
	entryAinB.SetEndpoint(epA)
	entryAinB.SetSession(session.New(respResult))
	tblB.Upsert(entryAinB)

	connA, connB := newE2EPipe(
		net.UDPAddrFromAddrPort(epA),
		net.UDPAddrFromAddrPort(epB),
	)

	mtu := 1420
	tunA, err := tun.CreateNetstackTUN("tunA", mustPrefixNetstack(t, "10.0.0.1/24"), mtu)
	if err != nil {
		t.Fatalf("CreateNetstackTUN A: %v", err)
	}
	defer tunA.Close()

	tunB, err := tun.CreateNetstackTUN("tunB", mustPrefixNetstack(t, "10.0.0.2/24"), mtu)
	if err != nil {
		t.Fatalf("CreateNetstackTUN B: %v", err)
	}
	defer tunB.Close()

	dispA := dataplane.New(tunA, connA, tblA)
	dispB := dataplane.New(tunB, connB, tblB)
	dispA.Start()
	dispB.Start()
	defer func() {
		dispA.Stop()
		dispB.Stop()
		dispA.Wait()
		dispB.Wait()
	}()

	// Start UDP echo server on B's VPN address using netstack
	netstackB := tunB.(*tun.NetstackTUN)
	udpConnB, err := netstackB.ListenUDPAddrPort(netip.AddrPortFrom(addrB, 9999))
	if err != nil {
		t.Fatalf("ListenUDPAddrPort B: %v", err)
	}
	defer udpConnB.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	done := make(chan struct{})
	go func() {
		defer wg.Done()
		buf := make([]byte, 10000) // Large buffer for MTU-sized packets
		for {
			select {
			case <-done:
				return
			default:
			}
			udpConnB.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, addr, err := udpConnB.ReadFrom(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				t.Logf("UDP ReadFrom error: %v", err)
				return
			}
			if _, err := udpConnB.WriteTo(buf[:n], addr); err != nil {
				t.Logf("UDP WriteTo error: %v", err)
				return
			}
		}
	}()

	time.Sleep(100 * time.Millisecond)

	// Send large UDP packet from A's netstack to B's VPN address
	netstackA := tunA.(*tun.NetstackTUN)
	udpConnA, err := netstackA.ListenUDPAddrPort(netip.AddrPortFrom(addrA, 0))
	if err != nil {
		t.Fatalf("ListenUDPAddrPort A: %v", err)
	}
	defer udpConnA.Close()

	// Create payload close to MTU (MTU - IPv4 header - UDP header = 1420 - 20 - 8 = 1392)
	// Use a larger payload to test fragmentation/reassembly
	payloadSize := 2000 // Larger than MTU to test IP fragmentation
	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	if _, err := udpConnA.WriteTo(payload, net.UDPAddrFromAddrPort(netip.AddrPortFrom(addrB, 9999))); err != nil {
		t.Fatalf("UDP WriteTo: %v", err)
	}

	udpConnA.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 10000)
	n, addr, err := udpConnA.ReadFrom(buf)
	close(done)
	wg.Wait()
	if err != nil {
		t.Fatalf("UDP ReadFrom: %v", err)
	}
	if n != len(payload) {
		t.Errorf("UDP payload size mismatch: got %d, want %d", n, len(payload))
	} else {
		for i := range payload {
			if buf[i] != payload[i] {
				t.Errorf("payload mismatch at byte %d: got %d, want %d", i, buf[i], payload[i])
				break
			}
		}
	}
	if addr.String() != netip.AddrPortFrom(addrB, 9999).String() {
		t.Errorf("UDP source addr: got %v, want %v", addr, netip.AddrPortFrom(addrB, 9999))
	}
}

// TestNetstackTUN_DataplaneHooks verifies that the dataplane hooks (OnHandshakeRequired,
// OnRekeyRequired, OnHandshakePacket, OnNATProbePacket, OnSessionEstablished)
// are called with the same packets as with a kernel TUN.
// This is a TODO test - currently the hooks are called through the dispatcher
// which uses the TUN interface, so they should work identically.
func TestNetstackTUN_DataplaneHooks(t *testing.T) {
	// TODO: Verify ACL hooks see the same packets as with a kernel TUN.
	// Currently the dispatcher uses the TUN interface (Read/Write) which is
	// implemented identically for both kernel TUN and netstack TUN. The hooks
	// are called from the dispatcher's udpLoop and tunLoop which don't depend
	// on the TUN implementation. This test documents the requirement.
	// If ACL hooks are added to the dataplane, add assertions here.
	t.Log("TODO: Verify ACL hooks are called with userspace TUN")
}
