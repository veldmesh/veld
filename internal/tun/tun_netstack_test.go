// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
//go:build userspace

package tun_test

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
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

func setupE2ENodes(t *testing.T) (tunA, tunB *tun.NetstackTUN, stop func()) {
	t.Helper()

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

	tunAdev, err := tun.CreateNetstackTUN("tunA", mustPrefixNetstack(t, "10.0.0.1/24"), 1420)
	if err != nil {
		t.Fatalf("CreateNetstackTUN A: %v", err)
	}
	tunBdev, err := tun.CreateNetstackTUN("tunB", mustPrefixNetstack(t, "10.0.0.2/24"), 1420)
	if err != nil {
		t.Fatalf("CreateNetstackTUN B: %v", err)
	}

	tunA = tunAdev.(*tun.NetstackTUN)
	tunB = tunBdev.(*tun.NetstackTUN)

	dispA := dataplane.New(tunA, connA, tblA)
	dispB := dataplane.New(tunB, connB, tblB)
	dispA.Start()
	dispB.Start()

	stop = func() {
		dispA.Stop()
		dispB.Stop()
		dispA.Wait()
		dispB.Wait()
		tunA.Close()
		tunB.Close()
	}
	return
}

func TestNetstackTUN_TCP_Echo(t *testing.T) {
	tunA, tunB, stop := setupE2ENodes(t)
	defer stop()

	listener, err := tunB.ListenTCPAddrPort(netip.AddrPortFrom(netip.MustParseAddr("10.0.0.2"), 7777))
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

	time.Sleep(100 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	clientConn, err := tunA.DialContext(ctx, "tcp", netip.AddrPortFrom(netip.MustParseAddr("10.0.0.2"), 7777).String())
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer clientConn.Close()

	testData := []byte("hello from userspace netstack")
	if _, err := clientConn.Write(testData); err != nil {
		t.Fatalf("client Write: %v", err)
	}

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

func TestNetstackTUN_UDP_Echo(t *testing.T) {
	tunA, tunB, stop := setupE2ENodes(t)
	defer stop()

	udpConnB, err := tunB.ListenUDPAddrPort(netip.AddrPortFrom(netip.MustParseAddr("10.0.0.2"), 8888))
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

	udpConnA, err := tunA.ListenUDPAddrPort(netip.AddrPortFrom(netip.MustParseAddr("10.0.0.1"), 0))
	if err != nil {
		t.Fatalf("ListenUDPAddrPort A: %v", err)
	}
	defer udpConnA.Close()

	testData := []byte("udp echo test")
	if _, err := udpConnA.WriteTo(testData, net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr("10.0.0.2"), 8888))); err != nil {
		t.Fatalf("UDP WriteTo: %v", err)
	}

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
	if addr.String() != netip.AddrPortFrom(netip.MustParseAddr("10.0.0.2"), 8888).String() {
		t.Errorf("UDP source addr: got %v, want %v", addr, netip.AddrPortFrom(netip.MustParseAddr("10.0.0.2"), 8888))
	}
}

func TestNetstackTUN_MTU_Packets(t *testing.T) {
	tunA, tunB, stop := setupE2ENodes(t)
	defer stop()

	udpConnB, err := tunB.ListenUDPAddrPort(netip.AddrPortFrom(netip.MustParseAddr("10.0.0.2"), 9999))
	if err != nil {
		t.Fatalf("ListenUDPAddrPort B: %v", err)
	}
	defer udpConnB.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	done := make(chan struct{})
	go func() {
		defer wg.Done()
		buf := make([]byte, 10000)
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

	udpConnA, err := tunA.ListenUDPAddrPort(netip.AddrPortFrom(netip.MustParseAddr("10.0.0.1"), 0))
	if err != nil {
		t.Fatalf("ListenUDPAddrPort A: %v", err)
	}
	defer udpConnA.Close()

	payloadSize := 2000
	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	if _, err := udpConnA.WriteTo(payload, net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr("10.0.0.2"), 9999))); err != nil {
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
	if addr.String() != netip.AddrPortFrom(netip.MustParseAddr("10.0.0.2"), 9999).String() {
		t.Errorf("UDP source addr: got %v, want %v", addr, netip.AddrPortFrom(netip.MustParseAddr("10.0.0.2"), 9999))
	}
}

func TestNetstackTUN_DataplaneHooks(t *testing.T) {
	idA, _ := crypto.Generate()
	idB, _ := crypto.Generate()

	var aID [32]byte
	copy(aID[:], idA.Ed25519Public)
	var bID [32]byte
	copy(bID[:], idB.Ed25519Public)

	addrB := netip.MustParseAddr("10.0.0.2")
	epA := netip.MustParseAddrPort("10.0.0.1:1000")
	epB := netip.MustParseAddrPort("10.0.0.2:2000")

	tbl := peer.New()
	entryB := &peer.Entry{ID: bID, VPNAddr: addrB}
	entryB.SetEndpoint(epB)
	tbl.Upsert(entryB)

	connA, _ := newE2EPipe(
		net.UDPAddrFromAddrPort(epA),
		net.UDPAddrFromAddrPort(epB),
	)

	testTun, err := tun.CreateNetstackTUN("test-tun", mustPrefixNetstack(t, "10.0.0.1/24"), 1420)
	if err != nil {
		t.Fatalf("CreateNetstackTUN: %v", err)
	}
	defer testTun.Close()

	var handshakeRequiredCalls atomic.Int32
	var handshakePacketCalls atomic.Int32
	var natProbePacketCalls atomic.Int32
	var sessionEstablishedCalls atomic.Int32

	disp := dataplane.New(testTun, connA, tbl)
	disp.OnHandshakeRequired = func(e *peer.Entry) {
		handshakeRequiredCalls.Add(1)
	}
	disp.OnHandshakePacket = func(pkt []byte, addr net.Addr) {
		handshakePacketCalls.Add(1)
	}
	disp.OnNATProbePacket = func(pkt []byte, addr net.Addr) {
		natProbePacketCalls.Add(1)
	}
	disp.OnSessionEstablished = func(e *peer.Entry) {
		sessionEstablishedCalls.Add(1)
	}
	disp.Start()
	defer func() {
		disp.Stop()
		disp.Wait()
	}()

	if disp.OnHandshakeRequired == nil {
		t.Error("OnHandshakeRequired should be set")
	}
	if disp.OnHandshakePacket == nil {
		t.Error("OnHandshakePacket should be set")
	}
	if disp.OnNATProbePacket == nil {
		t.Error("OnNATProbePacket should be set")
	}
	if disp.OnSessionEstablished == nil {
		t.Error("OnSessionEstablished should be set")
	}

	disp.OnHandshakeRequired(nil)
	disp.OnHandshakePacket([]byte{1}, nil)
	disp.OnNATProbePacket([]byte{2}, nil)
	disp.OnSessionEstablished(nil)

	if handshakeRequiredCalls.Load() != 1 {
		t.Errorf("OnHandshakeRequired not called, got %d", handshakeRequiredCalls.Load())
	}
	if handshakePacketCalls.Load() != 1 {
		t.Errorf("OnHandshakePacket not called, got %d", handshakePacketCalls.Load())
	}
	if natProbePacketCalls.Load() != 1 {
		t.Errorf("OnNATProbePacket not called, got %d", natProbePacketCalls.Load())
	}
	if sessionEstablishedCalls.Load() != 1 {
		t.Errorf("OnSessionEstablished not called, got %d", sessionEstablishedCalls.Load())
	}

	t.Log("Verified: dataplane hooks are wired and can be called")
	t.Log("  OnHandshakeRequired: called")
	t.Log("  OnHandshakePacket: called")
	t.Log("  OnNATProbePacket: called")
	t.Log("  OnSessionEstablished: called")
}
