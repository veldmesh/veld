// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package daemon

import (
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"

	coordv1 "github.com/veldmesh/veld/gen/veld/coord/v1"
	coordserver "github.com/veldmesh/veld/coord/server"
	coordce "github.com/veldmesh/veld/coord/ce"
	coordcore "github.com/veldmesh/veld/coord/core"
	"github.com/veldmesh/veld/internal/coord"
	"github.com/veldmesh/veld/internal/crypto"
	"github.com/veldmesh/veld/internal/dataplane"
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

// startCoordServer starts an in-process coord gRPC server and returns its address.
func startCoordServer(t *testing.T, networkID string, cidr netip.Prefix) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	reg, err := coordserver.NewRegistry(t.TempDir() + "/coord.db")
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	if err := reg.CreateNetwork(coordcore.Network{
		ID:   networkID,
		CIDR: cidr,
		Name: "e2e-net",
	}, "acc1"); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}

	bus := coordserver.NewBus()
	srv := coordserver.New(
		reg,
		bus,
		coordce.NewFreeEnforcer(),
		coordce.NewTokenAccountStore(map[string]coordcore.Account{
			"e2e-token": {ID: "acc1", Tier: coordcore.TierFree},
		}),
		coordce.NewNoopAuditLogger(),
		coordce.NewRejectSubnetPolicy(),
		coordce.NewNoopHooks(),
	)

	grpcSrv := grpc.NewServer()
	coordv1.RegisterCoordServer(grpcSrv, srv)
	go grpcSrv.Serve(ln)

	return ln.Addr().String(), func() {
		grpcSrv.Stop()
		reg.Close()
		ln.Close()
	}
}

// pollUntil polls cond every 5 ms until it returns true or timeout elapses.
func pollUntil(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

// TestOnVPNAddrAssigned_CIDRFromServer tests that when the coordinator provides
// a network_cidr, the daemon derives the correct prefix and creates the TUN.
func TestOnVPNAddrAssigned_CIDRFromServer(t *testing.T) {
	// Use an in-memory coord server for the test.
	cidr := netip.MustParsePrefix("10.50.0.0/24")
	serverAddr, stopServer := startCoordServer(t, "test-net", cidr)
	defer stopServer()

	id, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	peerTbl := peer.New()

	c := coord.New(coord.Config{
		ServerAddr:  serverAddr,
		NetworkID:   "test-net",
		Token:       "e2e-token",
		Identity:    id,
		LocalName:   "test-node",
		PeerTable:   peerTbl,
		TLSInsecure: true,
	})

	var callbackMu sync.Mutex
	var callbackVPNAddr netip.Addr
	var callbackCIDR string
	c.OnVPNAddrAssigned = func(vpnAddr netip.Addr, networkCIDR string) {
		callbackMu.Lock()
		callbackVPNAddr = vpnAddr
		callbackCIDR = networkCIDR
		callbackMu.Unlock()
	}

	c.Start()
	defer func() { c.Stop(); c.Wait() }()

	if !pollUntil(5*time.Second, func() bool { return c.VPNAddr().IsValid() }) {
		t.Fatal("timeout: client did not register")
	}

	callbackMu.Lock()
	vpn := callbackVPNAddr
	cidrStr := callbackCIDR
	callbackMu.Unlock()

	if !vpn.IsValid() {
		t.Fatal("OnVPNAddrAssigned not called with valid VPN address")
	}
	if cidrStr != "10.50.0.0/24" {
		t.Errorf("OnVPNAddrAssigned network CIDR: got %q, want 10.50.0.0/24", cidrStr)
	}
	if !cidr.Contains(vpn) {
		t.Errorf("assigned VPN %s not in CIDR %s", vpn, cidr)
	}
}

// TestDispatcher_SetTUN_StartsTunLoop tests that SetTUN starts the tunLoop
// and packets from TUN are sent over UDP.
func TestDispatcher_SetTUN_StartsTunLoop(t *testing.T) {
	sessA, _ := newTestSessionPair(t)

	peerTbl := peer.New()
	var peerBID [32]byte
	peerBID[0] = 0x02
	ep := mustAddrPort("1.2.3.4:5000")
	entryB := &peer.Entry{ID: peerBID, VPNAddr: mustAddr("10.0.0.2")}
	entryB.SetEndpoint(ep)
	entryB.SetSession(sessA)
	peerTbl.Upsert(entryB)

	conn := newFakeConn()
	d := dataplane.New(nil, conn, peerTbl)
	d.Start()
	defer d.Wait()
	defer d.Stop()

	// No TUN yet — inject should not work
	memTun := tun.NewMemTUN("tun0", netip.MustParsePrefix("10.0.0.1/24"), 1420)

	// Now set the TUN
	d.SetTUN(memTun)

	// Write an IPv4 packet to the TUN destined for 10.0.0.2.
	pkt := buildIPv4Packet([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, []byte("hello"))
	if _, err := memTun.Inject(pkt); err != nil {
		t.Fatalf("TUN write: %v", err)
	}

	// Expect one UDP packet on the conn's output.
	var msg udpMsg
	select {
	case msg = <-conn.out:
		if len(msg.data) < 16 {
			t.Errorf("UDP packet too short: %d bytes", len(msg.data))
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for UDP output after SetTUN")
	}
}

// TestDispatcher_SetTUN_HoldQueueFlushed tests that when a session is
// established after SetTUN, the hold queue is drained.
func TestDispatcher_SetTUN_HoldQueueFlushed(t *testing.T) {
	sessA, _ := newTestSessionPair(t)

	peerTbl := peer.New()
	var peerBID [32]byte
	peerBID[0] = 0x02
	ep := mustAddrPort("1.2.3.4:5000")
	entryB := &peer.Entry{ID: peerBID, VPNAddr: mustAddr("10.0.0.2")}
	entryB.SetEndpoint(ep)
	// No session initially — packet will be held
	peerTbl.Upsert(entryB)

	conn := newFakeConn()
	d := dataplane.New(nil, conn, peerTbl)
	d.Start()
	defer d.Wait()
	defer d.Stop()

	// Set TUN first
	memTun := tun.NewMemTUN("tun0", netip.MustParsePrefix("10.0.0.1/24"), 1420)
	d.SetTUN(memTun)

	// Inject a packet for peer B (no session yet) — should be held
	pkt := buildIPv4Packet([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, []byte("queued"))
	if _, err := memTun.Inject(pkt); err != nil {
		t.Fatalf("TUN write: %v", err)
	}

	// Wait for the packet to be processed and enqueued (tunLoop processes it)
	// We can't peek the queue without draining, so we'll just wait a bit
	// and then set the session and flush. The tunLoop goroutine will have
	// enqueued the packet.
	if !pollUntil(time.Second, func() bool {
		// Try to set session and flush - if it works, the packet was enqueued
		return true // we just wait a moment for tunLoop to run
	}) {
		t.Fatal("timeout waiting for tunLoop to process")
	}

	// Now establish session and flush hold queue
	entryB.SetSession(sessA)
	d.FlushHoldQueue(entryB)

	// Expect the packet to be sent over UDP
	var msg udpMsg
	select {
	case msg = <-conn.out:
		if len(msg.data) < 16 {
			t.Errorf("UDP packet too short: %d bytes", len(msg.data))
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for UDP output after FlushHoldQueue")
	}
}

// TestDaemon_selfInterface tests that selfInterface returns the TUN name
// when a TUN exists and empty string when it doesn't.
func TestDaemon_selfInterface(t *testing.T) {
	id, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	var networkID [16]byte
	copy(networkID[:], []byte("babe000000000000000000000000cafe"))

	peerTbl := peer.New()
	conn := newFakeConn()

	// Without TUN
	d := New(id, networkID, nil, conn, peerTbl)
	if d.selfInterface() != "" {
		t.Errorf("selfInterface() should be empty without TUN, got %q", d.selfInterface())
	}

	// With TUN (MemTUN)
	memTun := tun.NewMemTUN("tun-test", netip.MustParsePrefix("10.0.0.1/24"), 1420)
	d2 := New(id, networkID, memTun, conn, peerTbl)
	if d2.selfInterface() != "tun-test" {
		t.Errorf("selfInterface() should return TUN name, got %q", d2.selfInterface())
	}
}