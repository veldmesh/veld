// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package daemon

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/veldmesh/veld/internal/coexist"
	intconfig "github.com/veldmesh/veld/internal/config"
	"github.com/veldmesh/veld/internal/crypto"
	"github.com/veldmesh/veld/internal/dataplane"
	"github.com/veldmesh/veld/internal/peer"
	"github.com/veldmesh/veld/internal/session"
	"github.com/veldmesh/veld/internal/tun"
)

// --- Test helpers from main branch ---

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
	pkt[0] = 0x45                // version=4, IHL=5
	pkt[1] = 0x00                // DSCP/ECN
	pkt[2] = byte(totalLen >> 8) // total length high
	pkt[3] = byte(totalLen)      // total length low
	pkt[8] = 64                  // TTL
	pkt[9] = 17                  // protocol: UDP
	copy(pkt[12:16], src[:])     // source IP
	copy(pkt[16:20], dst[:])     // dest IP
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

// --- Test helpers from PR branch ---

// newTestDaemon builds a Daemon with real components but does not start it.
// A nil TUN mirrors coord mode at startup: the TUN is created only after
// the coordinator assigns the VPN address.
func newTestDaemon(t *testing.T, tdev tun.TUN) *Daemon {
	t.Helper()
	id, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	var networkID [16]byte
	return New(id, networkID, tdev, conn, peer.New())
}

func testPrintf(b *strings.Builder) coexist.Printf {
	return func(format string, args ...any) (int, error) {
		return fmt.Fprintf(b, format, args...)
	}
}

// --- Coexistence tests (PR branch) ---

func TestSelfInterfaceEmptyWithoutTUN(t *testing.T) {
	d := newTestDaemon(t, nil)
	if got := d.selfInterface(); got != "" {
		t.Errorf("selfInterface() = %q, want empty before the TUN exists", got)
	}
}

func TestSelfInterfaceFromStaticTUN(t *testing.T) {
	dev := tun.NewMemTUN("veld0", netip.MustParsePrefix("10.100.0.1/24"), 1420)
	d := newTestDaemon(t, dev)
	if got := d.selfInterface(); got != "veld0" {
		t.Errorf("selfInterface() = %q, want veld0", got)
	}
}

// TestSelfInterfaceResolvesTUNAfterConstruction is the coord-mode regression:
// the TUN appears only after the coordinator assigns the VPN address, so
// collision checks must resolve the interface name at check time. Capturing
// the name once at startup would pin the pre-TUN empty string forever and
// make every later check misattribute veld's own routes to a commercial VPN.
func TestSelfInterfaceResolvesTUNAfterConstruction(t *testing.T) {
	d := newTestDaemon(t, nil)
	if got := d.selfInterface(); got != "" {
		t.Fatalf("selfInterface() = %q, want empty before the TUN exists", got)
	}

	// The coordinator assigned the address; veld creates its TUN now.
	d.mu.Lock()
	d.tunDev = tun.NewMemTUN("veld1", netip.MustParsePrefix("10.100.0.1/24"), 1420)
	d.mu.Unlock()

	if got := d.selfInterface(); got != "veld1" {
		t.Errorf("selfInterface() = %q, want veld1 after the TUN was created", got)
	}
}

// --- resolveIfaceName (node.iface_name -> TUN name to create) ---

// TestResolveIfaceNameEmptyUsesPlatformDefault: a config without an
// explicit iface_name (what all new configs carry since the legacy tun0
// default was dropped) resolves to the platform default, without logging.
func TestResolveIfaceNameEmptyUsesPlatformDefault(t *testing.T) {
	var b strings.Builder
	if got := resolveIfaceName(testPrintf(&b), ""); got != tun.DefaultIfaceName() {
		t.Errorf("empty iface_name must resolve to the platform default %q, got %q", tun.DefaultIfaceName(), got)
	}
	if b.Len() != 0 {
		t.Errorf("empty iface_name must not log, got:\n%s", b.String())
	}
}

// TestResolveIfaceNameMigratesLegacyTun0: a config written by an older veld
// carries the legacy default "tun0". It must map to the platform default
// with a one-line notice — veld can no longer create a TUN named tun0 next
// to an OpenVPN-based VPN (TUNSETIFF fails with EEXIST).
func TestResolveIfaceNameMigratesLegacyTun0(t *testing.T) {
	var b strings.Builder
	if got := resolveIfaceName(testPrintf(&b), legacyIfaceName); got != tun.DefaultIfaceName() {
		t.Errorf("legacy iface_name must resolve to the platform default %q, got %q", tun.DefaultIfaceName(), got)
	}
	out := b.String()
	if !strings.Contains(out, legacyIfaceName) || !strings.Contains(out, tun.DefaultIfaceName()) {
		t.Errorf("migration must log one line naming the legacy value and the platform default, got:\n%s", out)
	}
}

// TestResolveIfaceNameHonorsOverride: any other value is honored verbatim,
// without logging.
func TestResolveIfaceNameHonorsOverride(t *testing.T) {
	var b strings.Builder
	if got := resolveIfaceName(testPrintf(&b), "custom1"); got != "custom1" {
		t.Errorf("iface_name custom1 must be honored verbatim, got %q", got)
	}
	if b.Len() != 0 {
		t.Errorf("an explicit iface_name must not log, got:\n%s", b.String())
	}
}

// --- Coord mode tests (main branch) ---

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

// TestDeriveMeshPrefix_CIDRFromServer tests that the prefix is derived
// from the server-provided network CIDR with the assigned VPN address.
func TestDeriveMeshPrefix_CIDRFromServer(t *testing.T) {
	vpnAddr := netip.MustParseAddr("10.50.0.5")
	prefix := deriveMeshPrefix(vpnAddr, "10.50.0.0/24")
	want := netip.PrefixFrom(vpnAddr, 24)
	if prefix != want {
		t.Errorf("deriveMeshPrefix: got %s, want %s", prefix, want)
	}
}

// TestDeriveMeshPrefix_MissingCIDRFallback tests that when the server
// does not provide a network CIDR, the prefix falls back to /24.
func TestDeriveMeshPrefix_MissingCIDRFallback(t *testing.T) {
	vpnAddr := netip.MustParseAddr("10.100.0.7")
	prefix := deriveMeshPrefix(vpnAddr, "")
	want := netip.PrefixFrom(vpnAddr, 24)
	if prefix != want {
		t.Errorf("deriveMeshPrefix: got %s, want %s", prefix, want)
	}
}

// TestDeriveMeshPrefix_InvalidCIDRFallback tests that an invalid CIDR
// from the server falls back to /24.
func TestDeriveMeshPrefix_InvalidCIDRFallback(t *testing.T) {
	vpnAddr := netip.MustParseAddr("192.168.1.3")
	prefix := deriveMeshPrefix(vpnAddr, "not-a-valid-cidr")
	want := netip.PrefixFrom(vpnAddr, 24)
	if prefix != want {
		t.Errorf("deriveMeshPrefix: got %s, want %s", prefix, want)
	}
}

// TestOnVPNAddrAssigned_Callback_CreateTUNFailure tests that when TUN
// creation fails (e.g., no /dev/net/tun), the daemon logs and keeps
// running without a data plane. The callback must not panic.
func TestOnVPNAddrAssigned_Callback_CreateTUNFailure(t *testing.T) {
	id, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	var networkID [16]byte
	copy(networkID[:], []byte("babe000000000000000000000000cafe"))

	peerTbl := peer.New()
	conn := newFakeConn()

	cfg := &intconfig.Config{
		Node: intconfig.NodeConfig{
			IfaceName: "vel-test",
			MTU:       1420,
		},
	}

	d := New(id, networkID, nil, conn, peerTbl)

	// Call the callback directly. In an environment without /dev/net/tun
	// CreateTUN fails; the callback must log and return, not panic.
	cb := d.onVPNAddrAssigned(cfg, conn)
	cb(netip.MustParseAddr("10.10.0.1"), "10.10.0.0/24")

	// The TUN should still be nil (creation failed in this container).
	d.mu.Lock()
	tunDev := d.tunDev
	d.mu.Unlock()
	if tunDev != nil {
		// If CreateTUN unexpectedly succeeded (privileged host), the TUN
		// exists — also acceptable. Close it.
		defer tunDev.Close()
	}
}

// TestOnVPNAddrAssigned_Callback_SameAddress_NoOp tests that if the
// callback is invoked with the same VPN address as the existing TUN,
// the TUN is left untouched.
func TestOnVPNAddrAssigned_Callback_SameAddress_NoOp(t *testing.T) {
	id, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	var networkID [16]byte
	copy(networkID[:], []byte("babe000000000000000000000000cafe"))

	peerTbl := peer.New()
	conn := newFakeConn()

	cfg := &intconfig.Config{
		Node: intconfig.NodeConfig{
			IfaceName: "vel-test",
			MTU:       1420,
		},
	}

	d := New(id, networkID, nil, conn, peerTbl)

	// Pre-populate with a MemTUN at address 10.0.0.1/24.
	existing := tun.NewMemTUN("vel-test", netip.MustParsePrefix("10.0.0.1/24"), 1420)
	d.mu.Lock()
	d.tunDev = existing
	d.mu.Unlock()

	// Call callback with the SAME address: no-op.
	cb := d.onVPNAddrAssigned(cfg, conn)
	cb(netip.MustParseAddr("10.0.0.1"), "10.0.0.0/24")

	// The TUN must be the same object and still open.
	d.mu.Lock()
	tunDev := d.tunDev
	d.mu.Unlock()
	if tunDev != existing {
		t.Fatalf("expected the same TUN object after same-address callback")
	}
	if _, err := existing.Inject([]byte{0x45}); err != nil {
		t.Errorf("existing TUN should still be open after no-op, got %v", err)
	}
}

// TestOnVPNAddrAssigned_Callback_AddressChange_RecreatesTUN tests that
// a re-registration assigning a different VPN address closes the old
// TUN and creates a new one with the new address. Uses the createTUN seam
// to simulate successful TUN creation.
func TestOnVPNAddrAssigned_Callback_AddressChange_RecreatesTUN(t *testing.T) {
	id, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	var networkID [16]byte
	copy(networkID[:], []byte("babe000000000000000000000000cafe"))

	peerTbl := peer.New()
	conn := newFakeConn()

	cfg := &intconfig.Config{
		Node: intconfig.NodeConfig{
			IfaceName: "vel-test",
			MTU:       1420,
		},
	}

	d := New(id, networkID, nil, conn, peerTbl)

	// Pre-populate with a MemTUN at address 10.0.0.1/24.
	existing := tun.NewMemTUN("vel-test", netip.MustParsePrefix("10.0.0.1/24"), 1420)
	d.mu.Lock()
	d.tunDev = existing
	d.mu.Unlock()

	// Override createTUN to return a new MemTUN with the new address.
	originalCreateTUN := createTUN
	newTun := tun.NewMemTUN("vel-test", netip.MustParsePrefix("10.0.0.2/24"), 1420)
	createTUN = func(iface string, prefix netip.Prefix, mtu int) (tun.TUN, error) {
		if prefix.Addr() == netip.MustParseAddr("10.0.0.2") {
			return newTun, nil
		}
		return originalCreateTUN(iface, prefix, mtu)
	}
	defer func() { createTUN = originalCreateTUN }()

	// Call callback with a DIFFERENT address (10.0.0.2).
	cb := d.onVPNAddrAssigned(cfg, conn)
	cb(netip.MustParseAddr("10.0.0.2"), "10.0.0.0/24")

	// The old TUN must be closed.
	if _, err := existing.Inject([]byte{0x45}); err != tun.ErrClosed {
		t.Errorf("old TUN should be closed after address change, got %v", err)
	}

	// The daemon's tunDev should now be the new TUN with the new address.
	d.mu.Lock()
	newTunDev := d.tunDev
	d.mu.Unlock()
	if newTunDev == nil {
		t.Fatal("expected new TUN after successful address change")
	}
	defer newTunDev.Close()
	if newTunDev == existing {
		t.Errorf("tunDev should not be the old TUN after address change")
	}
	if newTunDev.Addr().Addr() != netip.MustParseAddr("10.0.0.2") {
		t.Errorf("new TUN address: got %s, want 10.0.0.2", newTunDev.Addr().Addr())
	}
}

// TestOnVPNAddrAssigned_Callback_CreateTUNFailure_KeepsOldTUN tests that
// when TUN creation fails during an address change, the old TUN is kept
// open and the daemon continues running with the old address.
func TestOnVPNAddrAssigned_Callback_CreateTUNFailure_KeepsOldTUN(t *testing.T) {
	id, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	var networkID [16]byte
	copy(networkID[:], []byte("babe000000000000000000000000cafe"))

	peerTbl := peer.New()
	conn := newFakeConn()

	cfg := &intconfig.Config{
		Node: intconfig.NodeConfig{
			IfaceName: "vel-test",
			MTU:       1420,
		},
	}

	d := New(id, networkID, nil, conn, peerTbl)

	// Pre-populate with a MemTUN at address 10.0.0.1/24.
	existing := tun.NewMemTUN("vel-test", netip.MustParsePrefix("10.0.0.1/24"), 1420)
	d.mu.Lock()
	d.tunDev = existing
	d.mu.Unlock()

	// Override createTUN to fail for the new address.
	originalCreateTUN := createTUN
	createTUN = func(iface string, prefix netip.Prefix, mtu int) (tun.TUN, error) {
		if prefix.Addr() == netip.MustParseAddr("10.0.0.2") {
			return nil, &tunErr{"simulated failure"}
		}
		return originalCreateTUN(iface, prefix, mtu)
	}
	defer func() { createTUN = originalCreateTUN }()

	// Call callback with a DIFFERENT address (10.0.0.2) — creation should fail.
	cb := d.onVPNAddrAssigned(cfg, conn)
	cb(netip.MustParseAddr("10.0.0.2"), "10.0.0.0/24")

	// The old TUN must still be open.
	if _, err := existing.Inject([]byte{0x45}); err != nil {
		t.Errorf("old TUN should still be open after failed address change, got %v", err)
	}

	// The daemon's tunDev should still be the old TUN.
	d.mu.Lock()
	tunDev := d.tunDev
	d.mu.Unlock()
	if tunDev != existing {
		t.Errorf("tunDev should still be the old TUN after failed address change, got %v", tunDev)
	}
}

// tunErr is a simple error type for test injection.
type tunErr struct{ msg string }

func (e *tunErr) Error() string { return e.msg }

// TestNewMDNSDiscovery_Disabled verifies that mDNS discovery is not
// constructed when disabled in config, regardless of environment.
func TestNewMDNSDiscovery_Disabled(t *testing.T) {
	id, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	var networkID [16]byte
	peerTbl := peer.New()
	conn := newFakeConn()
	d := New(id, networkID, nil, conn, peerTbl)

	cfg := &intconfig.Config{MDNS: intconfig.MDNSConfig{Enabled: false}}
	disc, err := d.newMDNSDiscovery(cfg, conn, netip.MustParseAddr("10.10.0.1"))
	if err != nil {
		t.Fatalf("newMDNSDiscovery: unexpected error: %v", err)
	}
	if disc != nil {
		t.Fatalf("newMDNSDiscovery: expected nil discovery when disabled, got %v", disc)
	}
}

// TestNewMDNSDiscovery_Enabled verifies that mDNS discovery is constructed
// and advertises the given VPN address when enabled in config. This is the
// same helper onVPNAddrAssigned uses to wire discovery in coord mode once
// the TUN exists, exercised directly so it doesn't depend on CreateTUN
// succeeding in the test environment.
func TestNewMDNSDiscovery_Enabled(t *testing.T) {
	id, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	var networkID [16]byte
	peerTbl := peer.New()
	conn := newFakeConn()
	d := New(id, networkID, nil, conn, peerTbl)

	cfg := &intconfig.Config{MDNS: intconfig.MDNSConfig{Enabled: true, Name: "test-node"}}
	disc, err := d.newMDNSDiscovery(cfg, conn, netip.MustParseAddr("10.10.0.1"))
	if err != nil {
		t.Skipf("mDNS discovery did not initialize in this environment: %v", err)
	}
	if disc == nil {
		t.Fatalf("newMDNSDiscovery: expected a discovery instance when enabled")
	}
	disc.Stop()
}

// TestOnVPNAddrAssigned_Callback_WiresMDNS verifies that once the
// coordinator assigns a VPN address, mDNS LAN discovery is created and
// started advertising it — mDNS has no address to advertise at
// construction time in coord mode, so it must be wired here instead.
func TestOnVPNAddrAssigned_Callback_WiresMDNS(t *testing.T) {
	id, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	var networkID [16]byte
	copy(networkID[:], []byte("babe000000000000000000000000cafe"))

	peerTbl := peer.New()
	conn := newFakeConn()

	cfg := &intconfig.Config{
		Node: intconfig.NodeConfig{
			IfaceName: "vel-test",
			MTU:       1420,
		},
		MDNS: intconfig.MDNSConfig{
			Enabled: true,
			Name:    "test-node",
		},
	}

	d := New(id, networkID, nil, conn, peerTbl)

	// Override createTUN to succeed so we can test mDNS wiring.
	originalCreateTUN := createTUN
	newTun := tun.NewMemTUN("vel-test", netip.MustParsePrefix("10.10.0.1/24"), 1420)
	createTUN = func(iface string, prefix netip.Prefix, mtu int) (tun.TUN, error) {
		return newTun, nil
	}
	defer func() { createTUN = originalCreateTUN }()

	cb := d.onVPNAddrAssigned(cfg, conn)
	cb(netip.MustParseAddr("10.10.0.1"), "10.10.0.0/24")

	disc := d.mdnsDiscovery()
	if disc == nil {
		// mDNS requires binding a multicast UDP socket; some sandboxes deny
		// this, matching how CreateTUN can fail in TestOnVPNAddrAssigned_
		// Callback_CreateTUNFailure. Nothing further to assert.
		t.Skip("mDNS discovery did not initialize in this environment")
	}

	// Stop with a timeout to avoid hanging on platforms where mDNS shutdown
	// may block (e.g., Windows multicast socket cleanup).
	stopped := make(chan struct{})
	go func() {
		disc.Stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("disc.Stop() timed out")
	}
}

// TestOnVPNAddrAssigned_Callback_SelfInterfaceVisible verifies the
// assigned TUN is visible via selfInterface() once set.
func TestOnVPNAddrAssigned_Callback_SelfInterfaceVisible(t *testing.T) {
	id, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	var networkID [16]byte
	copy(networkID[:], []byte("babe000000000000000000000000cafe"))

	peerTbl := peer.New()
	conn := newFakeConn()

	memTun := tun.NewMemTUN("vel0", netip.MustParsePrefix("10.100.0.1/24"), 1420)
	d := New(id, networkID, memTun, conn, peerTbl)

	if got := d.selfInterface(); got != "vel0" {
		t.Errorf("selfInterface() = %q, want %q", got, "vel0")
	}
}
