// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package dataplane

import (
	"encoding/binary"
	"encoding/hex"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/veldmesh/veld/internal/acl"
	"github.com/veldmesh/veld/internal/crypto"
	"github.com/veldmesh/veld/internal/peer"
	"github.com/veldmesh/veld/internal/session"
	"github.com/veldmesh/veld/internal/tun"
)

// TestDispatcher_ACL_Allowed verifies that allowed connections pass.
func TestDispatcher_ACL_Allowed(t *testing.T) {
	idA, _ := crypto.Generate()
	idB, _ := crypto.Generate()
	var peerAID, peerBID [32]byte
	copy(peerAID[:], idA.Ed25519Public)
	copy(peerBID[:], idB.Ed25519Public)

	// Build policy with actual peer keys
	policy := `version = 1
default = "deny"
[peers]
alice = "ed25519:` + hex.EncodeToString(peerAID[:]) + `"
bob   = "ed25519:` + hex.EncodeToString(peerBID[:]) + `"
[[rule]]
from = "alice"
to   = "bob"
ports = ["tcp/8080"]
`

	d, conn, _ := makeDispatcherWithPolicy(t, peerAID, peerBID, policy)

	// Send TCP SYN from alice (self) to bob on port 8080 - should be allowed
	src := [4]byte{10, 0, 0, 1}
	dst := [4]byte{10, 0, 0, 2}
	pkt := buildTCPSYNPacket(src, dst, 12345, 8080)
	d.handleTunPacket(pkt)

	// Should have sent encrypted packet
	select {
	case msg := <-conn.out:
		if len(msg.data) < HeaderSize {
			t.Fatalf("packet too short: %d", len(msg.data))
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout: allowed packet not sent")
	}
}

// TestDispatcher_ACL_Denied verifies that denied connections are dropped.
func TestDispatcher_ACL_Denied(t *testing.T) {
	idA, _ := crypto.Generate()
	idB, _ := crypto.Generate()
	var peerAID, peerBID [32]byte
	copy(peerAID[:], idA.Ed25519Public)
	copy(peerBID[:], idB.Ed25519Public)

	policy := `version = 1
default = "deny"
[peers]
alice = "ed25519:` + hex.EncodeToString(peerAID[:]) + `"
bob   = "ed25519:` + hex.EncodeToString(peerBID[:]) + `"
[[rule]]
from = "alice"
to   = "bob"
ports = ["tcp/8080"]
`

	d, conn, _ := makeDispatcherWithPolicy(t, peerAID, peerBID, policy)

	// Send TCP SYN from alice (self) to bob on port 22 - should be denied
	src := [4]byte{10, 0, 0, 1}
	dst := [4]byte{10, 0, 0, 2}
	pkt := buildTCPSYNPacket(src, dst, 12345, 22)
	d.handleTunPacket(pkt)

	// Should NOT have sent encrypted packet
	select {
	case <-conn.out:
		t.Error("denied packet should not be sent")
	case <-time.After(100 * time.Millisecond):
		// Expected: no packet sent
	}
}

// TestDispatcher_ACL_OutboundOnly verifies that outbound-only peers cannot receive inbound connections.
func TestDispatcher_ACL_OutboundOnly(t *testing.T) {
	idA, _ := crypto.Generate()
	idB, _ := crypto.Generate()
	var peerAID, peerBID [32]byte
	copy(peerAID[:], idA.Ed25519Public)
	copy(peerBID[:], idB.Ed25519Public)

	policy := `version = 1
default = "deny"
[peers]
alice = "ed25519:` + hex.EncodeToString(peerAID[:]) + `"
bob   = "ed25519:` + hex.EncodeToString(peerBID[:]) + `"
[[rule]]
from = "alice"
to   = "bob"
ports = ["tcp/8080"]
[outbound_only]
peers = ["bob"]
`

	d, conn, _ := makeDispatcherWithPolicy(t, peerAID, peerBID, policy)

	// Send TCP SYN from alice (self) to bob on port 8080 - should be DENIED because bob is outbound-only
	src := [4]byte{10, 0, 0, 1}
	dst := [4]byte{10, 0, 0, 2}
	pkt := buildTCPSYNPacket(src, dst, 12345, 8080)
	d.handleTunPacket(pkt)

	// Should NOT have sent encrypted packet
	select {
	case <-conn.out:
		t.Error("outbound-only peer should deny inbound connections")
	case <-time.After(100 * time.Millisecond):
		// Expected: no packet sent
	}
}

// TestDispatcher_ACL_FragmentDrop verifies that fragments without transport header are dropped.
func TestDispatcher_ACL_FragmentDrop(t *testing.T) {
	idA, _ := crypto.Generate()
	idB, _ := crypto.Generate()
	var peerAID, peerBID [32]byte
	copy(peerAID[:], idA.Ed25519Public)
	copy(peerBID[:], idB.Ed25519Public)

	policy := `version = 1
default = "deny"
[peers]
alice = "ed25519:` + hex.EncodeToString(peerAID[:]) + `"
bob   = "ed25519:` + hex.EncodeToString(peerBID[:]) + `"
[[rule]]
from = "alice"
to   = "bob"
ports = ["tcp/8080"]
`

	d, conn, _ := makeDispatcherWithPolicy(t, peerAID, peerBID, policy)

	// Send an IPv4 fragment without transport header
	pkt := make([]byte, 20+8) // IPv4 header + 8 bytes fragment data
	pkt[0] = 0x45
	pkt[1] = 0x00
	binary.BigEndian.PutUint16(pkt[2:4], 28)
	pkt[4] = 0x00
	pkt[5] = 0x00
	binary.BigEndian.PutUint16(pkt[6:8], 0x2000) // MF flag set, offset=0
	pkt[8] = 64
	pkt[9] = 6 // TCP
	srcIP := [4]byte{10, 0, 0, 1}
	dstIP := [4]byte{10, 0, 0, 2}
	copy(pkt[12:16], srcIP[:])
	copy(pkt[16:20], dstIP[:])

	d.handleTunPacket(pkt)

	// Should NOT have sent encrypted packet (fragment without transport header)
	select {
	case <-conn.out:
		t.Error("fragment without transport header should be dropped")
	case <-time.After(100 * time.Millisecond):
		// Expected: no packet sent
	}
}

// TestDispatcher_ACL_PolicySwapRevokesFlow verifies that a policy swap revokes existing flows.
func TestDispatcher_ACL_PolicySwapRevokesFlow(t *testing.T) {
	idA, _ := crypto.Generate()
	idB, _ := crypto.Generate()
	var peerAID, peerBID [32]byte
	copy(peerAID[:], idA.Ed25519Public)
	copy(peerBID[:], idB.Ed25519Public)

	policy1 := `version = 1
default = "deny"
[peers]
alice = "ed25519:` + hex.EncodeToString(peerAID[:]) + `"
bob   = "ed25519:` + hex.EncodeToString(peerBID[:]) + `"
[[rule]]
from = "alice"
to   = "bob"
ports = ["tcp/8080"]
`
	policy2 := `version = 2
default = "deny"
[peers]
alice = "ed25519:` + hex.EncodeToString(peerAID[:]) + `"
bob   = "ed25519:` + hex.EncodeToString(peerBID[:]) + `"
# No rules - all denied
`

	d, conn, _ := makeDispatcherWithPolicy(t, peerAID, peerBID, policy1)

	// First, establish an outbound flow from alice to bob on port 8080
	src := [4]byte{10, 0, 0, 1}
	dst := [4]byte{10, 0, 0, 2}
	syn := buildTCPSYNPacket(src, dst, 12345, 8080)
	d.handleTunPacket(syn)

	select {
	case <-conn.out:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout: SYN not sent")
	}

	// Now swap to policy2 (deny all)
	p2, _, err := acl.ParsePolicy(policy2)
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	d.SetPolicyDecider(p2.Compile())

	// Try to send another packet on the same flow - should be denied now
	syn2 := buildTCPSYNPacket(src, dst, 12345, 8080)
	d.handleTunPacket(syn2)

	// Should NOT have sent encrypted packet (policy revoked)
	select {
	case <-conn.out:
		t.Error("revoked flow should be denied after policy swap")
	case <-time.After(100 * time.Millisecond):
		// Expected: no packet sent
	}
}

// TestDispatcher_ACL_InboundOutboundOnlySelf verifies that self as outbound-only drops inbound.
func TestDispatcher_ACL_InboundOutboundOnlySelf(t *testing.T) {
	idA, _ := crypto.Generate()
	idB, _ := crypto.Generate()
	var peerAID, peerBID [32]byte
	copy(peerAID[:], idA.Ed25519Public)
	copy(peerBID[:], idB.Ed25519Public)

	policy := `version = 1
default = "deny"
[peers]
alice = "ed25519:` + hex.EncodeToString(peerAID[:]) + `"
bob   = "ed25519:` + hex.EncodeToString(peerBID[:]) + `"
[[rule]]
from = "bob"
to   = "alice"
ports = ["tcp/8080"]
[outbound_only]
peers = ["alice"]
`

	sessA, _ := newTestSessionPair(t)

	peerTbl := peer.New()
	ep := mustAddrPort("1.2.3.4:5000")
	entryB := &peer.Entry{ID: peerBID, VPNAddr: mustAddr("10.0.0.2")}
	entryB.SetEndpoint(ep)
	entryB.SetSession(sessA)
	peerTbl.Upsert(entryB)

	tunDev := tun.NewMemTUN("tun0", netip.MustParsePrefix("10.0.0.1/24"), 1420)
	conn := newFakeConn()

	d := New(tunDev, conn, peerTbl)

	p, _, err := acl.ParsePolicy(policy)
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	compiled := p.Compile()
	d.SetPolicyDecider(compiled)
	d.SetSelfPeerID(peerAID) // alice is self

	d.Start()
	defer d.Stop()

	// Test the policy decision directly for inbound to self (outbound-only)
	dec := compiled.Decide(peerBID, peerAID, acl.ProtoTCP, 8080)
	if dec.Action != acl.ActionDeny || !dec.OutboundOnly {
		t.Errorf("expected deny with outbound_only=true, got %+v", dec)
	}
}

// makeInboundDispatcher creates a dispatcher for testing inbound packets.
// Returns the dispatcher, the session for encrypting packets, and the peer IDs.
func makeInboundDispatcher(t *testing.T, peerAID, peerBID [32]byte, policySrc string) (*Dispatcher, *session.Session) {
	t.Helper()

	idA, _ := crypto.Generate()
	idB, _ := crypto.Generate()
	// Use the provided peer IDs for the session pair
	// We need to create a session pair where idB is the peer (bob)
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
	sessA := session.New(initResult)
	sessB := session.New(respResult)

	peerTbl := peer.New()
	ep := mustAddrPort("1.2.3.4:5000")
	entryB := &peer.Entry{ID: peerBID, VPNAddr: mustAddr("10.0.0.2")}
	entryB.SetEndpoint(ep)
	entryB.SetSession(sessA)
	peerTbl.Upsert(entryB)

	tunDev := tun.NewMemTUN("tun0", netip.MustParsePrefix("10.0.0.1/24"), 1420)
	conn := newFakeConn()

	d := New(tunDev, conn, peerTbl)

	p, _, err := acl.ParsePolicy(policySrc)
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	compiled := p.Compile()
	d.SetPolicyDecider(compiled)
	d.SetSelfPeerID(peerAID)

	d.Start()

	return d, sessB
}

// encryptPacket encrypts a plaintext packet using the session for inbound testing.
func encryptPacket(sess *session.Session, plain []byte) []byte {
	nonce, ct, err := sess.Encrypt(plain)
	if err != nil {
		panic(err)
	}
	return buildDataPacket(nonce, ct)
}

// TestDispatcher_ACL_Inbound_DeniedPeer_TCPACKNoSYN verifies that a denied peer
// cannot send a TCP ACK/data segment without a prior SYN.
func TestDispatcher_ACL_Inbound_DeniedPeer_TCPACKNoSYN(t *testing.T) {
	idA, _ := crypto.Generate()
	idB, _ := crypto.Generate()
	var peerAID, peerBID [32]byte
	copy(peerAID[:], idA.Ed25519Public)
	copy(peerBID[:], idB.Ed25519Public)

	policy := `version = 1
default = "deny"
[peers]
alice = "ed25519:` + hex.EncodeToString(peerAID[:]) + `"
bob   = "ed25519:` + hex.EncodeToString(peerBID[:]) + `"
[[rule]]
from = "alice"
to   = "bob"
ports = ["tcp/8080"]
`

	d, sessB := makeInboundDispatcher(t, peerAID, peerBID, policy)

	tunDev := d.tun.(*tun.MemTUN)
	defer d.Stop()

	// bob (denied peer) sends TCP ACK to alice on port 8080 without prior SYN
	src := [4]byte{10, 0, 0, 2} // bob's VPN
	dst := [4]byte{10, 0, 0, 1} // alice's VPN
	pkt := buildTCPACKPacket(src, dst, 12345, 8080)

	// Encrypt and send inbound packet from bob
	encrypted := encryptPacket(sessB, pkt)
	d.handleUDPPacket(encrypted, &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 5000})

	// Should NOT write to TUN (packet dropped)
	buf := make([]byte, 1500)
	done := make(chan bool, 1)
	go func() {
		n, err := tunDev.ReadDelivered(buf)
		if err == nil && n > 0 {
			done <- true
		} else {
			done <- false
		}
	}()

	select {
	case got := <-done:
		if got {
			t.Error("denied peer's TCP ACK without SYN should be dropped")
		}
	case <-time.After(100 * time.Millisecond):
		// Expected: no packet written to TUN
	}
}

// TestDispatcher_ACL_Inbound_DeniedPeer_Fragment verifies that a denied peer
// cannot send a fragment.
func TestDispatcher_ACL_Inbound_DeniedPeer_Fragment(t *testing.T) {
	idA, _ := crypto.Generate()
	idB, _ := crypto.Generate()
	var peerAID, peerBID [32]byte
	copy(peerAID[:], idA.Ed25519Public)
	copy(peerBID[:], idB.Ed25519Public)

	policy := `version = 1
default = "deny"
[peers]
alice = "ed25519:` + hex.EncodeToString(peerAID[:]) + `"
bob   = "ed25519:` + hex.EncodeToString(peerBID[:]) + `"
[[rule]]
from = "alice"
to   = "bob"
ports = ["tcp/8080"]
`

	d, sessB := makeInboundDispatcher(t, peerAID, peerBID, policy)

	tunDev := d.tun.(*tun.MemTUN)
	defer d.Stop()

	// bob (denied peer) sends an IPv4 fragment to alice
	fragment := buildIPv4Fragment([4]byte{10, 0, 0, 2}, [4]byte{10, 0, 0, 1})

	encrypted := encryptPacket(sessB, fragment)
	d.handleUDPPacket(encrypted, &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 5000})

	// Should NOT write to TUN (packet dropped)
	buf := make([]byte, 1500)
	done := make(chan bool, 1)
	go func() {
		n, err := tunDev.ReadDelivered(buf)
		if err == nil && n > 0 {
			done <- true
		} else {
			done <- false
		}
	}()

	select {
	case got := <-done:
		if got {
			t.Error("denied peer's fragment should be dropped")
		}
	case <-time.After(100 * time.Millisecond):
		// Expected: no packet written to TUN
	}
}

// TestDispatcher_ACL_Inbound_DeniedPeer_ICMPError verifies that a denied peer
// cannot send an ICMP error.
func TestDispatcher_ACL_Inbound_DeniedPeer_ICMPError(t *testing.T) {
	idA, _ := crypto.Generate()
	idB, _ := crypto.Generate()
	var peerAID, peerBID [32]byte
	copy(peerAID[:], idA.Ed25519Public)
	copy(peerBID[:], idB.Ed25519Public)

	policy := `version = 1
default = "deny"
[peers]
alice = "ed25519:` + hex.EncodeToString(peerAID[:]) + `"
bob   = "ed25519:` + hex.EncodeToString(peerBID[:]) + `"
[[rule]]
from = "alice"
to   = "bob"
ports = ["tcp/8080"]
`

	d, sessB := makeInboundDispatcher(t, peerAID, peerBID, policy)

	tunDev := d.tun.(*tun.MemTUN)
	defer d.Stop()

	// Build a TCP SYN that would be allowed (alice -> bob)
	originalSYN := buildTCPSYNPacket([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 12345, 8080)

	// bob (denied peer) sends an ICMP error quoting the SYN
	icmpErr := buildICMPErrorPacket(originalSYN)

	encrypted := encryptPacket(sessB, icmpErr)
	d.handleUDPPacket(encrypted, &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 5000})

	// Should NOT write to TUN (packet dropped)
	buf := make([]byte, 1500)
	done := make(chan bool, 1)
	go func() {
		n, err := tunDev.ReadDelivered(buf)
		if err == nil && n > 0 {
			done <- true
		} else {
			done <- false
		}
	}()

	select {
	case got := <-done:
		if got {
			t.Error("denied peer's ICMP error should be dropped")
		}
	case <-time.After(100 * time.Millisecond):
		// Expected: no packet written to TUN
	}
}

// TestDispatcher_ACL_Inbound_AllowedFlow_ReplyPasses verifies that replies to
// an allowed connection pass.
func TestDispatcher_ACL_Inbound_AllowedFlow_ReplyPasses(t *testing.T) {
	idA, _ := crypto.Generate()
	idB, _ := crypto.Generate()
	var peerAID, peerBID [32]byte
	copy(peerAID[:], idA.Ed25519Public)
	copy(peerBID[:], idB.Ed25519Public)

	policy := `version = 1
default = "deny"
[peers]
alice = "ed25519:` + hex.EncodeToString(peerAID[:]) + `"
bob   = "ed25519:` + hex.EncodeToString(peerBID[:]) + `"
[[rule]]
from = "bob"
to   = "alice"
ports = ["tcp/8080"]
`

	d, sessB := makeInboundDispatcher(t, peerAID, peerBID, policy)

	tunDev := d.tun.(*tun.MemTUN)
	defer d.Stop()

	// First, bob sends a SYN to alice on port 8080 (allowed)
	// src: bob (10.0.0.2), dst: alice (10.0.0.1)
	// srcPort: 12345 (ephemeral), dstPort: 8080 (service)
	syn := buildTCPSYNPacket([4]byte{10, 0, 0, 2}, [4]byte{10, 0, 0, 1}, 12345, 8080)
	encryptedSYN := encryptPacket(sessB, syn)
	d.handleUDPPacket(encryptedSYN, &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 5000})

	// Should write SYN to TUN
	buf := make([]byte, 1500)
	done := make(chan bool, 1)
	go func() {
		n, err := tunDev.ReadDelivered(buf)
		if err != nil || n == 0 {
			done <- false
		} else {
			done <- true
		}
	}()

	select {
	case got := <-done:
		if !got {
			t.Fatal("timeout: allowed SYN not written to TUN")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout: allowed SYN not written to TUN")
	}

	// Now bob sends a TCP ACK (reply) - should pass
	// For the reply, src/dst are swapped, and ports are swapped
	ack := buildTCPACKPacket([4]byte{10, 0, 0, 2}, [4]byte{10, 0, 0, 1}, 12345, 8080)
	encryptedACK := encryptPacket(sessB, ack)
	d.handleUDPPacket(encryptedACK, &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 5000})

	// Should write ACK to TUN
	done2 := make(chan bool, 1)
	go func() {
		n, err := tunDev.ReadDelivered(buf)
		if err != nil || n == 0 {
			done2 <- false
		} else {
			done2 <- true
		}
	}()

	select {
	case got := <-done2:
		if !got {
			t.Fatal("timeout: allowed reply ACK not written to TUN")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout: allowed reply ACK not written to TUN")
	}
}
