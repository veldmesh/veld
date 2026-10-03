// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package e2e_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/veldmesh/veld/internal/crypto"
	"github.com/veldmesh/veld/internal/nat"
	"github.com/veldmesh/veld/internal/peer"
	"github.com/veldmesh/veld/internal/relay"
)

// TestRelayFallback_TwoPeers is an end-to-end test of the relay fallback path:
// two peers behind simulated symmetric NATs (their NAT probes are blackholed,
// so hole punching times out), NAT signals exchanged directly the way the
// coord server would relay them, both sides falling back to a volunteer relay
// peer, and a data-plane datagram delivered end-to-end through the relay.
//
// The relay service runs in-process and speaks the real Noise IK channel
// protocol; it can forward frames but cannot read the datagram payloads
// (they are session-encrypted end-to-end in production — here we assert on
// observable byte delivery across the relay).
func TestRelayFallback_TwoPeers(t *testing.T) {
	// Volunteer relay peer reachable by both nodes.
	relayID, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate relay identity: %v", err)
	}
	relayLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("relay listen: %v", err)
	}
	relaySvc := relay.NewService(relayID, relayLn)
	go relaySvc.Serve(context.Background()) //nolint:errcheck
	t.Cleanup(func() { relaySvc.Close() })
	relayAddr := relaySvc.Addr()
	relayKey := relayID.X25519Public

	idA, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate idA: %v", err)
	}
	idB, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate idB: %v", err)
	}

	connA, portA := makeDataConn(t)
	connB, portB := makeDataConn(t)

	mgrA := nat.New(connA, portA, "" /*no STUN in tests*/, idA)
	mgrB := nat.New(connB, portB, "" /*no STUN in tests*/, idB)

	// No pumpNATProbes goroutines: probes are blackholed, simulating both
	// peers behind symmetric NATs. Hole punching must time out.

	// Relay fallback wiring, mirroring daemon.NewFromConfig: on punch timeout,
	// dial the relay on the pair's rendezvous channel and stand up a loopback
	// proxy whose address becomes the peer's endpoint.

	type fallback struct {
		proxy *relay.Proxy
		err   error
	}
	fellBackA := make(chan fallback, 1)
	fellBackB := make(chan fallback, 1)

	dataTargetA := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(portA)}
	dataTargetB := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(portB)}

	var selfA, selfB [32]byte
	copy(selfA[:], idA.Ed25519Public)
	copy(selfB[:], idB.Ed25519Public)

	entryA := &peer.Entry{ID: selfA, X25519Pub: idA.X25519Public}
	entryA.VPNAddr = netip.MustParseAddr("10.60.0.1")
	entryB := &peer.Entry{ID: selfB, X25519Pub: idB.X25519Public}
	entryB.VPNAddr = netip.MustParseAddr("10.60.0.2")

	mgrA.OnPunchTimeout = func(peerID [32]byte) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		rc, err := relay.Dial(ctx, relayAddr, relayKey, idA, entryB.X25519Pub)
		if err != nil {
			fellBackA <- fallback{err: err}
			return
		}
		p, err := relay.NewProxy(rc, dataTargetA)
		if err != nil {
			_ = rc.Close()
		}
		fellBackA <- fallback{proxy: p, err: err}
	}
	mgrB.OnPunchTimeout = func(peerID [32]byte) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		rc, err := relay.Dial(ctx, relayAddr, relayKey, idB, entryA.X25519Pub)
		if err != nil {
			fellBackB <- fallback{err: err}
			return
		}
		p, err := relay.NewProxy(rc, dataTargetB)
		if err != nil {
			_ = rc.Close()
		}
		fellBackB <- fallback{proxy: p, err: err}
	}

	// Exchange NAT signals directly, as the coord server would relay them.
	peerIDofA := hex.EncodeToString(idA.Ed25519Public[:32])
	peerIDofB := hex.EncodeToString(idB.Ed25519Public[:32])
	sendAtoB := func(payload []byte) error { mgrB.DeliverSignal(peerIDofA, payload); return nil }
	sendBtoA := func(payload []byte) error { mgrA.DeliverSignal(peerIDofB, payload); return nil }

	mgrA.Start(context.Background(), entryB, sendAtoB)
	mgrB.Start(context.Background(), entryA, sendBtoA)

	// Hole punching must fail and both sides must fall back to the relay.
	timeout := time.After(30 * time.Second)
	var proxyA, proxyB *relay.Proxy
	for i := 0; i < 2; i++ {
		select {
		case f := <-fellBackA:
			if f.err != nil {
				t.Fatalf("A relay fallback: %v", f.err)
			}
			proxyA = f.proxy
		case f := <-fellBackB:
			if f.err != nil {
				t.Fatalf("B relay fallback: %v", f.err)
			}
			proxyB = f.proxy
		case <-timeout:
			t.Fatal("timeout waiting for relay fallback on both peers")
		}
	}
	defer proxyA.Close()
	defer proxyB.Close()

	// Observable behaviour: a data-plane datagram sent to the peer's relay
	// endpoint arrives on the other node's data-plane socket, and vice versa.
	msg := []byte("A to B over relay")
	if _, err := connA.WriteTo(msg, net.UDPAddrFromAddrPort(proxyA.LocalAddr())); err != nil {
		t.Fatalf("A write: %v", err)
	}
	buf := make([]byte, 2048)
	// Stray in-flight NAT probes from the timed-out punching round may still
	// arrive on the data conn (the real dispatcher filters them by packet
	// type); skip anything that isn't the expected datagram. A bounded
	// deadline is set per iteration so skipped packets can't extend the
	// overall wait indefinitely.
	for {
		connB.SetReadDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck
		n, fromB, err := connB.ReadFrom(buf)
		if err != nil {
			t.Fatalf("B read: %v", err)
		}
		if !bytes.Equal(buf[:n], msg) {
			continue
		}
		if fromB.(*net.UDPAddr).Port != int(proxyB.LocalAddr().Port()) {
			t.Errorf("B sees source port %d, want its relay proxy port %d",
				fromB.(*net.UDPAddr).Port, proxyB.LocalAddr().Port())
		}
		break
	}

	reply := []byte("B to A over relay")
	if _, err := connB.WriteTo(reply, net.UDPAddrFromAddrPort(proxyB.LocalAddr())); err != nil {
		t.Fatalf("B write: %v", err)
	}
	// Same stray-probe filtering as above, with a bounded per-iteration
	// deadline.
	for {
		connA.SetReadDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck
		n, fromA, err := connA.ReadFrom(buf)
		if err != nil {
			t.Fatalf("A read: %v", err)
		}
		if !bytes.Equal(buf[:n], reply) {
			continue
		}
		if fromA.(*net.UDPAddr).Port != int(proxyA.LocalAddr().Port()) {
			t.Errorf("A sees source port %d, want its relay proxy port %d",
				fromA.(*net.UDPAddr).Port, proxyA.LocalAddr().Port())
		}
		break
	}
}
