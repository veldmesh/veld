// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package e2e_test

import (
	"context"
	"encoding/hex"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/veldmesh/veld/internal/coord"
	"github.com/veldmesh/veld/internal/crypto"
	"github.com/veldmesh/veld/internal/nat"
	"github.com/veldmesh/veld/internal/peer"
)

// makeDataConn opens a UDP listener on a random loopback port.
func makeDataConn(t *testing.T) (net.PacketConn, uint16) {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	port := conn.LocalAddr().(*net.UDPAddr).Port
	return conn, uint16(port)
}

// pumpNATProbes forwards TypeNATProbe packets from conn into mgr.HandleProbe.
func pumpNATProbes(conn net.PacketConn, mgr *nat.Manager) {
	buf := make([]byte, 64)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		if n < 4 {
			continue
		}
		pktType := uint32(buf[0])<<24 | uint32(buf[1])<<16 | uint32(buf[2])<<8 | uint32(buf[3])
		if pktType == 0x05 {
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			mgr.HandleProbe(pkt, addr)
		}
	}
}

// TestNATTraversal_TwoPeersViaCoord is an end-to-end test that starts two
// coord clients and two NAT managers, and verifies that each peer discovers
// the other's UDP endpoint using the full signal relay path through the
// in-process coord server.
func TestNATTraversal_TwoPeersViaCoord(t *testing.T) {
	cidr := netip.MustParsePrefix("10.60.0.0/24")
	serverAddr, stopServer := startCoordServer(t, "nat-e2e", cidr)
	defer stopServer()

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

	tblA := peer.New()
	tblB := peer.New()

	mgrA := nat.New(connA, portA, "" /*no STUN in tests*/, idA)
	mgrB := nat.New(connB, portB, "" /*no STUN in tests*/, idB)

	discoveredByA := make(chan netip.AddrPort, 2)
	discoveredByB := make(chan netip.AddrPort, 2)

	mgrA.OnEndpointDiscovered = func(_ [32]byte, ep netip.AddrPort) {
		select {
		case discoveredByA <- ep:
		default:
		}
	}
	mgrB.OnEndpointDiscovered = func(_ [32]byte, ep netip.AddrPort) {
		select {
		case discoveredByB <- ep:
		default:
		}
	}

	go pumpNATProbes(connA, mgrA)
	go pumpNATProbes(connB, mgrB)

	// Wire coord clients.
	cA := coord.New(coord.Config{
		ServerAddr:  serverAddr,
		NetworkID:   "nat-e2e",
		Token:       "e2e-token",
		Identity:    idA,
		LocalName:   "node-a",
		PeerTable:   tblA,
		TLSInsecure: true,
	})
	cB := coord.New(coord.Config{
		ServerAddr:  serverAddr,
		NetworkID:   "nat-e2e",
		Token:       "e2e-token",
		Identity:    idB,
		LocalName:   "node-b",
		PeerTable:   tblB,
		TLSInsecure: true,
	})

	// When a peer is discovered: start NAT negotiation.
	// The sendFn uses coord SendSignal to relay the encrypted candidate payload.
	cA.OnPeerAdded = func(e *peer.Entry) {
		toPeerID := hex.EncodeToString(e.ID[:])
		sendFn := func(payload []byte) error {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return cA.SendSignal(ctx, toPeerID, payload)
		}
		mgrA.Start(context.Background(), e, sendFn)
	}
	cB.OnPeerAdded = func(e *peer.Entry) {
		toPeerID := hex.EncodeToString(e.ID[:])
		sendFn := func(payload []byte) error {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return cB.SendSignal(ctx, toPeerID, payload)
		}
		mgrB.Start(context.Background(), e, sendFn)
	}

	// Wire signal delivery from coord to NAT manager.
	cA.OnSignal = mgrA.DeliverSignal
	cB.OnSignal = mgrB.DeliverSignal

	cA.Start()
	defer func() { cA.Stop(); cA.Wait() }()
	cB.Start()
	defer func() { cB.Stop(); cB.Wait() }()

	// Wait for mutual endpoint discovery.
	timeout := time.After(10 * time.Second)
	var epAtA, epAtB netip.AddrPort
	remaining := 2
	for remaining > 0 {
		select {
		case ep := <-discoveredByA:
			epAtA = ep
			remaining--
		case ep := <-discoveredByB:
			epAtB = ep
			remaining--
		case <-timeout:
			t.Fatalf("timeout: A discovered=%v B discovered=%v", epAtA.IsValid(), epAtB.IsValid())
		}
	}

	if !epAtA.IsValid() {
		t.Error("A did not discover B's endpoint")
	}
	if !epAtB.IsValid() {
		t.Error("B did not discover A's endpoint")
	}

	// On loopback, each side should see the other's data-plane port.
	if epAtA.Port() != portB {
		t.Errorf("A sees B at port %d, want %d", epAtA.Port(), portB)
	}
	if epAtB.Port() != portA {
		t.Errorf("B sees A at port %d, want %d", epAtB.Port(), portA)
	}
}
