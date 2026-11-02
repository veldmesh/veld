// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package dataplane

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"

	"github.com/veldmesh/veld/internal/acl"
	"github.com/veldmesh/veld/internal/crypto"
	"github.com/veldmesh/veld/internal/peer"
	"github.com/veldmesh/veld/internal/tun"
)

var (
	benchmarkDispatcherNoPolicy *Dispatcher
	benchmarkDispatcher50Rules  *Dispatcher
	benchmarkTCPSYNPacket       []byte
	benchmarkUDPPacket          []byte
	benchmarkPeerID             [32]byte
	benchmarkOtherPeerID        [32]byte
)

func init() {
	// Create a test identity
	id, _ := crypto.Generate()
	copy(benchmarkPeerID[:], id.Ed25519Public)

	// Other peer ID
	benchmarkOtherPeerID[0] = 1
	benchmarkOtherPeerID[1] = 2

	// Build a TCP SYN packet
	benchmarkTCPSYNPacket = buildTCPSYNPacketForBench()

	// Build a UDP packet
	benchmarkUDPPacket = buildUDPPacketForBench()

	conn, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer conn.Close()

	tunDev := tun.NewMemTUN("benchTUN", netip.MustParsePrefix("10.100.0.1/24"), 1420)

	// Set up peer table with a valid session
	tbl := peer.New()
	entry := &peer.Entry{
		ID:        benchmarkOtherPeerID,
		X25519Pub: id.X25519Public,
		VPNAddr:   netip.MustParseAddr("10.100.0.2"),
		Name:      "peer2",
	}
	ep, _ := netip.ParseAddrPort(conn.LocalAddr().String())
	entry.SetEndpoint(ep)
	// Note: session is nil, so handleTunPacket will enqueue and return
	tbl.Upsert(entry)

	// Dispatcher with no policy
	dispNoPolicy := New(tunDev, conn, tbl)
	dispNoPolicy.SetSelfPeerID(benchmarkPeerID)
	dispNoPolicy.Start()
	benchmarkDispatcherNoPolicy = dispNoPolicy

	// Dispatcher with 50-rule policy
	policy50 := create50RulePolicy(benchmarkPeerID, benchmarkOtherPeerID)
	compiled50 := policy50.Compile()

	tunDev2 := tun.NewMemTUN("benchTUN2", netip.MustParsePrefix("10.100.0.1/24"), 1420)
	conn2, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer conn2.Close()

	tbl2 := peer.New()
	entry2 := &peer.Entry{
		ID:        benchmarkOtherPeerID,
		X25519Pub: id.X25519Public,
		VPNAddr:   netip.MustParseAddr("10.100.0.2"),
		Name:      "peer2",
	}
	ep2, _ := netip.ParseAddrPort(conn2.LocalAddr().String())
	entry2.SetEndpoint(ep2)
	tbl2.Upsert(entry2)

	disp50 := New(tunDev2, conn2, tbl2)
	disp50.SetSelfPeerID(benchmarkPeerID)
	disp50.SetPolicyDecider(compiled50)
	disp50.Start()
	benchmarkDispatcher50Rules = disp50
}

func buildTCPSYNPacketForBench() []byte {
	pkt := make([]byte, 40)
	pkt[0] = 0x45
	pkt[1] = 0x00
	binary.BigEndian.PutUint16(pkt[2:4], 40)
	binary.BigEndian.PutUint16(pkt[4:6], 0)
	binary.BigEndian.PutUint16(pkt[6:8], 0)
	pkt[8] = 64
	pkt[9] = 6
	binary.BigEndian.PutUint32(pkt[12:16], 0x0a000001) // 10.0.0.1
	binary.BigEndian.PutUint32(pkt[16:20], 0x0a640002) // 10.100.0.2
	binary.BigEndian.PutUint16(pkt[20:22], 12345)
	binary.BigEndian.PutUint16(pkt[22:24], 8080)
	binary.BigEndian.PutUint32(pkt[24:28], 0)
	binary.BigEndian.PutUint32(pkt[28:32], 0)
	pkt[32] = 0x50
	pkt[33] = 0x02 // SYN
	return pkt
}

func buildUDPPacketForBench() []byte {
	pkt := make([]byte, 28)
	pkt[0] = 0x45
	pkt[1] = 0x00
	binary.BigEndian.PutUint16(pkt[2:4], 28)
	binary.BigEndian.PutUint16(pkt[4:6], 0)
	binary.BigEndian.PutUint16(pkt[6:8], 0)
	pkt[8] = 64
	pkt[9] = 17
	binary.BigEndian.PutUint32(pkt[12:16], 0x0a640002) // 10.100.0.2
	binary.BigEndian.PutUint32(pkt[16:20], 0x0a000001) // 10.0.0.1
	binary.BigEndian.PutUint16(pkt[20:22], 8080)
	binary.BigEndian.PutUint16(pkt[22:24], 12345)
	binary.BigEndian.PutUint16(pkt[24:26], 8)
	return pkt
}

func create50RulePolicy(selfPeerID, otherPeerID [32]byte) *acl.Policy {
	peers := map[string]acl.PeerKey{
		"self":  selfPeerID,
		"peer2": otherPeerID,
	}

	rules := make([]acl.Rule, 50)
	for i := 0; i < 50; i++ {
		port := uint16(1000 + i)
		rules[i] = acl.Rule{
			From: "self",
			To:   "peer2",
			Ports: []acl.PortRange{
				{Proto: acl.ProtoTCP, Start: port, End: port},
			},
		}
	}

	return &acl.Policy{
		Version:      1,
		Default:      acl.DefaultDeny,
		Peers:        peers,
		Tags:         map[string][]string{},
		Rules:        rules,
		OutboundOnly: []string{},
	}
}

// BenchmarkHandleTunPacketACL benchmarks just the ACL check portion of handleTunPacket
func BenchmarkHandleTunPacketACL_NoPolicy(b *testing.B) {
	d := benchmarkDispatcherNoPolicy
	pkt := benchmarkTCPSYNPacket

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Simulate the ACL check from handleTunPacket
		pd := d.getPolicyDecider()
		if pd != nil {
			flow, _, _ := acl.ParsePacket(pkt)
			if flow.Proto != 0 {
				// Mock entry lookup
				entry, _ := d.peers.LookupByVPN(netip.MustParseAddr("10.100.0.2"))
				if entry != nil {
					pd.Decide(d.selfPeerID, entry.ID, flow.Proto, flow.DstPort)
				}
			}
		}
	}
}

func BenchmarkHandleTunPacketACL_50Rules(b *testing.B) {
	d := benchmarkDispatcher50Rules
	pkt := benchmarkTCPSYNPacket

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pd := d.getPolicyDecider()
		if pd != nil {
			flow, _, _ := acl.ParsePacket(pkt)
			if flow.Proto != 0 {
				entry, _ := d.peers.LookupByVPN(netip.MustParseAddr("10.100.0.2"))
				if entry != nil {
					pd.Decide(d.selfPeerID, entry.ID, flow.Proto, flow.DstPort)
				}
			}
		}
	}
}

// BenchmarkHandleUDPPacketACL benchmarks just the ACL check portion of handleUDPPacket
func BenchmarkHandleUDPPacketACL_NoPolicy(b *testing.B) {
	d := benchmarkDispatcherNoPolicy
	pkt := benchmarkUDPPacket

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pd := d.getPolicyDecider()
		if pd != nil {
			flow, _, _ := acl.ParsePacket(pkt)
			if flow.Proto != 0 {
				srcPeerID := benchmarkOtherPeerID
				pd.Decide(srcPeerID, d.selfPeerID, flow.Proto, flow.DstPort)
			}
		}
	}
}

func BenchmarkHandleUDPPacketACL_50Rules(b *testing.B) {
	d := benchmarkDispatcher50Rules
	pkt := benchmarkUDPPacket

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pd := d.getPolicyDecider()
		if pd != nil {
			flow, _, _ := acl.ParsePacket(pkt)
			if flow.Proto != 0 {
				srcPeerID := benchmarkOtherPeerID
				pd.Decide(srcPeerID, d.selfPeerID, flow.Proto, flow.DstPort)
			}
		}
	}
}

// BenchmarkFullHandleTunPacket_NoPolicy benchmarks the full handleTunPacket path (with nil session)
func BenchmarkFullHandleTunPacket_NoPolicy(b *testing.B) {
	d := benchmarkDispatcherNoPolicy
	pkt := benchmarkTCPSYNPacket

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.handleTunPacket(pkt)
	}
}

func BenchmarkFullHandleTunPacket_50Rules(b *testing.B) {
	d := benchmarkDispatcher50Rules
	pkt := benchmarkTCPSYNPacket

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.handleTunPacket(pkt)
	}
}

// BenchmarkFullHandleUDPPacket_NoPolicy benchmarks the full handleUDPPacket path
func BenchmarkFullHandleUDPPacket_NoPolicy(b *testing.B) {
	d := benchmarkDispatcherNoPolicy
	// Build a full UDP packet with header
	header := make([]byte, HeaderSize)
	binary.BigEndian.PutUint64(header[0:8], 1)
	header[8] = byte(TypeData)
	fullPkt := append(header, benchmarkUDPPacket...)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.handleUDPPacket(fullPkt, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345})
	}
}

func BenchmarkFullHandleUDPPacket_50Rules(b *testing.B) {
	d := benchmarkDispatcher50Rules
	header := make([]byte, HeaderSize)
	binary.BigEndian.PutUint64(header[0:8], 1)
	header[8] = byte(TypeData)
	fullPkt := append(header, benchmarkUDPPacket...)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.handleUDPPacket(fullPkt, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345})
	}
}
