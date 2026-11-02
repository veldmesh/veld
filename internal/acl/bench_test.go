// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package acl

import (
	"testing"
)

var benchmarkPolicy *CompiledPolicy
var benchmarkFlowTable *FlowTable

func init() {
	// Set up a realistic policy for benchmarking
	peers := make(map[string]PeerKey)
	for i := 0; i < 100; i++ {
		var key PeerKey
		key[0] = byte(i)
		key[1] = byte(i >> 8)
		peers[peerName(i)] = key
	}

	rules := []Rule{
		{From: "*", To: "*", Ports: []PortRange{{Proto: ProtoTCP, Start: 22, End: 22}}},
		{From: "tag:admins", To: "tag:servers", Ports: []PortRange{{Proto: ProtoTCP, Start: 443, End: 443}}},
		{From: "peer1", To: "peer2", Ports: []PortRange{{Proto: ProtoUDP, Start: 53, End: 53}}},
	}

	tags := map[string][]string{
		"admins":  {"peer1", "peer2", "peer3"},
		"servers": {"peer10", "peer11", "peer12"},
	}

	p := &Policy{
		Version:      1,
		Default:      DefaultDeny,
		Peers:        peers,
		Tags:         tags,
		Rules:        rules,
		OutboundOnly: []string{"peer50"},
	}
	benchmarkPolicy = p.Compile()
	benchmarkFlowTable = NewFlowTable(DefaultFlowTableConfig())
}

func peerName(i int) string {
	if i < 10 {
		return "peer0" + string(rune('0'+i))
	}
	return "peer" + string(rune('0'+i/10)) + string(rune('0'+i%10))
}

func BenchmarkDecide(b *testing.B) {
	src := PeerKey{1: 1}
	dst := PeerKey{1: 2}
	proto := ProtoTCP
	port := uint16(22)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkPolicy.Decide(src, dst, proto, port)
	}
}

func BenchmarkDecide_Miss(b *testing.B) {
	src := PeerKey{1: 99} // Not in policy
	dst := PeerKey{1: 2}
	proto := ProtoTCP
	port := uint16(22)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkPolicy.Decide(src, dst, proto, port)
	}
}

func BenchmarkDecide_RuleMatch(b *testing.B) {
	src := PeerKey{0: 1}  // peer1
	dst := PeerKey{0: 10} // peer10
	proto := ProtoTCP
	port := uint16(443)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkPolicy.Decide(src, dst, proto, port)
	}
}

func BenchmarkParsePacket_IPv4TCP(b *testing.B) {
	pkt := make([]byte, 40)
	pkt[0] = 0x45
	pkt[1] = 0x00
	binaryBigEndianPutUint16(pkt[2:4], 40)
	binaryBigEndianPutUint16(pkt[4:6], 0)
	binaryBigEndianPutUint16(pkt[6:8], 0)
	pkt[8] = 64
	pkt[9] = 6
	binaryBigEndianPutUint32(pkt[12:16], 0x0a000001)
	binaryBigEndianPutUint32(pkt[16:20], 0x0a000002)
	binaryBigEndianPutUint16(pkt[20:22], 12345)
	binaryBigEndianPutUint16(pkt[22:24], 22)
	binaryBigEndianPutUint32(pkt[24:28], 0)
	binaryBigEndianPutUint32(pkt[28:32], 0)
	pkt[32] = 0x50
	pkt[33] = 0x02

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ParsePacket(pkt)
	}
}

func BenchmarkParsePacket_IPv6TCP(b *testing.B) {
	pkt := make([]byte, 60)
	pkt[0] = 0x60
	pkt[1] = 0x00
	pkt[2] = 0x00
	pkt[3] = 0x00
	binaryBigEndianPutUint16(pkt[4:6], 20)
	pkt[6] = 6
	pkt[7] = 64
	copy(pkt[8:24], []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01})
	copy(pkt[24:40], []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02})
	binaryBigEndianPutUint16(pkt[40:42], 12345)
	binaryBigEndianPutUint16(pkt[42:44], 22)
	binaryBigEndianPutUint32(pkt[44:48], 0)
	binaryBigEndianPutUint32(pkt[48:52], 0)
	pkt[52] = 0x50
	pkt[53] = 0x02

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ParsePacket(pkt)
	}
}

func BenchmarkParsePacket_IPv4UDP(b *testing.B) {
	pkt := make([]byte, 28)
	pkt[0] = 0x45
	pkt[1] = 0x00
	binaryBigEndianPutUint16(pkt[2:4], 28)
	binaryBigEndianPutUint16(pkt[4:6], 0)
	binaryBigEndianPutUint16(pkt[6:8], 0)
	pkt[8] = 64
	pkt[9] = 17
	binaryBigEndianPutUint32(pkt[12:16], 0x0a000001)
	binaryBigEndianPutUint32(pkt[16:20], 0x0a000002)
	binaryBigEndianPutUint16(pkt[20:22], 12345)
	binaryBigEndianPutUint16(pkt[22:24], 53)
	binaryBigEndianPutUint16(pkt[24:26], 8)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ParsePacket(pkt)
	}
}

func BenchmarkFlowTable_Lookup(b *testing.B) {
	f := Flow{
		SrcIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: 1},
		DstIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: 2},
		SrcPort: 12345,
		DstPort: 22,
		Proto:   ProtoTCP,
		IPv6:    false,
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			benchmarkFlowTable.Lookup(f, true, FlowStateNew)
		}
	})
}

func BenchmarkFlowTable_Lookup_Hot(b *testing.B) {
	f := Flow{
		SrcIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: 1},
		DstIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: 2},
		SrcPort: 12345,
		DstPort: 22,
		Proto:   ProtoTCP,
		IPv6:    false,
	}

	// Pre-populate
	benchmarkFlowTable.Lookup(f, true, FlowStateNew)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			benchmarkFlowTable.Lookup(f, false, FlowStateNew)
		}
	})
}

func BenchmarkPolicySwap_Decide(b *testing.B) {
	ps := &PolicySwap{}
	ps.Store(benchmarkPolicy)

	src := PeerKey{1: 1}
	dst := PeerKey{1: 2}
	proto := ProtoTCP
	port := uint16(22)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ps.Decide(src, dst, proto, port)
	}
}

// Helper functions for benchmark setup
func binaryBigEndianPutUint16(b []byte, v uint16) {
	b[0] = byte(v >> 8)
	b[1] = byte(v)
}

func binaryBigEndianPutUint32(b []byte, v uint32) {
	b[0] = byte(v >> 24)
	b[1] = byte(v >> 16)
	b[2] = byte(v >> 8)
	b[3] = byte(v)
}
