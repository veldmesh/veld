// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package acl

import (
	"encoding/binary"
	"testing"
)

func TestParsePacket_IPv4TCP_SYN(t *testing.T) {
	// IPv4 header (20 bytes) + TCP header (20 bytes) with SYN flag
	// Version=4, IHL=5, TOS=0, TotalLen=40, ID=0, Flags=0, FragOffset=0, TTL=64, Proto=TCP, Checksum=0
	// SrcIP=10.0.0.1, DstIP=10.0.0.2
	// SrcPort=12345, DstPort=22, Seq=0, Ack=0, Flags=SYN (0x02)
	pkt := make([]byte, 40)
	// IPv4 header
	pkt[0] = 0x45                            // version=4, IHL=5
	pkt[1] = 0x00                            // TOS
	binary.BigEndian.PutUint16(pkt[2:4], 40) // Total Length
	binary.BigEndian.PutUint16(pkt[4:6], 0)  // ID
	binary.BigEndian.PutUint16(pkt[6:8], 0)  // Flags + FragOffset
	pkt[8] = 64                              // TTL
	pkt[9] = 6                               // Protocol = TCP
	// Checksum (skip, set to 0)
	binary.BigEndian.PutUint32(pkt[12:16], 0x0a000001) // SrcIP = 10.0.0.1
	binary.BigEndian.PutUint32(pkt[16:20], 0x0a000002) // DstIP = 10.0.0.2
	// TCP header
	binary.BigEndian.PutUint16(pkt[20:22], 12345) // SrcPort
	binary.BigEndian.PutUint16(pkt[22:24], 22)    // DstPort
	binary.BigEndian.PutUint32(pkt[24:28], 0)     // Seq
	binary.BigEndian.PutUint32(pkt[28:32], 0)     // Ack
	pkt[32] = 0x50                                // Data offset=5, reserved=0
	pkt[33] = 0x02                                // Flags = SYN
	// Window, Checksum, Urgent (zeros)

	flow, kind, err := ParsePacket(pkt)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}
	if kind != KindStart {
		t.Errorf("kind: got %v, want %v", kind, KindStart)
	}
	if flow.Proto != ProtoTCP {
		t.Errorf("proto: got %v, want %v", flow.Proto, ProtoTCP)
	}
	if flow.SrcPort != 12345 || flow.DstPort != 22 {
		t.Errorf("ports: got %d/%d, want 12345/22", flow.SrcPort, flow.DstPort)
	}
	if flow.IPv6 {
		t.Error("IPv6 should be false")
	}
}

func TestParsePacket_IPv4TCP_SYNACK(t *testing.T) {
	// Same as above but SYN+ACK (not a connection start)
	pkt := make([]byte, 40)
	pkt[0] = 0x45
	pkt[1] = 0x00
	binary.BigEndian.PutUint16(pkt[2:4], 40)
	binary.BigEndian.PutUint16(pkt[4:6], 0)
	binary.BigEndian.PutUint16(pkt[6:8], 0)
	pkt[8] = 64
	pkt[9] = 6
	binary.BigEndian.PutUint32(pkt[12:16], 0x0a000002) // SrcIP = 10.0.0.2
	binary.BigEndian.PutUint32(pkt[16:20], 0x0a000001) // DstIP = 10.0.0.1
	binary.BigEndian.PutUint16(pkt[20:22], 22)         // SrcPort
	binary.BigEndian.PutUint16(pkt[22:24], 12345)      // DstPort
	binary.BigEndian.PutUint32(pkt[24:28], 0)
	binary.BigEndian.PutUint32(pkt[28:32], 1)
	pkt[32] = 0x50
	pkt[33] = 0x12 // Flags = SYN|ACK

	_, kind, err := ParsePacket(pkt)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}
	if kind != KindOther {
		t.Errorf("kind: got %v, want %v (SYN+ACK is not start)", kind, KindOther)
	}
}

func TestParsePacket_IPv4UDP(t *testing.T) {
	// IPv4 + UDP
	pkt := make([]byte, 28)
	pkt[0] = 0x45
	pkt[1] = 0x00
	binary.BigEndian.PutUint16(pkt[2:4], 28)
	binary.BigEndian.PutUint16(pkt[4:6], 0)
	binary.BigEndian.PutUint16(pkt[6:8], 0)
	pkt[8] = 64
	pkt[9] = 17 // UDP
	binary.BigEndian.PutUint32(pkt[12:16], 0x0a000001)
	binary.BigEndian.PutUint32(pkt[16:20], 0x0a000002)
	// UDP header
	binary.BigEndian.PutUint16(pkt[20:22], 12345) // SrcPort
	binary.BigEndian.PutUint16(pkt[22:24], 53)    // DstPort
	binary.BigEndian.PutUint16(pkt[24:26], 8)     // Length
	// Checksum (0)

	flow, kind, err := ParsePacket(pkt)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}
	if kind != KindStart {
		t.Errorf("kind: got %v, want %v (first UDP is start)", kind, KindStart)
	}
	if flow.Proto != ProtoUDP {
		t.Errorf("proto: got %v, want %v", flow.Proto, ProtoUDP)
	}
	if flow.SrcPort != 12345 || flow.DstPort != 53 {
		t.Errorf("ports: got %d/%d", flow.SrcPort, flow.DstPort)
	}
}

func TestParsePacket_IPv4ICMPEchoRequest(t *testing.T) {
	// IPv4 + ICMP Echo Request (type=8, code=0)
	pkt := make([]byte, 28)
	pkt[0] = 0x45
	pkt[1] = 0x00
	binary.BigEndian.PutUint16(pkt[2:4], 28)
	binary.BigEndian.PutUint16(pkt[4:6], 0)
	binary.BigEndian.PutUint16(pkt[6:8], 0)
	pkt[8] = 64
	pkt[9] = 1 // ICMP
	binary.BigEndian.PutUint32(pkt[12:16], 0x0a000001)
	binary.BigEndian.PutUint32(pkt[16:20], 0x0a000002)
	// ICMP header
	pkt[20] = 8 // Type = Echo Request
	pkt[21] = 0 // Code = 0
	// Checksum, ID, Sequence (zeros)

	flow, kind, err := ParsePacket(pkt)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}
	if kind != KindStart {
		t.Errorf("kind: got %v, want %v (echo request is start)", kind, KindStart)
	}
	if flow.Proto != ProtoICMP {
		t.Errorf("proto: got %v, want %v", flow.Proto, ProtoICMP)
	}
}

func TestParsePacket_IPv4ICMPEchoReply(t *testing.T) {
	// IPv4 + ICMP Echo Reply (type=0, code=0) - not a start
	pkt := make([]byte, 28)
	pkt[0] = 0x45
	pkt[1] = 0x00
	binary.BigEndian.PutUint16(pkt[2:4], 28)
	binary.BigEndian.PutUint16(pkt[4:6], 0)
	binary.BigEndian.PutUint16(pkt[6:8], 0)
	pkt[8] = 64
	pkt[9] = 1
	binary.BigEndian.PutUint32(pkt[12:16], 0x0a000002)
	binary.BigEndian.PutUint32(pkt[16:20], 0x0a000001)
	pkt[20] = 0 // Type = Echo Reply
	pkt[21] = 0

	_, kind, err := ParsePacket(pkt)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}
	if kind != KindOther {
		t.Errorf("kind: got %v, want %v (echo reply is not start)", kind, KindOther)
	}
}

func TestParsePacket_IPv4Fragment_NoTransport(t *testing.T) {
	// IPv4 fragment with MF flag set, offset > 0 (no transport header)
	pkt := make([]byte, 20)
	pkt[0] = 0x45
	pkt[1] = 0x00
	binary.BigEndian.PutUint16(pkt[2:4], 20)
	binary.BigEndian.PutUint16(pkt[4:6], 1)
	binary.BigEndian.PutUint16(pkt[6:8], 0x2000) // MF flag (0x2000) + offset
	pkt[8] = 64
	pkt[9] = 6 // TCP
	binary.BigEndian.PutUint32(pkt[12:16], 0x0a000001)
	binary.BigEndian.PutUint32(pkt[16:20], 0x0a000002)

	flow, kind, err := ParsePacket(pkt)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}
	if kind != KindFragment {
		t.Errorf("kind: got %v, want %v", kind, KindFragment)
	}
	if flow.Proto != ProtoTCP {
		t.Errorf("proto: got %v, want %v", flow.Proto, ProtoTCP)
	}
	if flow.SrcPort != 0 || flow.DstPort != 0 {
		t.Errorf("ports should be 0 for fragment: got %d/%d", flow.SrcPort, flow.DstPort)
	}
}

func TestParsePacket_IPv4FirstFragment_WithTransport(t *testing.T) {
	// IPv4 first fragment (offset=0, MF=1) with TCP header
	pkt := make([]byte, 40)
	pkt[0] = 0x45
	pkt[1] = 0x00
	binary.BigEndian.PutUint16(pkt[2:4], 40)
	binary.BigEndian.PutUint16(pkt[4:6], 1)
	binary.BigEndian.PutUint16(pkt[6:8], 0x2000) // MF=1, offset=0
	pkt[8] = 64
	pkt[9] = 6
	binary.BigEndian.PutUint32(pkt[12:16], 0x0a000001)
	binary.BigEndian.PutUint32(pkt[16:20], 0x0a000002)
	// TCP header
	binary.BigEndian.PutUint16(pkt[20:22], 12345)
	binary.BigEndian.PutUint16(pkt[22:24], 22)
	pkt[32] = 0x50 // Data offset=5, reserved=0
	pkt[33] = 0x02 // SYN

	flow, kind, err := ParsePacket(pkt)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}
	if kind != KindStart {
		t.Errorf("kind: got %v, want %v", kind, KindStart)
	}
	if flow.SrcPort != 12345 || flow.DstPort != 22 {
		t.Errorf("ports: got %d/%d", flow.SrcPort, flow.DstPort)
	}
}

func TestParsePacket_IPv6TCP_SYN(t *testing.T) {
	// IPv6 header (40 bytes) + TCP header (20 bytes) with SYN
	// Version=6, TC=0, Flow=0, PayloadLen=20, NextHeader=TCP, HopLimit=64
	// SrcIP=2001:db8::1, DstIP=2001:db8::2
	pkt := make([]byte, 60)
	// IPv6 header
	pkt[0] = 0x60 // Version=6, TC=0
	pkt[1] = 0x00
	pkt[2] = 0x00
	pkt[3] = 0x00                            // Flow label
	binary.BigEndian.PutUint16(pkt[4:6], 20) // Payload Length
	pkt[6] = 6                               // Next Header = TCP
	pkt[7] = 64                              // Hop Limit
	// SrcIP = 2001:db8::1
	copy(pkt[8:24], []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01})
	// DstIP = 2001:db8::2
	copy(pkt[24:40], []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02})
	// TCP header
	binary.BigEndian.PutUint16(pkt[40:42], 12345)
	binary.BigEndian.PutUint16(pkt[42:44], 22)
	binary.BigEndian.PutUint32(pkt[44:48], 0)
	binary.BigEndian.PutUint32(pkt[48:52], 0)
	pkt[52] = 0x50
	pkt[53] = 0x02 // SYN

	flow, kind, err := ParsePacket(pkt)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}
	if kind != KindStart {
		t.Errorf("kind: got %v, want %v", kind, KindStart)
	}
	if !flow.IPv6 {
		t.Error("IPv6 should be true")
	}
	if flow.Proto != ProtoTCP {
		t.Errorf("proto: got %v, want %v", flow.Proto, ProtoTCP)
	}
}

func TestParsePacket_IPv6WithExtensionHeaders(t *testing.T) {
	// IPv6 with Hop-by-Hop extension header, then TCP
	// IPv6 header: NextHeader=0 (Hop-by-Hop)
	// Hop-by-Hop header: NextHeader=6 (TCP), Length=0 (8 bytes)
	pkt := make([]byte, 68)
	// IPv6 header
	pkt[0] = 0x60
	pkt[1] = 0x00
	pkt[2] = 0x00
	pkt[3] = 0x00
	binary.BigEndian.PutUint16(pkt[4:6], 28) // Payload Length = 8 (hop-by-hop) + 20 (TCP)
	pkt[6] = 0                               // Next Header = Hop-by-Hop (0)
	pkt[7] = 64
	copy(pkt[8:24], []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01})
	copy(pkt[24:40], []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02})
	// Hop-by-Hop extension header
	pkt[40] = 6 // Next Header = TCP
	pkt[41] = 0 // Length = 0 (8 bytes total)
	// Options (2 bytes padding)
	pkt[42] = 0x00
	pkt[43] = 0x00
	pkt[44] = 0x00
	pkt[45] = 0x00
	pkt[46] = 0x00
	pkt[47] = 0x00
	// TCP header
	binary.BigEndian.PutUint16(pkt[48:50], 12345)
	binary.BigEndian.PutUint16(pkt[50:52], 22)
	binary.BigEndian.PutUint32(pkt[52:56], 0)
	binary.BigEndian.PutUint32(pkt[56:60], 0)
	pkt[60] = 0x50
	pkt[61] = 0x02 // SYN

	flow, kind, err := ParsePacket(pkt)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}
	if kind != KindStart {
		t.Errorf("kind: got %v, want %v", kind, KindStart)
	}
	if !flow.IPv6 {
		t.Error("IPv6 should be true")
	}
	if flow.Proto != ProtoTCP {
		t.Errorf("proto: got %v, want %v", flow.Proto, ProtoTCP)
	}
}

func TestParsePacket_IPv6ICMPv6EchoRequest(t *testing.T) {
	// IPv6 + ICMPv6 Echo Request (type=128)
	pkt := make([]byte, 48)
	pkt[0] = 0x60
	pkt[1] = 0x00
	pkt[2] = 0x00
	pkt[3] = 0x00
	binary.BigEndian.PutUint16(pkt[4:6], 8) // Payload Length
	pkt[6] = 58                             // Next Header = ICMPv6
	pkt[7] = 64
	copy(pkt[8:24], []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01})
	copy(pkt[24:40], []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02})
	// ICMPv6 Echo Request
	pkt[40] = 128 // Type = Echo Request
	pkt[41] = 0   // Code = 0
	// Checksum, ID, Seq (zeros)

	flow, kind, err := ParsePacket(pkt)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}
	if kind != KindStart {
		t.Errorf("kind: got %v, want %v", kind, KindStart)
	}
	if flow.Proto != ProtoICMPv6 {
		t.Errorf("proto: got %v, want %v", flow.Proto, ProtoICMPv6)
	}
}

func TestParsePacket_IPv6Fragment(t *testing.T) {
	// IPv6 with Fragment extension header, then TCP (but fragment offset > 0)
	pkt := make([]byte, 68)
	pkt[0] = 0x60
	pkt[1] = 0x00
	pkt[2] = 0x00
	pkt[3] = 0x00
	binary.BigEndian.PutUint16(pkt[4:6], 28)
	pkt[6] = 44 // Next Header = Fragment (44)
	pkt[7] = 64
	copy(pkt[8:24], []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01})
	copy(pkt[24:40], []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02})
	// Fragment header
	pkt[40] = 6                                    // Next Header = TCP
	pkt[41] = 0                                    // Reserved
	binary.BigEndian.PutUint16(pkt[42:44], 0x2000) // Fragment offset=1, M=1 (in units of 8 bytes)
	pkt[44] = 0x00
	pkt[45] = 0x01 // Identification
	pkt[46] = 0x00
	pkt[47] = 0x00
	// No transport header (offset > 0)

	flow, kind, err := ParsePacket(pkt)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}
	if kind != KindFragment {
		t.Errorf("kind: got %v, want %v", kind, KindFragment)
	}
	if flow.Proto != ProtoTCP {
		t.Errorf("proto: got %v, want %v", flow.Proto, ProtoTCP)
	}
}

func TestParsePacket_TooShort(t *testing.T) {
	pkt := []byte{0x45} // Too short for IPv4 header
	_, _, err := ParsePacket(pkt)
	if err == nil {
		t.Fatal("expected error for too short packet")
	}
}

func TestParsePacket_UnknownProtocol(t *testing.T) {
	// IPv4 with unknown protocol - should return KindOther (no error, caller drops under default deny)
	pkt := make([]byte, 20)
	pkt[0] = 0x45
	pkt[1] = 0x00
	binary.BigEndian.PutUint16(pkt[2:4], 20)
	binary.BigEndian.PutUint16(pkt[4:6], 0)
	binary.BigEndian.PutUint16(pkt[6:8], 0)
	pkt[8] = 64
	pkt[9] = 99 // Unknown protocol
	binary.BigEndian.PutUint32(pkt[12:16], 0x0a000001)
	binary.BigEndian.PutUint32(pkt[16:20], 0x0a000002)

	_, kind, err := ParsePacket(pkt)
	if err != nil {
		t.Fatalf("ParsePacket: unexpected error: %v", err)
	}
	if kind != KindOther {
		t.Errorf("kind: got %v, want %v", kind, KindOther)
	}
}

func TestParsePacket_IPv6UnknownExtensionHeader(t *testing.T) {
	// IPv6 with unknown extension header type
	pkt := make([]byte, 48)
	pkt[0] = 0x60
	pkt[1] = 0x00
	pkt[2] = 0x00
	pkt[3] = 0x00
	binary.BigEndian.PutUint16(pkt[4:6], 8)
	pkt[6] = 99 // Unknown extension header
	pkt[7] = 64
	copy(pkt[8:24], []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01})
	copy(pkt[24:40], []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02})

	_, _, err := ParsePacket(pkt)
	if err == nil {
		t.Fatal("expected error for unknown extension header")
	}
}
