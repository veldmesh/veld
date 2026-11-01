// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package acl

import (
	"encoding/binary"
	"errors"
)

// Flow represents a parsed network flow.
type Flow struct {
	SrcIP   [16]byte // IPv4 in last 4 bytes, IPv6 full 16 bytes
	DstIP   [16]byte
	SrcPort uint16
	DstPort uint16
	Proto   Proto
	IPv6    bool
}

// Kind represents the packet kind for ACL purposes.
type Kind int

const (
	KindStart    Kind = iota // connection start (SYN, first UDP, ICMP echo request)
	KindOther                // other packet (reply, data, etc.)
	KindFragment             // IPv4 fragment without transport header
	KindError                // ICMP error (unreachable, time exceeded, etc.)
)

// ParsePacket parses an IPv4 or IPv6 packet and returns the flow, kind, and any error.
// For IPv4, SrcIP/DstIP are stored in the last 4 bytes of the 16-byte array.
// For unparseable transport headers, returns an error (callers should drop under default deny).
func ParsePacket(pkt []byte) (Flow, Kind, error) {
	var flow Flow
	if len(pkt) < 20 {
		return flow, KindOther, errors.New("packet too short for IPv4 header")
	}

	version := pkt[0] >> 4
	switch version {
	case 4:
		return parseIPv4(pkt)
	case 6:
		return parseIPv6(pkt)
	}
	return flow, KindOther, errors.New("unknown IP version")
}

func parseIPv4(pkt []byte) (Flow, Kind, error) {
	var flow Flow
	flow.IPv6 = false

	if len(pkt) < 20 {
		return flow, KindOther, errors.New("IPv4 packet too short")
	}

	ihl := int(pkt[0] & 0x0F)
	if ihl < 5 {
		return flow, KindOther, errors.New("invalid IPv4 IHL")
	}
	headerLen := ihl * 4
	if len(pkt) < headerLen {
		return flow, KindOther, errors.New("IPv4 packet shorter than header")
	}

	// Total length
	totalLen := binary.BigEndian.Uint16(pkt[2:4])
	if int(totalLen) > len(pkt) {
		totalLen = uint16(len(pkt))
	}
	_ = totalLen

	// Fragment info
	flagsFrag := binary.BigEndian.Uint16(pkt[6:8])
	fragOffset := flagsFrag & 0x1FFF           // 13 bits
	moreFragments := (flagsFrag & 0x2000) != 0 // MF flag

	// Protocol
	proto := Proto(pkt[9])
	flow.Proto = proto

	// IP addresses (store in last 4 bytes of 16-byte array)
	copy(flow.SrcIP[12:16], pkt[12:16])
	copy(flow.DstIP[12:16], pkt[16:20])

	// Check if this is a fragment without transport header
	if fragOffset > 0 || moreFragments {
		if fragOffset > 0 {
			// Not first fragment - no transport header
			return flow, KindFragment, nil
		}
		// First fragment (offset=0) with MF flag - may have transport header
		// Continue to parse transport, but if not enough data, treat as fragment
	}

	// Parse transport header
	if len(pkt) < headerLen+4 {
		// Not enough for minimal transport header - treat as fragment if MF was set
		if moreFragments {
			return flow, KindFragment, nil
		}
		return flow, KindOther, nil
	}

	transport := pkt[headerLen:]
	return parseTransport(flow, proto, transport)
}

func parseIPv6(pkt []byte) (Flow, Kind, error) {
	var flow Flow
	flow.IPv6 = true

	if len(pkt) < 40 {
		return flow, KindOther, errors.New("IPv6 packet too short")
	}

	// Payload length
	payloadLen := binary.BigEndian.Uint16(pkt[4:6])
	nextHeader := Proto(pkt[6])
	_ = pkt[7] // hopLimit, unused

	// IP addresses (16 bytes each)
	copy(flow.SrcIP[:], pkt[8:24])
	copy(flow.DstIP[:], pkt[24:40])

	// Walk extension headers
	offset := 40
	remaining := int(payloadLen)
	proto := nextHeader

	for {
		if remaining < 0 {
			return flow, KindOther, errors.New("IPv6 payload length exceeded")
		}

		switch proto {
		case ProtoTCP, ProtoUDP, ProtoICMP, ProtoICMPv6:
			// Found transport header
			flow.Proto = proto
			if offset >= len(pkt) {
				return flow, KindOther, errors.New("IPv6 packet ends before transport header")
			}
			transport := pkt[offset:]
			return parseTransport(flow, proto, transport)

		case 0: // Hop-by-Hop Options
			if offset+2 > len(pkt) {
				return flow, KindOther, errors.New("IPv6 Hop-by-Hop header truncated")
			}
			nextHeader = Proto(pkt[offset])
			extLen := int(pkt[offset+1]) // in 8-byte units, not including first 8 bytes
			headerSize := 8 + extLen*8
			if offset+headerSize > len(pkt) {
				return flow, KindOther, errors.New("IPv6 Hop-by-Hop header exceeds packet")
			}
			offset += headerSize
			remaining -= headerSize
			proto = nextHeader

		case 43: // Routing
			if offset+2 > len(pkt) {
				return flow, KindOther, errors.New("IPv6 Routing header truncated")
			}
			nextHeader = Proto(pkt[offset])
			extLen := int(pkt[offset+1])
			headerSize := 8 + extLen*8
			if offset+headerSize > len(pkt) {
				return flow, KindOther, errors.New("IPv6 Routing header exceeds packet")
			}
			offset += headerSize
			remaining -= headerSize
			proto = nextHeader

		case 44: // Fragment
			if offset+8 > len(pkt) {
				return flow, KindOther, errors.New("IPv6 Fragment header truncated")
			}
			nextHeader = Proto(pkt[offset])
			// Reserved byte at offset+1
			fragOffset := binary.BigEndian.Uint16(pkt[offset+2 : offset+4])
			_ = (fragOffset & 0x1) != 0  // moreFragments, unused
			fragOffset = fragOffset >> 3 // in 8-byte units
			// Identification at offset+4 to offset+7 (4 bytes)

			if fragOffset > 0 {
				// Not first fragment - no transport header accessible
				flow.Proto = nextHeader
				return flow, KindFragment, nil
			}
			// First fragment - continue to next header
			offset += 8
			remaining -= 8
			proto = nextHeader

		case 51: // AH (Authentication Header)
			if offset+2 > len(pkt) {
				return flow, KindOther, errors.New("IPv6 AH header truncated")
			}
			nextHeader = Proto(pkt[offset])
			// AH length is in 4-byte units, not including first 8 bytes
			extLen := int(pkt[offset+1])
			headerSize := 8 + extLen*4
			if offset+headerSize > len(pkt) {
				return flow, KindOther, errors.New("IPv6 AH header exceeds packet")
			}
			offset += headerSize
			remaining -= headerSize
			proto = nextHeader

		case 50: // ESP (Encapsulating Security Payload)
			// ESP is encrypted, can't parse further
			return flow, KindOther, errors.New("IPv6 ESP header - cannot parse encrypted payload")

		case 60: // Destination Options
			if offset+2 > len(pkt) {
				return flow, KindOther, errors.New("IPv6 Destination Options header truncated")
			}
			nextHeader = Proto(pkt[offset])
			extLen := int(pkt[offset+1])
			headerSize := 8 + extLen*8
			if offset+headerSize > len(pkt) {
				return flow, KindOther, errors.New("IPv6 Destination Options header exceeds packet")
			}
			offset += headerSize
			remaining -= headerSize
			proto = nextHeader

		default:
			return flow, KindOther, errors.New("unknown IPv6 extension header")
		}
	}
}

func parseTransport(flow Flow, proto Proto, transport []byte) (Flow, Kind, error) {
	switch proto {
	case ProtoTCP:
		return parseTCP(flow, transport)
	case ProtoUDP:
		return parseUDP(flow, transport)
	case ProtoICMP:
		return parseICMP(flow, transport)
	case ProtoICMPv6:
		return parseICMPv6(flow, transport)
	default:
		return flow, KindOther, errors.New("unknown transport protocol")
	}
}

func parseTCP(flow Flow, tcp []byte) (Flow, Kind, error) {
	if len(tcp) < 20 {
		return flow, KindOther, errors.New("TCP header too short")
	}

	flow.SrcPort = binary.BigEndian.Uint16(tcp[0:2])
	flow.DstPort = binary.BigEndian.Uint16(tcp[2:4])

	// Data offset (top 4 bits of byte 12)
	dataOffset := int(tcp[12] >> 4)
	if dataOffset < 5 {
		return flow, KindOther, errors.New("invalid TCP data offset")
	}
	headerLen := dataOffset * 4
	if len(tcp) < headerLen {
		return flow, KindOther, errors.New("TCP packet shorter than header")
	}

	// Flags (byte 13)
	flags := tcp[13]
	syn := (flags & 0x02) != 0
	ack := (flags & 0x10) != 0

	// Connection start: SYN without ACK
	if syn && !ack {
		return flow, KindStart, nil
	}
	return flow, KindOther, nil
}

func parseUDP(flow Flow, udp []byte) (Flow, Kind, error) {
	if len(udp) < 8 {
		return flow, KindOther, errors.New("UDP header too short")
	}

	flow.SrcPort = binary.BigEndian.Uint16(udp[0:2])
	flow.DstPort = binary.BigEndian.Uint16(udp[2:4])
	// Length = binary.BigEndian.Uint16(udp[4:6])
	// Checksum = binary.BigEndian.Uint16(udp[6:8])

	// First UDP packet of a flow is considered a start
	// (We can't determine if it's "first" without flow table, so treat all UDP as start)
	return flow, KindStart, nil
}

func parseICMP(flow Flow, icmp []byte) (Flow, Kind, error) {
	if len(icmp) < 4 {
		return flow, KindOther, errors.New("ICMP header too short")
	}

	msgType := icmp[0]
	code := icmp[1]
	// Checksum = binary.BigEndian.Uint16(icmp[2:4])

	// Connection start: Echo Request (type 8, code 0)
	if msgType == 8 && code == 0 {
		return flow, KindStart, nil
	}

	// ICMP errors that quote original packet
	if isICMPError(msgType, code) {
		return parseICMPError(flow, icmp)
	}

	return flow, KindOther, nil
}

func parseICMPv6(flow Flow, icmp []byte) (Flow, Kind, error) {
	if len(icmp) < 4 {
		return flow, KindOther, errors.New("ICMPv6 header too short")
	}

	msgType := icmp[0]
	code := icmp[1]
	// Checksum = binary.BigEndian.Uint16(icmp[2:4])

	// Connection start: Echo Request (type 128, code 0)
	if msgType == 128 && code == 0 {
		return flow, KindStart, nil
	}

	// ICMPv6 errors that quote original packet
	if isICMPv6Error(msgType, code) {
		return parseICMPError(flow, icmp)
	}

	return flow, KindOther, nil
}

func isICMPError(msgType, code uint8) bool {
	// Destination Unreachable (3), Source Quench (4 - deprecated), Redirect (5),
	// Time Exceeded (11), Parameter Problem (12)
	switch msgType {
	case 3, 4, 5, 11, 12:
		return true
	}
	return false
}

func isICMPv6Error(msgType, code uint8) bool {
	// Destination Unreachable (1), Packet Too Big (2), Time Exceeded (3), Parameter Problem (4)
	switch msgType {
	case 1, 2, 3, 4:
		return true
	}
	return false
}

func parseICMPError(flow Flow, icmp []byte) (Flow, Kind, error) {
	// ICMP error messages contain the original IP header + 8 bytes of transport header
	// Starting at byte 8 (after type, code, checksum, unused)
	if len(icmp) < 8+20 {
		return flow, KindError, nil // Not enough to parse quoted packet
	}

	quoted := icmp[8:]
	if len(quoted) < 20 {
		return flow, KindError, nil
	}

	// Parse quoted IP header
	version := quoted[0] >> 4
	switch version {
	case 4:
		return parseICMPErrorIPv4(flow, quoted)
	case 6:
		return parseICMPErrorIPv6(flow, quoted)
	}
	return flow, KindError, nil
}

func parseICMPErrorIPv4(flow Flow, quoted []byte) (Flow, Kind, error) {
	if len(quoted) < 20 {
		return flow, KindError, nil
	}

	ihl := int(quoted[0] & 0x0F)
	if ihl < 5 {
		return flow, KindError, nil
	}
	headerLen := ihl * 4
	if len(quoted) < headerLen+4 {
		return flow, KindError, nil
	}

	proto := Proto(quoted[9])
	flow.Proto = proto
	flow.IPv6 = false

	copy(flow.SrcIP[12:16], quoted[12:16])
	copy(flow.DstIP[12:16], quoted[16:20])

	// Parse quoted transport header (first 8 bytes)
	transport := quoted[headerLen:]
	if len(transport) < 4 {
		return flow, KindError, nil
	}

	switch proto {
	case ProtoTCP, ProtoUDP:
		flow.SrcPort = binary.BigEndian.Uint16(transport[0:2])
		flow.DstPort = binary.BigEndian.Uint16(transport[2:4])
	case ProtoICMP, ProtoICMPv6:
		// ICMP quoted in ICMP error - type/code in first 2 bytes
		// Ports not applicable
	}

	return flow, KindError, nil
}

func parseICMPErrorIPv6(flow Flow, quoted []byte) (Flow, Kind, error) {
	if len(quoted) < 40 {
		return flow, KindError, nil
	}

	nextHeader := Proto(quoted[6])
	flow.Proto = nextHeader
	flow.IPv6 = true

	copy(flow.SrcIP[:], quoted[8:24])
	copy(flow.DstIP[:], quoted[24:40])

	// For simplicity, we don't walk extension headers in quoted packet
	// Just try to parse transport at fixed offset 40
	if len(quoted) < 40+4 {
		return flow, KindError, nil
	}

	transport := quoted[40:]
	switch nextHeader {
	case ProtoTCP, ProtoUDP:
		if len(transport) >= 4 {
			flow.SrcPort = binary.BigEndian.Uint16(transport[0:2])
			flow.DstPort = binary.BigEndian.Uint16(transport[2:4])
		}
	}

	return flow, KindError, nil
}
