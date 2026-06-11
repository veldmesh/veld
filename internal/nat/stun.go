// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package nat

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"time"
)

const stunMagicCookie uint32 = 0x2112A442

// QuerySTUN sends an RFC 5389 STUN Binding Request to stunAddr using a
// temporary UDP socket and returns the server-reflexive (public) IPv4 address.
//
// A temporary socket (not the data-plane conn) is used to avoid interfering
// with packet demultiplexing. The returned IP reflects the external IP visible
// to the STUN server; the port reflects the temporary socket's external port.
// Callers should combine the returned IP with their known local data-plane port
// to build a server-reflexive candidate for cone NATs.
func QuerySTUN(ctx context.Context, stunAddr string) (netip.AddrPort, error) {
	udpAddr, err := net.ResolveUDPAddr("udp4", stunAddr)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("resolve stun: %w", err)
	}

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("listen for stun: %w", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	conn.SetDeadline(deadline)

	// Build STUN Binding Request (20-byte header, no attributes)
	var req [20]byte
	binary.BigEndian.PutUint16(req[0:2], 0x0001) // Binding Request
	binary.BigEndian.PutUint16(req[2:4], 0)       // Message Length: 0
	binary.BigEndian.PutUint32(req[4:8], stunMagicCookie)
	var txID [12]byte
	rand.Read(txID[:])
	copy(req[8:20], txID[:])

	if _, err := conn.WriteToUDP(req[:], udpAddr); err != nil {
		return netip.AddrPort{}, fmt.Errorf("send stun request: %w", err)
	}

	buf := make([]byte, 512)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("read stun response: %w", err)
	}

	return parseSTUNResponse(buf[:n], txID)
}

func parseSTUNResponse(data []byte, txID [12]byte) (netip.AddrPort, error) {
	if len(data) < 20 {
		return netip.AddrPort{}, fmt.Errorf("stun response too short: %d bytes", len(data))
	}

	msgType := binary.BigEndian.Uint16(data[0:2])
	if msgType != 0x0101 {
		return netip.AddrPort{}, fmt.Errorf("unexpected stun message type: %04x", msgType)
	}
	if [12]byte(data[8:20]) != txID {
		return netip.AddrPort{}, fmt.Errorf("stun transaction ID mismatch")
	}

	msgLen := int(binary.BigEndian.Uint16(data[2:4]))
	attrs := data[20:]
	if msgLen > len(attrs) {
		attrs = attrs[:] // use what we got
	} else {
		attrs = attrs[:msgLen]
	}

	for len(attrs) >= 4 {
		attrType := binary.BigEndian.Uint16(attrs[0:2])
		attrLen := int(binary.BigEndian.Uint16(attrs[2:4]))
		if 4+attrLen > len(attrs) {
			break
		}
		value := attrs[4 : 4+attrLen]

		switch attrType {
		case 0x0020: // XOR-MAPPED-ADDRESS (preferred)
			return parseXORMappedAddr(value)
		case 0x0001: // MAPPED-ADDRESS (fallback)
			return parseMappedAddr(value)
		}
		// Align to 4-byte boundary
		padded := (attrLen + 3) &^ 3
		attrs = attrs[4+padded:]
	}

	return netip.AddrPort{}, fmt.Errorf("no mapped address attribute in stun response")
}

func parseXORMappedAddr(data []byte) (netip.AddrPort, error) {
	if len(data) < 8 || data[1] != 0x01 { // only IPv4
		return netip.AddrPort{}, fmt.Errorf("xor-mapped-address: need ≥8 bytes and IPv4 family")
	}
	port := binary.BigEndian.Uint16(data[2:4]) ^ uint16(stunMagicCookie>>16)
	cookie := [4]byte{0x21, 0x12, 0xA4, 0x42}
	var ip [4]byte
	for i := range ip {
		ip[i] = data[4+i] ^ cookie[i]
	}
	return netip.AddrPortFrom(netip.AddrFrom4(ip), port), nil
}

func parseMappedAddr(data []byte) (netip.AddrPort, error) {
	if len(data) < 8 || data[1] != 0x01 {
		return netip.AddrPort{}, fmt.Errorf("mapped-address: need ≥8 bytes and IPv4 family")
	}
	port := binary.BigEndian.Uint16(data[2:4])
	var ip [4]byte
	copy(ip[:], data[4:8])
	return netip.AddrPortFrom(netip.AddrFrom4(ip), port), nil
}
