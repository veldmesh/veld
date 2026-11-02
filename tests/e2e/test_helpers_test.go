// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package e2e_test

import (
	"encoding/binary"
	"net/netip"

	"github.com/veldmesh/veld/internal/crypto"
	"github.com/veldmesh/veld/internal/peer"
	"github.com/veldmesh/veld/internal/tun"
)

func makeEntry(id *crypto.Identity, name, vpn string, ep netip.AddrPort) *peer.Entry {
	var peerID [32]byte
	copy(peerID[:], id.Ed25519Public)
	e := &peer.Entry{
		ID:        peerID,
		X25519Pub: id.X25519Public,
		VPNAddr:   netip.MustParseAddr(vpn),
		Name:      name,
	}
	if ep.IsValid() {
		e.SetEndpoint(ep)
	}
	return e
}

// makeUDPv4Packet builds an IPv4 packet with a UDP header.
func makeUDPv4Packet(src, dst [4]byte, srcPort, dstPort uint16, payload []byte) []byte {
	udpLen := 8 + len(payload)
	total := 20 + udpLen
	pkt := make([]byte, total)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(total))
	pkt[4] = 0x00
	pkt[5] = 0x00
	pkt[6] = 0x00
	pkt[7] = 0x00
	pkt[8] = 64
	pkt[9] = 17
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])
	binary.BigEndian.PutUint16(pkt[20:22], srcPort)
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)
	binary.BigEndian.PutUint16(pkt[24:26], uint16(udpLen))
	copy(pkt[28:], payload)
	return pkt
}

// drainMemTUN drains any packets from the MemTUN's delivery channel.
func drainMemTUN(t *tun.MemTUN) {
	t.Drain()
}
