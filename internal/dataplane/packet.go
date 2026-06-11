// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package dataplane

import "encoding/binary"

// Wire format for UDP packets:
//   [4B] packet_type
//   [4B] sender_index (reserved, 0 for now)
//   [8B] nonce
//   [NB] ChaCha20-Poly1305 ciphertext + 16B auth tag
const HeaderSize = 16

const (
	TypeData          uint32 = 0x01
	TypeHandshakeInit uint32 = 0x02
	TypeHandshakeResp uint32 = 0x03
	TypeKeepalive     uint32 = 0x04
	TypeNATProbe      uint32 = 0x05 // NAT hole-punch probe/reply
)

// buildDataPacket assembles a wire-format UDP payload from a nonce and ciphertext.
func buildDataPacket(nonce uint64, ct []byte) []byte {
	buf := make([]byte, HeaderSize+len(ct))
	binary.BigEndian.PutUint32(buf[0:4], TypeData)
	binary.BigEndian.PutUint32(buf[4:8], 0) // sender_index: reserved
	binary.BigEndian.PutUint64(buf[8:16], nonce)
	copy(buf[HeaderSize:], ct)
	return buf
}

// parseHeader decodes the 16-byte header. Caller must ensure len(hdr) >= HeaderSize.
func parseHeader(hdr []byte) (pktType, senderIdx uint32, nonce uint64) {
	pktType = binary.BigEndian.Uint32(hdr[0:4])
	senderIdx = binary.BigEndian.Uint32(hdr[4:8])
	nonce = binary.BigEndian.Uint64(hdr[8:16])
	return
}
