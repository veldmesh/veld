// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package nat

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
)

// buildXORMappedAddrValue builds the 8-byte XOR-MAPPED-ADDRESS attribute value
// for IPv4. port and ip are the original (un-XORed) values.
func buildXORMappedAddrValue(ip [4]byte, port uint16) []byte {
	val := make([]byte, 8)
	val[0] = 0x00 // reserved
	val[1] = 0x01 // family IPv4
	cookie := [4]byte{0x21, 0x12, 0xA4, 0x42}
	xorPort := port ^ uint16(stunMagicCookie>>16)
	binary.BigEndian.PutUint16(val[2:4], xorPort)
	for i := 0; i < 4; i++ {
		val[4+i] = ip[i] ^ cookie[i]
	}
	return val
}

// buildMappedAddrValue builds the 8-byte MAPPED-ADDRESS attribute value for IPv4.
func buildMappedAddrValue(ip [4]byte, port uint16) []byte {
	val := make([]byte, 8)
	val[0] = 0x00 // reserved
	val[1] = 0x01 // family IPv4
	binary.BigEndian.PutUint16(val[2:4], port)
	copy(val[4:8], ip[:])
	return val
}

// buildSTUNResponse builds a minimal STUN Binding Response with a single attribute.
// attrType is the 16-bit attribute type; attrValue is the raw value bytes.
// txID is the 12-byte transaction ID embedded in the header.
func buildSTUNResponse(txID [12]byte, attrType uint16, attrValue []byte) []byte {
	attrLen := len(attrValue)
	// Pad attribute value to 4-byte boundary
	padded := (attrLen + 3) &^ 3
	// Total message length = 4 (type+len header) + padded value
	msgLen := 4 + padded

	pkt := make([]byte, 20+msgLen)
	binary.BigEndian.PutUint16(pkt[0:2], 0x0101) // Binding Response
	binary.BigEndian.PutUint16(pkt[2:4], uint16(msgLen))
	binary.BigEndian.PutUint32(pkt[4:8], stunMagicCookie)
	copy(pkt[8:20], txID[:])

	// Attribute TLV
	binary.BigEndian.PutUint16(pkt[20:22], attrType)
	binary.BigEndian.PutUint16(pkt[22:24], uint16(attrLen))
	copy(pkt[24:24+attrLen], attrValue)
	return pkt
}

// -- parseXORMappedAddr tests --------------------------------------------------

func TestParseXORMappedAddr_OK(t *testing.T) {
	ip := [4]byte{1, 2, 3, 4}
	port := uint16(51820)
	val := buildXORMappedAddrValue(ip, port)

	got, err := parseXORMappedAddr(val)
	if err != nil {
		t.Fatalf("parseXORMappedAddr: %v", err)
	}
	want := netip.AddrPortFrom(netip.AddrFrom4(ip), port)
	if got != want {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseXORMappedAddr_TooShort(t *testing.T) {
	_, err := parseXORMappedAddr([]byte{0x00, 0x01, 0x00, 0x00})
	if err == nil {
		t.Error("expected error for too-short input")
	}
}

func TestParseXORMappedAddr_IPv6Family(t *testing.T) {
	// 8 bytes but family = 0x02 (IPv6)
	val := make([]byte, 8)
	val[1] = 0x02
	_, err := parseXORMappedAddr(val)
	if err == nil {
		t.Error("expected error for IPv6 family")
	}
}

// -- parseMappedAddr tests -----------------------------------------------------

func TestParseMappedAddr_OK(t *testing.T) {
	ip := [4]byte{10, 0, 0, 1}
	port := uint16(12345)
	val := buildMappedAddrValue(ip, port)

	got, err := parseMappedAddr(val)
	if err != nil {
		t.Fatalf("parseMappedAddr: %v", err)
	}
	want := netip.AddrPortFrom(netip.AddrFrom4(ip), port)
	if got != want {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseMappedAddr_TooShort(t *testing.T) {
	_, err := parseMappedAddr([]byte{0x00, 0x01, 0x00})
	if err == nil {
		t.Error("expected error for 3-byte input")
	}
}

// -- parseSTUNResponse tests ---------------------------------------------------

func TestParseSTUNResponse_XORMapped(t *testing.T) {
	var txID [12]byte
	copy(txID[:], []byte("txid12345678"))

	ip := [4]byte{1, 2, 3, 4}
	port := uint16(51820)
	attrVal := buildXORMappedAddrValue(ip, port)
	pkt := buildSTUNResponse(txID, 0x0020, attrVal)

	got, err := parseSTUNResponse(pkt, txID)
	if err != nil {
		t.Fatalf("parseSTUNResponse: %v", err)
	}
	want := netip.AddrPortFrom(netip.AddrFrom4(ip), port)
	if got != want {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseSTUNResponse_MappedAddrFallback(t *testing.T) {
	var txID [12]byte
	copy(txID[:], []byte("txid12345678"))

	ip := [4]byte{5, 6, 7, 8}
	port := uint16(9999)
	attrVal := buildMappedAddrValue(ip, port)
	pkt := buildSTUNResponse(txID, 0x0001, attrVal)

	got, err := parseSTUNResponse(pkt, txID)
	if err != nil {
		t.Fatalf("parseSTUNResponse fallback: %v", err)
	}
	want := netip.AddrPortFrom(netip.AddrFrom4(ip), port)
	if got != want {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseSTUNResponse_TooShort(t *testing.T) {
	_, err := parseSTUNResponse(make([]byte, 10), [12]byte{})
	if err == nil {
		t.Fatal("expected error for 10-byte packet")
	}
	if !strings.Contains(err.Error(), "too short") {
		t.Errorf("expected 'too short' in error, got %v", err)
	}
}

func TestParseSTUNResponse_WrongType(t *testing.T) {
	pkt := make([]byte, 20)
	binary.BigEndian.PutUint16(pkt[0:2], 0x0002) // not Binding Response
	binary.BigEndian.PutUint32(pkt[4:8], stunMagicCookie)

	_, err := parseSTUNResponse(pkt, [12]byte{})
	if err == nil {
		t.Fatal("expected error for wrong message type")
	}
	if !strings.Contains(err.Error(), "unexpected") {
		t.Errorf("expected 'unexpected' in error, got %v", err)
	}
}

func TestParseSTUNResponse_TxIDMismatch(t *testing.T) {
	var txID [12]byte
	copy(txID[:], []byte("txid12345678"))

	ip := [4]byte{1, 2, 3, 4}
	attrVal := buildXORMappedAddrValue(ip, 51820)
	pkt := buildSTUNResponse(txID, 0x0020, attrVal)

	var differentTxID [12]byte
	copy(differentTxID[:], []byte("differentxxxx"))

	_, err := parseSTUNResponse(pkt, differentTxID)
	if err == nil {
		t.Fatal("expected error for txID mismatch")
	}
	if !strings.Contains(err.Error(), "mismatch") {
		t.Errorf("expected 'mismatch' in error, got %v", err)
	}
}

func TestParseSTUNResponse_NoAttribute(t *testing.T) {
	var txID [12]byte
	copy(txID[:], []byte("txid12345678"))

	// Valid header with msgLen=0 and no attributes
	pkt := make([]byte, 20)
	binary.BigEndian.PutUint16(pkt[0:2], 0x0101) // Binding Response
	binary.BigEndian.PutUint16(pkt[2:4], 0)       // msgLen = 0
	binary.BigEndian.PutUint32(pkt[4:8], stunMagicCookie)
	copy(pkt[8:20], txID[:])

	_, err := parseSTUNResponse(pkt, txID)
	if err == nil {
		t.Fatal("expected error for missing mapped address")
	}
	if !strings.Contains(err.Error(), "no mapped address") {
		t.Errorf("expected 'no mapped address' in error, got %v", err)
	}
}
