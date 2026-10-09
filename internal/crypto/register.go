// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package crypto

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
)

// RegisterSignatureDomain is the domain-separation prefix of the message a
// daemon signs to prove possession of its Ed25519 private key when
// registering with the coord server: "veld-coord-register-v1" followed by a
// NUL byte. It ensures a Register signature is never a valid signature for
// any other protocol message, even one signed by the same key.
const RegisterSignatureDomain = "veld-coord-register-v1\x00"

// RegisterTimestampWindow bounds the client clock carried in a Register
// signature: |now - timestamp_unix| must not exceed this many seconds, so a
// captured Register cannot be replayed later.
const RegisterTimestampWindow = 120 // seconds

// RegisterClaims are the RegisterRequest fields covered by the
// proof-of-possession signature, plus the client timestamp.
type RegisterClaims struct {
	NetworkID     string   // network_id
	Ed25519Public string   // ed25519_public, base64, exactly as sent on the wire
	X25519Public  string   // x25519_public, base64, exactly as sent on the wire
	Endpoint      string   // endpoint, "ip:port" or ""
	SubnetRoutes  []string // subnet_routes; signed in sorted order
	TimestampUnix int64    // client clock, unix seconds
}

// RegisterSignedMessage returns the deterministic message signed for a
// Register proof of key possession: the domain prefix, then length-prefixed
// network_id, ed25519_public, x25519_public and endpoint, then the sorted
// subnet routes as a length-prefixed list, then the timestamp as a
// big-endian uint64. This is the single encoding shared by the coord client
// (which signs it) and the coord server (which verifies it); its golden
// test vector lives in register_test.go.
func RegisterSignedMessage(claims RegisterClaims) []byte {
	// Sort a copy: the encoding must not depend on, or change, the order
	// the caller listed the routes in.
	routes := make([]string, len(claims.SubnetRoutes))
	copy(routes, claims.SubnetRoutes)
	sort.Strings(routes)

	buf := make([]byte, 0, len(RegisterSignatureDomain)+4*4+8+
		len(claims.NetworkID)+len(claims.Ed25519Public)+len(claims.X25519Public)+len(claims.Endpoint)+
		len(routes)*36)
	buf = append(buf, RegisterSignatureDomain...)
	buf = appendPrefixedString(buf, claims.NetworkID)
	buf = appendPrefixedString(buf, claims.Ed25519Public)
	buf = appendPrefixedString(buf, claims.X25519Public)
	buf = appendPrefixedString(buf, claims.Endpoint)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(routes)))
	for _, r := range routes {
		buf = appendPrefixedString(buf, r)
	}
	buf = binary.BigEndian.AppendUint64(buf, uint64(claims.TimestampUnix))
	return buf
}

// appendPrefixedString appends s to buf as a big-endian uint32 length
// followed by the raw bytes, so no field can be read as part of the next.
func appendPrefixedString(buf []byte, s string) []byte {
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(s)))
	return append(buf, s...)
}

// SignRegister signs the Register message for claims with priv, producing
// the bytes a daemon sends in RegisterRequest.signature.
func SignRegister(priv ed25519.PrivateKey, claims RegisterClaims) []byte {
	return ed25519.Sign(priv, RegisterSignedMessage(claims))
}

// VerifyRegisterSignature checks a Register proof of key possession: sig
// must be a valid Ed25519 signature by pub over the Register message for
// claims, and claims.TimestampUnix must lie within RegisterTimestampWindow
// of now. It returns a descriptive error for every failure mode, so a
// caller can reject all of them alike (with codes.Unauthenticated)
// without leaking which check failed.
func VerifyRegisterSignature(pub ed25519.PublicKey, sig []byte, claims RegisterClaims, now int64) error {
	if len(sig) == 0 {
		return errors.New("missing register signature")
	}
	if drift := now - claims.TimestampUnix; drift < -RegisterTimestampWindow || drift > RegisterTimestampWindow {
		return fmt.Errorf("register timestamp %d outside ±%ds window of %d", claims.TimestampUnix, RegisterTimestampWindow, now)
	}
	if !ed25519.Verify(pub, RegisterSignedMessage(claims), sig) {
		return errors.New("invalid register signature")
	}
	return nil
}
