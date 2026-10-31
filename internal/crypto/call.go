// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package crypto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

// CallSignatureDomain is the domain-separation prefix of the message a peer
// signs to act as itself in a coord RPC other than Register (Leave, Watch,
// SendSignal): "veld-coord-call-v1" followed by a NUL byte. The shared
// token only proves membership of the account; the signature proves the
// caller holds the private key of the peer it names.
const CallSignatureDomain = "veld-coord-call-v1\x00"

// CallTimestampWindow bounds the client clock in a call signature, in
// seconds, like RegisterTimestampWindow.
const CallTimestampWindow = RegisterTimestampWindow

// Coord RPC method names covered by call signatures.
const (
	CallLeave      = "Leave"
	CallWatch      = "Watch"
	CallSendSignal = "SendSignal"
)

// CallClaims are the request fields covered by a call signature.
type CallClaims struct {
	Method        string   // one of the Call* constants
	PeerID        string   // the peer acting: Ed25519 public key, hex
	Args          []string // method arguments, in a fixed order per method
	TimestampUnix int64    // client clock, unix seconds
}

// LeaveClaims returns the claims a Leave request signs.
func LeaveClaims(peerID string, ts int64) CallClaims {
	return CallClaims{Method: CallLeave, PeerID: peerID, TimestampUnix: ts}
}

// WatchClaims returns the claims a Watch request naming peerID signs.
func WatchClaims(peerID, networkID string, ts int64) CallClaims {
	return CallClaims{Method: CallWatch, PeerID: peerID, Args: []string{networkID}, TimestampUnix: ts}
}

// SendSignalClaims returns the claims a SendSignal request signs. The
// payload is covered by its SHA-256, so a signature cannot be reused for a
// different payload.
func SendSignalClaims(fromPeerID, toPeerID string, payload []byte, ts int64) CallClaims {
	sum := sha256.Sum256(payload)
	return CallClaims{Method: CallSendSignal, PeerID: fromPeerID, Args: []string{toPeerID, hex.EncodeToString(sum[:])}, TimestampUnix: ts}
}

// CallSignedMessage returns the deterministic message signed for claims: the
// domain prefix, then length-prefixed method and peer ID, then the arguments
// as a length-prefixed list, then the timestamp as a big-endian uint64.
func CallSignedMessage(claims CallClaims) []byte {
	buf := make([]byte, 0, len(CallSignatureDomain)+64+len(claims.PeerID))
	buf = append(buf, CallSignatureDomain...)
	buf = appendPrefixedString(buf, claims.Method)
	buf = appendPrefixedString(buf, claims.PeerID)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(claims.Args)))
	for _, a := range claims.Args {
		buf = appendPrefixedString(buf, a)
	}
	buf = binary.BigEndian.AppendUint64(buf, uint64(claims.TimestampUnix))
	return buf
}

// SignCall signs the call message for claims with priv.
func SignCall(priv ed25519.PrivateKey, claims CallClaims) []byte {
	return ed25519.Sign(priv, CallSignedMessage(claims))
}

// VerifyCallSignature checks that sig is a valid signature by pub over the
// call message for claims, with claims.TimestampUnix within
// CallTimestampWindow of now.
func VerifyCallSignature(pub ed25519.PublicKey, sig []byte, claims CallClaims, now int64) error {
	if len(sig) == 0 {
		return errors.New("missing call signature")
	}
	if drift := now - claims.TimestampUnix; drift < -CallTimestampWindow || drift > CallTimestampWindow {
		return fmt.Errorf("call timestamp %d outside ±%ds window of %d", claims.TimestampUnix, CallTimestampWindow, now)
	}
	if !ed25519.Verify(pub, CallSignedMessage(claims), sig) {
		return errors.New("invalid call signature")
	}
	return nil
}
