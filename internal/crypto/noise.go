// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"

	"github.com/flynn/noise"
)

// ErrHandshakeDrop is returned when a handshake message must be silently dropped.
// The caller MUST NOT send any response — doing so leaks information about valid keys.
var ErrHandshakeDrop = errors.New("handshake dropped")

// HandshakeResult holds the outputs of a completed Noise IK handshake.
type HandshakeResult struct {
	// Initiator: SendCS=cs1, RecvCS=cs2 (Noise IK spec convention)
	// Responder: SendCS=cs2, RecvCS=cs1
	SendCS            *noise.CipherState
	RecvCS            *noise.CipherState
	SessionID         [8]byte
	PeerEd25519Public ed25519.PublicKey
	NetworkID         [16]byte
}

// PeerLookupFn authorizes an initiator by Ed25519 public key.
// Returns the peer's expected X25519 static pubkey from the peer table.
// Returns false if the peer is unknown — the caller must silently drop.
type PeerLookupFn func(ed25519Pub []byte) (x25519Pub [32]byte, known bool)

// InitiatorHS is the initiator side of a Noise IK handshake.
type InitiatorHS struct {
	hs         *noise.HandshakeState
	localID    *Identity
	peerX25519 [32]byte
	networkID  [16]byte
}

// ResponderHS is the responder side of a Noise IK handshake.
type ResponderHS struct {
	hs                *noise.HandshakeState
	localID           *Identity
	peerLookup        PeerLookupFn
	peerX25519        [32]byte
	peerEd25519Public ed25519.PublicKey
	networkID         [16]byte
}

func noiseSuite() noise.CipherSuite {
	return noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
}

// NewInitiatorHS creates an initiator-side Noise IK handshake directed at peerX25519.
func NewInitiatorHS(localID *Identity, peerX25519 [32]byte, networkID [16]byte) (*InitiatorHS, error) {
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: noiseSuite(),
		Pattern:     noise.HandshakeIK,
		Initiator:   true,
		StaticKeypair: noise.DHKey{
			Private: localID.X25519Private[:],
			Public:  localID.X25519Public[:],
		},
		PeerStatic: peerX25519[:],
	})
	if err != nil {
		return nil, err
	}
	return &InitiatorHS{hs: hs, localID: localID, peerX25519: peerX25519, networkID: networkID}, nil
}

// BuildMessage1 constructs the initiator's first Noise IK handshake message.
//
// Payload (120 bytes, encrypted by Noise):
//
//	ed25519_pub [32]  initiator's Ed25519 public key
//	sig         [64]  SignForPeer(peerX25519, nowSec)
//	network_id  [16]  the network UUID
//	timestamp   [ 8]  nowSec as big-endian uint64
func (h *InitiatorHS) BuildMessage1(nowSec int64) ([]byte, error) {
	sig, err := h.localID.SignForPeer(h.peerX25519, nowSec)
	if err != nil {
		return nil, err
	}

	payload := make([]byte, 120)
	copy(payload[0:32], h.localID.Ed25519Public)
	copy(payload[32:96], sig[:])
	copy(payload[96:112], h.networkID[:])
	binary.BigEndian.PutUint64(payload[112:120], uint64(nowSec))

	msg, _, _, err := h.hs.WriteMessage(nil, payload)
	if err != nil {
		return nil, err
	}
	return msg, nil
}

// ProcessMessage2 decrypts and validates the responder's reply, returning session keys.
// Returns ErrHandshakeDrop on ANY validation failure — caller must send no response.
//
// Payload (112 bytes, decrypted by Noise):
//
//	ed25519_pub [32]  responder's Ed25519 public key
//	sig         [64]  responder's SignForPeer(initiator_x25519, nowSec)
//	session_id  [ 8]  random
//	timestamp   [ 8]  big-endian uint64
func (h *InitiatorHS) ProcessMessage2(msg []byte, _ int64) (*HandshakeResult, error) {
	payload, cs1, cs2, err := h.hs.ReadMessage(nil, msg)
	if err != nil {
		return nil, ErrHandshakeDrop
	}

	if len(payload) != 112 {
		return nil, ErrHandshakeDrop
	}

	peerEd25519Pub := make(ed25519.PublicKey, 32)
	copy(peerEd25519Pub, payload[0:32])

	var sig [64]byte
	copy(sig[:], payload[32:96])

	var sessionID [8]byte
	copy(sessionID[:], payload[96:104])

	ts := int64(binary.BigEndian.Uint64(payload[104:112]))

	// sig covers responder_x25519 || initiator_x25519 || timestamp
	if err := VerifyPeerSig(peerEd25519Pub, h.peerX25519, h.localID.X25519Public, sig, ts); err != nil {
		return nil, ErrHandshakeDrop
	}

	// Initiator: cs1 = send (initiator→responder), cs2 = recv (responder→initiator)
	return &HandshakeResult{
		SendCS:            cs1,
		RecvCS:            cs2,
		SessionID:         sessionID,
		PeerEd25519Public: peerEd25519Pub,
		NetworkID:         h.networkID,
	}, nil
}

// NewResponderHS creates a responder-side Noise IK handshake state.
// peerLookup is called during ProcessMessage1 to authorize the initiator.
func NewResponderHS(localID *Identity, peerLookup PeerLookupFn) (*ResponderHS, error) {
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: noiseSuite(),
		Pattern:     noise.HandshakeIK,
		Initiator:   false,
		StaticKeypair: noise.DHKey{
			Private: localID.X25519Private[:],
			Public:  localID.X25519Public[:],
		},
	})
	if err != nil {
		return nil, err
	}
	return &ResponderHS{hs: hs, localID: localID, peerLookup: peerLookup}, nil
}

// ProcessMessage1 decrypts and validates the initiator's first message.
// Returns ErrHandshakeDrop on ANY validation failure — caller must send no response.
func (h *ResponderHS) ProcessMessage1(msg []byte, _ int64) error {
	payload, _, _, err := h.hs.ReadMessage(nil, msg)
	if err != nil {
		return ErrHandshakeDrop
	}

	if len(payload) != 120 {
		return ErrHandshakeDrop
	}

	peerEd25519Pub := make(ed25519.PublicKey, 32)
	copy(peerEd25519Pub, payload[0:32])

	var sig [64]byte
	copy(sig[:], payload[32:96])

	var networkID [16]byte
	copy(networkID[:], payload[96:112])

	ts := int64(binary.BigEndian.Uint64(payload[112:120]))

	// Extract initiator's X25519 static key (decrypted by Noise IK 's' token)
	peerStaticBytes := h.hs.PeerStatic()
	if len(peerStaticBytes) != 32 {
		return ErrHandshakeDrop
	}
	var peerX25519 [32]byte
	copy(peerX25519[:], peerStaticBytes)

	// Authorize: check peer table; also verify the X25519 they sent matches what's registered
	registeredX25519, known := h.peerLookup(peerEd25519Pub)
	if !known || peerX25519 != registeredX25519 {
		return ErrHandshakeDrop
	}

	// sig covers initiator_x25519 || responder_x25519 || timestamp
	if err := VerifyPeerSig(peerEd25519Pub, peerX25519, h.localID.X25519Public, sig, ts); err != nil {
		return ErrHandshakeDrop
	}

	h.peerX25519 = peerX25519
	h.peerEd25519Public = peerEd25519Pub
	h.networkID = networkID
	return nil
}

// BuildMessage2 constructs the responder's reply and returns session keys.
// Must only be called after a successful ProcessMessage1.
//
// Payload (112 bytes, encrypted by Noise):
//
//	ed25519_pub [32]  responder's Ed25519 public key
//	sig         [64]  SignForPeer(peerX25519, nowSec)
//	session_id  [ 8]  random
//	timestamp   [ 8]  nowSec as big-endian uint64
func (h *ResponderHS) BuildMessage2(nowSec int64) ([]byte, *HandshakeResult, error) {
	sig, err := h.localID.SignForPeer(h.peerX25519, nowSec)
	if err != nil {
		return nil, nil, err
	}

	var sessionID [8]byte
	if _, err := rand.Read(sessionID[:]); err != nil {
		return nil, nil, err
	}

	payload := make([]byte, 112)
	copy(payload[0:32], h.localID.Ed25519Public)
	copy(payload[32:96], sig[:])
	copy(payload[96:104], sessionID[:])
	binary.BigEndian.PutUint64(payload[104:112], uint64(nowSec))

	msg, cs1, cs2, err := h.hs.WriteMessage(nil, payload)
	if err != nil {
		return nil, nil, err
	}

	// Responder: cs1 = recv (initiator→responder), cs2 = send (responder→initiator)
	return msg, &HandshakeResult{
		SendCS:            cs2,
		RecvCS:            cs1,
		SessionID:         sessionID,
		PeerEd25519Public: h.peerEd25519Public,
		NetworkID:         h.networkID,
	}, nil
}
