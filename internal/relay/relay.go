// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT

// Package relay implements a DERP-style relay fallback for peers that cannot
// establish a direct UDP path via NAT hole punching (e.g. symmetric NATs).
//
// The relay is a volunteer mesh peer — never the coord server. Clients connect
// to it over TCP and open a Noise IK-encrypted channel (X25519 + SHA-256 +
// ChaCha20-Poly1305) using the relay's pinned static key. The handshake's
// encrypted payload carries the *remote peer's* X25519 public key; the relay
// derives the rendezvous channel from that key plus the initiator key it just
// authenticated (ChannelID), and splices the two connections that arrive on
// the same channel from opposite directions.
//
// Because the channel is derived from the authenticated initiator key rather
// than from a client-supplied channel ID, a third party who merely knows both
// peers' public keys cannot join or hijack a pair's channel — only
// connections authenticated as one of the two peers map onto it. (A malicious
// relay can still refuse service or splice wrongly, but it learns nothing and
// no honest relay will pair an impostor.)
//
// The relay is blind: payloads flowing over a channel are the peers' own
// data-plane datagrams, which are already end-to-end encrypted by the
// session layer (peer-to-peer Noise IK + ChaCha20-Poly1305). The relay
// learns only endpoints, volumes, and timing.
//
// Wire protocol (client → relay is the Noise IK initiator):
//
//	frame 1: Noise IK message_1, payload = 32-byte remote peer X25519 key
//	frame 2: Noise IK message_2 from the relay, empty payload
//	thereafter: length-prefixed frames carrying encrypted messages
//
// Every frame on the wire is [uint16 big-endian length][ciphertext].
//
// This package holds the MIT-licensed relay client (Dial/Conn/Proxy) and the
// wire protocol. The relay server lives in the top-level relay package.
package relay

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/flynn/noise"

	"github.com/veldmesh/veld/internal/crypto"
)

// maxMessage is the largest plaintext payload carried by a single relay
// frame: the 16-bit length field caps a frame at 65535 bytes and the
// ChaCha20-Poly1305 tag adds 16 bytes, so payloads above 65519 would not
// fit on the wire. This is far above the tunnel MTU (1420), so framing
// never truncates a data-plane datagram.
const maxMessage = 0xFFFF - 16

// ChannelIDSize is the size of a derived relay channel identifier in bytes.
const ChannelIDSize = 16

// NoiseSuite is the Noise cipher suite used by the relay channel protocol
// (X25519 + ChaCha20-Poly1305 + SHA-256). It is exported so the relay server
// (top-level relay package) speaks exactly the same protocol.
var NoiseSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)

// ChannelID derives the 16-byte rendezvous channel ID for a key pair.
// It is symmetric: ChannelID(a, b) == ChannelID(b, a), so both peers of a
// failing NAT pair arrive at the same channel without any extra signalling.
func ChannelID(a, b [32]byte) [ChannelIDSize]byte {
	lo, hi := a, b
	if bytes.Compare(a[:], b[:]) > 0 {
		lo, hi = b, a
	}
	h := sha256.New()
	h.Write([]byte("veld-relay-channel-v1"))
	h.Write(lo[:])
	h.Write(hi[:])
	sum := h.Sum(nil)
	var id [ChannelIDSize]byte
	copy(id[:], sum[:ChannelIDSize])
	return id
}

// Conn is a Noise IK-encrypted message stream to a relay, paired with the
// remote peer's connection on the same channel.
type Conn struct {
	raw        net.Conn
	send, recv *noise.CipherState
	wmu        sync.Mutex
}

// WriteMessage encrypts b and writes it as one length-prefixed frame.
// Concurrent calls are serialised: both encryption and the write happen
// under the write mutex so the cipher state is never raced.
func (c *Conn) WriteMessage(b []byte) error {
	if len(b) > maxMessage {
		return fmt.Errorf("relay: message too large (%d > %d)", len(b), maxMessage)
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	ct, err := c.send.Encrypt(nil, nil, b)
	if err != nil {
		return err
	}
	return WriteFrame(c.raw, ct)
}

// ReadMessage reads and decrypts the next frame from the relay.
func (c *Conn) ReadMessage() ([]byte, error) {
	frame, err := ReadFrame(c.raw)
	if err != nil {
		return nil, err
	}
	return c.recv.Decrypt(nil, nil, frame)
}

// Close terminates the underlying TCP connection.
func (c *Conn) Close() error { return c.raw.Close() }

// Dial connects to the relay service at addr ("host:port", TCP), completes a
// Noise IK handshake against the relay's pinned X25519 static key, and
// requests a channel to remotePeerKey — the X25519 public key of the peer
// this node is trying to reach. The relay derives the rendezvous channel
// from the caller's authenticated static key and remotePeerKey; the returned
// Conn starts delivering messages once that peer has also connected.
func Dial(ctx context.Context, addr string, relayX25519 [32]byte, id *crypto.Identity, remotePeerKey [32]byte) (*Conn, error) {
	var d net.Dialer
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("relay dial %s: %w", addr, err)
	}

	if dl, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(dl)
		defer raw.SetDeadline(time.Time{}) //nolint:errcheck
	}

	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: NoiseSuite,
		Pattern:     noise.HandshakeIK,
		Initiator:   true,
		StaticKeypair: noise.DHKey{
			Private: id.X25519Private[:],
			Public:  id.X25519Public[:],
		},
		PeerStatic: relayX25519[:],
	})
	if err != nil {
		_ = raw.Close()
		return nil, err
	}

	msg1, _, _, err := hs.WriteMessage(nil, remotePeerKey[:])
	if err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("relay handshake msg1: %w", err)
	}
	if err := WriteFrame(raw, msg1); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("relay handshake send: %w", err)
	}

	msg2, err := ReadFrame(raw)
	if err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("relay handshake recv: %w", err)
	}
	_, cs1, cs2, err := hs.ReadMessage(nil, msg2)
	if err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("relay handshake msg2: %w", err)
	}
	// Initiator: cs1 = send, cs2 = recv.
	return &Conn{raw: raw, send: cs1, recv: cs2}, nil
}

// WriteFrame writes msg with a 2-byte big-endian length prefix.
func WriteFrame(w io.Writer, msg []byte) error {
	if len(msg) > 0xFFFF {
		return errors.New("relay: frame too large")
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(msg)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(msg)
	return err
}

// ReadFrame reads one length-prefixed frame.
func ReadFrame(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(hdr[:])
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
