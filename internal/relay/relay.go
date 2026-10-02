// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT

// Package relay implements a DERP-style relay fallback for peers that cannot
// establish a direct UDP path via NAT hole punching (e.g. symmetric NATs).
//
// The relay is a volunteer mesh peer — never the coord server. Clients connect
// to it over TCP and open a Noise IK-encrypted channel (X25519 + SHA-256 +
// ChaCha20-Poly1305) using the relay's pinned static key. Both sides of a
// failing peer pair derive the same 16-byte channel ID from their peer IDs
// (ChannelID); the relay splices the two connections that present the same
// channel ID and forwards opaque frames between them.
//
// The relay is blind: payloads flowing over a channel are the peers' own
// data-plane datagrams, which are already end-to-end encrypted by the
// session layer (peer-to-peer Noise IK + ChaCha20-Poly1305). The relay
// learns only channel IDs, volumes, and timing.
//
// Wire protocol (client → relay is the Noise IK initiator):
//
//	frame 1: Noise IK message_1, payload = 16-byte channel ID
//	frame 2: Noise IK message_2 from the relay, empty payload
//	thereafter: length-prefixed frames carrying encrypted messages
//
// Every frame on the wire is [uint16 big-endian length][ciphertext].
package relay

import (
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

// maxMessage is the largest payload carried by a single relay frame.
// Sized generously above one tunnel MTU (1420) plus session overhead.
const maxMessage = 1 << 16

// ChannelIDSize is the size of a rendezvous channel ID in bytes.
const ChannelIDSize = 16

var noiseSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)

// ChannelID derives the 16-byte rendezvous channel ID for a peer pair.
// It is symmetric: ChannelID(a, b) == ChannelID(b, a), so both peers of a
// failing NAT pair arrive at the same channel without any extra signalling.
func ChannelID(a, b [32]byte) [ChannelIDSize]byte {
	lo, hi := a, b
	if bytes32Compare(a, b) > 0 {
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

func bytes32Compare(a, b [32]byte) int {
	for i := 0; i < 32; i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// Conn is a Noise IK-encrypted message stream to a relay, paired with the
// remote peer's connection on the same channel.
type Conn struct {
	raw        net.Conn
	send, recv *noise.CipherState
	wmu        sync.Mutex
}

// WriteMessage encrypts b and writes it as one length-prefixed frame.
// Concurrent calls are serialised.
func (c *Conn) WriteMessage(b []byte) error {
	if len(b) > maxMessage {
		return fmt.Errorf("relay: message too large (%d > %d)", len(b), maxMessage)
	}
	ct, err := c.send.Encrypt(nil, nil, b)
	if err != nil {
		return err
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return writeFrame(c.raw, ct)
}

// ReadMessage reads and decrypts the next frame from the relay.
func (c *Conn) ReadMessage() ([]byte, error) {
	frame, err := readFrame(c.raw)
	if err != nil {
		return nil, err
	}
	return c.recv.Decrypt(nil, nil, frame)
}

// Close terminates the underlying TCP connection.
func (c *Conn) Close() error { return c.raw.Close() }

// Dial connects to the relay service at addr ("host:port", TCP), completes a
// Noise IK handshake against the relay's pinned X25519 static key, and
// registers channelID. The returned Conn starts delivering messages once the
// peer with the same channel ID has also connected.
func Dial(ctx context.Context, addr string, relayX25519 [32]byte, id *crypto.Identity, channelID [ChannelIDSize]byte) (*Conn, error) {
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
		CipherSuite: noiseSuite,
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

	msg1, _, _, err := hs.WriteMessage(nil, channelID[:])
	if err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("relay handshake msg1: %w", err)
	}
	if err := writeFrame(raw, msg1); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("relay handshake send: %w", err)
	}

	msg2, err := readFrame(raw)
	if err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("relay handshake recv: %w", err)
	}
	if _, cs1, cs2, err := hs.ReadMessage(nil, msg2); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("relay handshake msg2: %w", err)
	} else {
		// Initiator: cs1 = send, cs2 = recv.
		return &Conn{raw: raw, send: cs1, recv: cs2}, nil
	}
}

// writeFrame writes msg with a 2-byte big-endian length prefix.
func writeFrame(w io.Writer, msg []byte) error {
	if len(msg) > 0xFFFF+32 { // ciphertext may exceed maxMessage by tag overhead only
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

// readFrame reads one length-prefixed frame.
func readFrame(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(hdr[:])
	if int(n) > maxMessage+32 {
		return nil, errors.New("relay: frame too large")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
