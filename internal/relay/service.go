// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT

package relay

import (
	"context"
	"net"
	"sync"

	"github.com/flynn/noise"

	"github.com/veldmesh/veld/internal/crypto"
)

// Service is a DERP-style relay server. It accepts Noise IK-encrypted client
// connections, groups them by channel ID, and splices pairs of connections on
// the same channel. It runs on a volunteer mesh peer — deploy it anywhere the
// failing pair can both reach over TCP. Traffic never transits the coord server.
type Service struct {
	id *crypto.Identity
	ln net.Listener

	mu      sync.Mutex
	waiting map[[ChannelIDSize]byte]*serverConn
	closed  bool
	done    chan struct{}
}

// serverConn is one client connection on the relay side.
type serverConn struct {
	raw        net.Conn
	send, recv *noise.CipherState
	channel    [ChannelIDSize]byte
	wmu        sync.Mutex
}

// NewService creates a relay Service listening on ln with the given identity.
// Clients must be configured with the identity's X25519 public key.
func NewService(id *crypto.Identity, ln net.Listener) *Service {
	return &Service{
		id:      id,
		ln:      ln,
		waiting: make(map[[ChannelIDSize]byte]*serverConn),
		done:    make(chan struct{}),
	}
}

// Addr returns the listener's address.
func (s *Service) Addr() string { return s.ln.Addr().String() }

// Serve accepts connections until the listener is closed or ctx is cancelled.
// It returns nil on clean shutdown.
func (s *Service) Serve(ctx context.Context) error {
	go func() {
		select {
		case <-ctx.Done():
			_ = s.Close()
		case <-s.done:
		}
	}()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			select {
			case <-s.done:
				return nil
			default:
				return err
			}
		}
		go s.handleConn(c)
	}
}

// Close stops the service and all pending connections.
func (s *Service) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	close(s.done)
	waiting := s.waiting
	s.waiting = make(map[[ChannelIDSize]byte]*serverConn)
	s.mu.Unlock()
	for _, sc := range waiting {
		_ = sc.raw.Close()
	}
	return s.ln.Close()
}

// handleConn performs the Noise IK handshake as responder, reads the channel
// ID from message_1's encrypted payload, and pairs the connection.
func (s *Service) handleConn(raw net.Conn) {
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: noiseSuite,
		Pattern:     noise.HandshakeIK,
		Initiator:   false,
		StaticKeypair: noise.DHKey{
			Private: s.id.X25519Private[:],
			Public:  s.id.X25519Public[:],
		},
	})
	if err != nil {
		_ = raw.Close()
		return
	}

	msg1, err := readFrame(raw)
	if err != nil {
		_ = raw.Close()
		return
	}
	payload, _, _, err := hs.ReadMessage(nil, msg1)
	if err != nil || len(payload) != ChannelIDSize {
		// Silent drop: no error reply — an error would be an oracle.
		_ = raw.Close()
		return
	}
	var channel [ChannelIDSize]byte
	copy(channel[:], payload)

	msg2, cs1, cs2, err := hs.WriteMessage(nil, nil)
	if err != nil {
		_ = raw.Close()
		return
	}
	if err := writeFrame(raw, msg2); err != nil {
		_ = raw.Close()
		return
	}

	// Responder: cs1 = recv (client→relay), cs2 = send (relay→client).
	sc := &serverConn{raw: raw, recv: cs1, send: cs2, channel: channel}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = raw.Close()
		return
	}
	other := s.waiting[channel]
	delete(s.waiting, channel)
	if other == nil {
		s.waiting[channel] = sc
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()

	// Pair matched: splice in both directions. When either direction fails,
	// both connections are closed.
	go splice(sc, other)
	splice(other, sc)
}

// splice forwards frames from src to dst until an error occurs, then closes both.
func splice(dst, src *serverConn) {
	for {
		frame, err := readFrame(src.raw)
		if err != nil {
			break
		}
		plain, err := src.recv.Decrypt(nil, nil, frame)
		if err != nil {
			break
		}
		ct, err := dst.send.Encrypt(nil, nil, plain)
		if err != nil {
			break
		}
		dst.wmu.Lock()
		err = writeFrame(dst.raw, ct)
		dst.wmu.Unlock()
		if err != nil {
			break
		}
	}
	_ = src.raw.Close()
	_ = dst.raw.Close()
}
