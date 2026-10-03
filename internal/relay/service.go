// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT

package relay

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/flynn/noise"

	"github.com/veldmesh/veld/internal/crypto"
)

// handshakeTimeout bounds the Noise IK handshake (reading message_1). Without
// it, a half-open connection could hold a file descriptor forever.
const handshakeTimeout = 10 * time.Second

// waitingTimeout bounds how long an unpaired connection waits for its
// counterpart before being evicted.
const waitingTimeout = 60 * time.Second

// Service is a DERP-style relay server. It accepts Noise IK-encrypted client
// connections, pairs the two ends of a peer pair (each client sends the
// remote peer's X25519 key in the handshake payload; the relay derives the
// channel from the authenticated initiator key plus that payload), and
// splices matched connections. It runs on a volunteer mesh peer — deploy it
// with the veld-relay command anywhere the failing pair can both reach over
// TCP. Traffic never transits the coord server.
type Service struct {
	id *crypto.Identity
	ln net.Listener

	mu      sync.Mutex
	waiting map[[channelIDSize]byte]*serverConn
	closed  bool
	// waitTimeout bounds how long an unpaired connection waits for its
	// counterpart; a field so tests can shorten it.
	waitTimeout time.Duration
	done        chan struct{}
}

// serverConn is one client connection on the relay side.
type serverConn struct {
	raw        net.Conn
	send, recv *noise.CipherState
	channel    [channelIDSize]byte
	clientKey  [32]byte // authenticated X25519 static key of this client
	wmu        sync.Mutex
}

// NewService creates a relay Service listening on ln with the given identity.
// Clients must be configured with the identity's X25519 public key.
func NewService(id *crypto.Identity, ln net.Listener) *Service {
	return &Service{
		id:          id,
		ln:          ln,
		waiting:     make(map[[channelIDSize]byte]*serverConn),
		done:        make(chan struct{}),
		waitTimeout: waitingTimeout,
	}
}

// Addr returns the listener's address.
func (s *Service) Addr() string { return s.ln.Addr().String() }

// Serve accepts connections until the listener is closed or ctx is cancelled.
// It returns nil on clean shutdown and never returns while its internal
// watcher goroutine is still running.
func (s *Service) Serve(ctx context.Context) error {
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		select {
		case <-ctx.Done():
			_ = s.Close()
		case <-s.done:
		}
	}()
	// Join the watcher before returning so no goroutine outlives Serve.
	defer func() { <-watchDone }()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			select {
			case <-s.done:
				return nil
			default:
			}
			// Accept failed for a reason other than shutdown: close the
			// service so the watcher unblocks, then report the error.
			_ = s.Close()
			return err
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
	s.waiting = make(map[[channelIDSize]byte]*serverConn)
	s.mu.Unlock()
	for _, sc := range waiting {
		_ = sc.raw.Close()
	}
	return s.ln.Close()
}

// handleConn performs the Noise IK handshake as responder, reads the remote
// peer's X25519 key from message_1's encrypted payload, derives the channel
// from the authenticated client key plus that payload, and pairs the
// connection.
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

	// Bound the handshake so half-open connections cannot pile up.
	_ = raw.SetDeadline(time.Now().Add(handshakeTimeout))
	msg1, err := readFrame(raw)
	if err != nil {
		_ = raw.Close()
		return
	}
	payload, _, _, err := hs.ReadMessage(nil, msg1)
	if err != nil || len(payload) != 32 {
		// Silent drop: no error reply — an error would be an oracle.
		_ = raw.Close()
		return
	}
	var remoteKey [32]byte
	copy(remoteKey[:], payload)

	// client's authenticated X25519 static key; the channel is derived from
	// it, so no third party can join a pair's channel by guessing the ID.
	var clientKey [32]byte
	copy(clientKey[:], hs.PeerStatic())
	if clientKey == remoteKey {
		// A peer cannot relay to itself.
		_ = raw.Close()
		return
	}

	msg2, cs1, cs2, err := hs.WriteMessage(nil, nil)
	if err != nil {
		_ = raw.Close()
		return
	}
	if err := writeFrame(raw, msg2); err != nil {
		_ = raw.Close()
		return
	}
	_ = raw.SetDeadline(time.Time{})

	// Responder: cs1 = recv (client→relay), cs2 = send (relay→client).
	sc := &serverConn{
		raw:       raw,
		recv:      cs1,
		send:      cs2,
		channel:   ChannelID(clientKey, remoteKey),
		clientKey: clientKey,
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = raw.Close()
		return
	}
	other := s.waiting[sc.channel]
	if other != nil && other.clientKey == clientKey {
		// Reconnect from the same client: replace the stale waiting
		// connection instead of splicing the client to itself.
		s.mu.Unlock()
		s.evict(sc.channel, other)
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			_ = raw.Close()
			return
		}
		other = s.waiting[sc.channel]
	}
	if other == nil {
		s.waiting[sc.channel] = sc
		s.mu.Unlock()
		// Evict unpaired connections after waitingTimeout so idle or
		// never-matched clients don't accumulate.
		time.AfterFunc(s.waitTimeout, func() { s.evict(sc.channel, sc) })
		return
	}
	delete(s.waiting, sc.channel)
	s.mu.Unlock()

	// Pair matched: splice in both directions. When either direction fails,
	// both connections are closed.
	go splice(sc, other)
	splice(other, sc)
}

// evict removes sc from the waiting map (if it is still the entry for
// channel) and closes it.
func (s *Service) evict(channel [channelIDSize]byte, sc *serverConn) {
	s.mu.Lock()
	if s.waiting[channel] != sc {
		s.mu.Unlock()
		return
	}
	delete(s.waiting, channel)
	s.mu.Unlock()
	_ = sc.raw.Close()
}

// splice forwards frames from src to dst until an error occurs, then closes
// both connections. Benign teardowns (EOF, closed conn) are quiet; real
// errors are logged for operational visibility.
func splice(dst, src *serverConn) {
	fail := func(err error) {
		if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
			log.Printf("relay: channel %x splice ended: %v", src.channel[:4], err)
		}
		_ = src.raw.Close()
		_ = dst.raw.Close()
	}
	for {
		frame, err := readFrame(src.raw)
		if err != nil {
			fail(err)
			return
		}
		plain, err := src.recv.Decrypt(nil, nil, frame)
		if err != nil {
			fail(err)
			return
		}
		ct, err := dst.send.Encrypt(nil, nil, plain)
		if err != nil {
			fail(err)
			return
		}
		dst.wmu.Lock()
		err = writeFrame(dst.raw, ct)
		dst.wmu.Unlock()
		if err != nil {
			fail(err)
			return
		}
	}
}
