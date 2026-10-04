// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: BUSL-1.1

// Package relay implements the Veld relay server: a DERP-style relay that
// volunteer mesh peers (or a small self-hosted VM) run with the veld-relay
// command for peers that cannot establish a direct UDP path via NAT hole
// punching (e.g. symmetric NATs). The relay client and the wire protocol
// live in internal/relay.
//
// The server accepts Noise IK-encrypted client connections over TCP,
// pairs the two ends of a peer pair — each client sends the remote peer's
// X25519 key in the handshake payload, and the relay derives the channel
// from the authenticated initiator key plus that payload — and splices
// matched connections. Traffic never transits the coord server, and the
// relay itself is blind: channel payloads are the peers' data-plane
// datagrams, already end-to-end encrypted by the session layer.
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
	"github.com/veldmesh/veld/internal/logsafe"
	relayc "github.com/veldmesh/veld/internal/relay"
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
//
// By default the service logs no per-connection events (no channel IDs, no
// client addresses); per-connection debug output requires the Verbose
// option.
type Service struct {
	id *crypto.Identity
	ln net.Listener

	mu      sync.Mutex
	waiting map[[relayc.ChannelIDSize]byte]*serverConn
	active  map[*serverConn]struct{} // paired connections with running splices
	closed  bool
	// waitTimeout bounds how long an unpaired connection waits for its
	// counterpart; a field so tests can shorten it.
	waitTimeout time.Duration
	done        chan struct{}
	wg          sync.WaitGroup // tracks running splice goroutines
	// verbose enables per-connection debug logging; off by default.
	verbose bool
}

// serverConn is one client connection on the relay side.
type serverConn struct {
	raw        net.Conn
	send, recv *noise.CipherState
	channel    [relayc.ChannelIDSize]byte
	clientKey  [32]byte // authenticated X25519 static key of this client
	wmu        sync.Mutex
}

// Option configures a relay Service at construction time.
type Option func(*Service)

// Verbose enables per-connection debug logging: connection attempts (with
// truncated client addresses), channel IDs, and splice errors. It is off by
// default — with default settings the relay logs no per-connection events
// at all — and is meant for local debugging only, not production.
func Verbose() Option {
	return func(s *Service) { s.verbose = true }
}

// NewService creates a relay Service listening on ln with the given identity.
// Clients must be configured with the identity's X25519 public key.
func NewService(id *crypto.Identity, ln net.Listener, opts ...Option) *Service {
	s := &Service{
		id:          id,
		ln:          ln,
		waiting:     make(map[[relayc.ChannelIDSize]byte]*serverConn),
		active:      make(map[*serverConn]struct{}),
		done:        make(chan struct{}),
		waitTimeout: waitingTimeout,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Addr returns the listener's address.
func (s *Service) Addr() string { return s.ln.Addr().String() }

// logf emits a per-connection debug line through the standard logger. It is
// a no-op unless Verbose was set: by default the relay logs nothing about
// individual connections (no channel IDs, no client addresses), so
// default-flag logs retain no client-identifying data.
func (s *Service) logf(format string, args ...any) {
	if !s.verbose {
		return
	}
	log.Printf("relay: "+format, args...)
}

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

// Close stops the service, closes all pending and active connections, and
// waits for all splice goroutines to exit before returning.
func (s *Service) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		s.wg.Wait()
		return nil
	}
	s.closed = true
	close(s.done)
	waiting := s.waiting
	s.waiting = make(map[[relayc.ChannelIDSize]byte]*serverConn)
	active := make([]*serverConn, 0, len(s.active))
	for sc := range s.active {
		active = append(active, sc)
	}
	s.mu.Unlock()
	for _, sc := range waiting {
		_ = sc.raw.Close()
	}
	// Closing active connections makes the blocked splice reads fail; the
	// splices then run their own cleanup and deregister.
	for _, sc := range active {
		_ = sc.raw.Close()
	}
	err := s.ln.Close()
	// Join all splice goroutines so none outlive the service.
	s.wg.Wait()
	return err
}

// handleConn performs the Noise IK handshake as responder, reads the remote
// peer's X25519 key from message_1's encrypted payload, derives the channel
// from the authenticated client key plus that payload, and pairs the
// connection.
func (s *Service) handleConn(raw net.Conn) {
	// Verbose-only, and truncated: full client addresses are never logged.
	if from := logsafe.TruncIP(raw.RemoteAddr().String()); from != "" {
		s.logf("connection from %s", from)
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: relayc.NoiseSuite,
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
	msg1, err := relayc.ReadFrame(raw)
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
	if err := relayc.WriteFrame(raw, msg2); err != nil {
		_ = raw.Close()
		return
	}
	_ = raw.SetDeadline(time.Time{})

	// Responder: cs1 = recv (client→relay), cs2 = send (relay→client).
	sc := &serverConn{
		raw:       raw,
		recv:      cs1,
		send:      cs2,
		channel:   relayc.ChannelID(clientKey, remoteKey),
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
	s.active[sc] = struct{}{}
	s.active[other] = struct{}{}
	s.wg.Add(2)
	s.mu.Unlock()

	// Pair matched: splice in both directions, tracked so Close can join
	// them. When either direction fails, both connections are closed.
	go func() {
		defer s.wg.Done()
		defer s.forget(sc)
		s.splice(sc, other)
	}()
	defer s.wg.Done()
	defer s.forget(other)
	s.splice(other, sc)
}

// forget removes sc from the active set once its splice has exited.
func (s *Service) forget(sc *serverConn) {
	s.mu.Lock()
	delete(s.active, sc)
	s.mu.Unlock()
}

// evict removes sc from the waiting map (if it is still the entry for
// channel) and closes it.
func (s *Service) evict(channel [relayc.ChannelIDSize]byte, sc *serverConn) {
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
// errors are reported through the per-connection debug log, which is only
// enabled in verbose mode.
func (s *Service) splice(dst, src *serverConn) {
	fail := func(err error) {
		if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
			s.logf("channel %x splice ended: %v", src.channel[:4], err)
		}
		_ = src.raw.Close()
		_ = dst.raw.Close()
	}
	for {
		frame, err := relayc.ReadFrame(src.raw)
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
		err = relayc.WriteFrame(dst.raw, ct)
		dst.wmu.Unlock()
		if err != nil {
			fail(err)
			return
		}
	}
}
