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
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"net/netip"
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

// Connection limits. Every connection holds a goroutine and buffers, and
// the handshake is reached before any authentication, so both the total
// and the number from one client IP are capped.
const (
	defaultMaxConns      = 4096
	defaultMaxConnsPerIP = 64
)

// msg1MaxAge is how far the client clock in message_1 may be from ours.
// Without it a recorded message_1 could be replayed at any time to evict
// the real client's waiting connection.
const msg1MaxAge = 30 * time.Second

// maxSeenMsg1 bounds the replay cache.
const maxSeenMsg1 = 1 << 16

// maxMsg1Size bounds the unauthenticated first frame. An IK message 1 with
// its 32-byte payload is 128 bytes.
const maxMsg1Size = 256

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

	// seenMsg1 holds the ephemeral keys of recent message_1s, so a
	// recorded handshake cannot be replayed within msg1MaxAge. Guarded by mu.
	seenMsg1 map[[32]byte]time.Time

	maxConns      int
	maxConnsPerIP int
	conns         int                // open connections, guarded by mu
	connsByIP     map[netip.Addr]int // open connections per client IP
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

// MaxConns sets the limits on open connections in total and per client IP.
// Zero leaves a limit at its default.
func MaxConns(total, perIP int) Option {
	return func(s *Service) {
		if total > 0 {
			s.maxConns = total
		}
		if perIP > 0 {
			s.maxConnsPerIP = perIP
		}
	}
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

		maxConns:      defaultMaxConns,
		maxConnsPerIP: defaultMaxConnsPerIP,
		connsByIP:     make(map[netip.Addr]int),
		seenMsg1:      make(map[[32]byte]time.Time),
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
	var backoff time.Duration
	for {
		c, err := s.ln.Accept()
		if err != nil {
			select {
			case <-s.done:
				return nil
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				// The listener is gone: close the service so the watcher
				// unblocks, then report the error.
				_ = s.Close()
				return err
			}
			// Anything else (EMFILE, ECONNABORTED, ...) is transient:
			// back off and keep serving, as net/http does.
			if backoff == 0 {
				backoff = 5 * time.Millisecond
			} else if backoff *= 2; backoff > time.Second {
				backoff = time.Second
			}
			select {
			case <-s.done:
				return nil
			case <-time.After(backoff):
			}
			continue
		}
		backoff = 0
		lc, ok := s.admit(c)
		if !ok {
			_ = c.Close()
			continue
		}
		go s.handleConn(lc)
	}
}

// admit counts c against the connection limits and wraps it so closing it
// releases its slot. It reports false when a limit is reached.
func (s *Service) admit(c net.Conn) (net.Conn, bool) {
	var ip netip.Addr
	if ap, err := netip.ParseAddrPort(c.RemoteAddr().String()); err == nil {
		ip = ap.Addr().Unmap()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conns >= s.maxConns || s.connsByIP[ip] >= s.maxConnsPerIP {
		return nil, false
	}
	s.conns++
	s.connsByIP[ip]++
	return &limitedConn{Conn: c, release: func() {
		s.mu.Lock()
		s.conns--
		if s.connsByIP[ip]--; s.connsByIP[ip] <= 0 {
			delete(s.connsByIP, ip)
		}
		s.mu.Unlock()
	}}, true
}

// limitedConn releases its connection-limit slot on the first Close.
type limitedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

// freshMsg1 reports whether a message_1 with this payload is recent and not
// a replay, and records it. The ephemeral key (the first 32 bytes of msg1)
// is fresh for every real handshake.
func (s *Service) freshMsg1(msg1, payload []byte) bool {
	now := time.Now()
	sent := time.UnixMilli(int64(binary.BigEndian.Uint64(payload[32:])))
	if d := now.Sub(sent); d > msg1MaxAge || d < -msg1MaxAge {
		return false
	}
	var eph [32]byte
	copy(eph[:], msg1)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.seenMsg1[eph]; ok {
		return false
	}
	if len(s.seenMsg1) >= maxSeenMsg1 {
		for k, exp := range s.seenMsg1 {
			if now.After(exp) {
				delete(s.seenMsg1, k)
			}
		}
		if len(s.seenMsg1) >= maxSeenMsg1 {
			return false
		}
	}
	// Remember it until its timestamp can no longer pass the check.
	s.seenMsg1[eph] = sent.Add(msg1MaxAge)
	return true
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
	msg1, err := relayc.ReadFrameMax(raw, maxMsg1Size)
	if err != nil {
		_ = raw.Close()
		return
	}
	payload, _, _, err := hs.ReadMessage(nil, msg1)
	if err != nil || len(payload) != relayc.Msg1PayloadSize || !s.freshMsg1(msg1, payload) {
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
// errors are reported through the per-connection debug log — only enabled
// in verbose mode — with the error text scrubbed, because network errors
// embed both endpoints' full ip:port in their text.
func (s *Service) splice(dst, src *serverConn) {
	fail := func(err error) {
		if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
			s.logf("channel %x splice ended: %s", src.channel[:4], logsafe.ScrubErr(err))
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
