// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package handshake

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/veldmesh/veld/internal/crypto"
	"github.com/veldmesh/veld/internal/peer"
	"github.com/veldmesh/veld/internal/session"
)

// Packet type constants -- must match dataplane.TypeHandshakeInit/Resp.
const (
	typeHandshakeInit uint32 = 0x02
	typeHandshakeResp uint32 = 0x03
	headerSize               = 16 // same as dataplane.HeaderSize
)

// handshakeRetryTimeout is the time after which a pending handshake is considered
// expired and a new one may be initiated. Matches WireGuard's REKEY_TIMEOUT.
const handshakeRetryTimeout = 5 * time.Second

// maxHandshakeRetries bounds the number of retries for a single handshake attempt.
const maxHandshakeRetries = 3

type pendingHS struct {
	hs        *crypto.InitiatorHS
	peerID    [32]byte
	createdAt time.Time
	retries   int
}

// Manager handles Noise IK handshake initiation and response over a shared UDP conn.
type Manager struct {
	localID   *crypto.Identity
	networkID [16]byte
	peers     *peer.Table
	conn      net.PacketConn

	// OnSessionEstablished is called after a successful handshake on either side.
	// The caller (daemon) uses this to flush the peer's hold queue via
	// dispatcher.FlushHoldQueue.
	OnSessionEstablished func(entry *peer.Entry)

	// TOFUCheck is called after each successful handshake to enforce Trust-On-First-Use
	// fingerprint pinning. vpnAddr is the peer's VPN address string; pub is the Ed25519
	// public key seen in the handshake. If TOFUCheck returns an error the session is
	// silently discarded. If nil, TOFU pinning is disabled.
	TOFUCheck func(vpnAddr string, pub ed25519.PublicKey) error

	// initTimestamps tracks the greatest accepted Init timestamp per peer ID.
	// Used to reject replayed handshake initiations. Entries older than
	// crypto.MaxTimestampSkew are pruned: an Init that old fails the
	// signature's freshness check anyway.
	initTimestamps map[[32]byte]int64

	// replayPath, if set, is where initTimestamps is saved after every
	// accepted Init, so a restart does not forget them. saveMu orders writes.
	replayPath string
	saveMu     sync.Mutex

	mu      sync.Mutex
	pending map[[32]byte]*pendingHS
}

// New creates a Manager.
func New(localID *crypto.Identity, networkID [16]byte, peers *peer.Table, conn net.PacketConn) *Manager {
	return &Manager{
		localID:        localID,
		networkID:      networkID,
		peers:          peers,
		conn:           conn,
		pending:        make(map[[32]byte]*pendingHS),
		initTimestamps: make(map[[32]byte]int64),
	}
}

// Initiate starts a Noise IK handshake with entry if none is already pending,
// or if the pending handshake has expired (older than handshakeRetryTimeout).
// This is wired as dispatcher.OnHandshakeRequired.
func (m *Manager) Initiate(entry *peer.Entry) {
	m.mu.Lock()
	phs, exists := m.pending[entry.ID]
	if exists {
		if time.Since(phs.createdAt) < handshakeRetryTimeout {
			m.mu.Unlock()
			return
		}
		// Expired: allow retry, but bound total retries.
		if phs.retries >= maxHandshakeRetries {
			// Retries exhausted: delete the pending entry so a future Initiate
			// can start a fresh handshake attempt (e.g., after network recovery).
			delete(m.pending, entry.ID)
			m.mu.Unlock()
			return
		}
		phs.retries++
		phs.createdAt = time.Now()
	}

	hs, err := crypto.NewInitiatorHS(m.localID, entry.X25519Pub, m.networkID)
	var msg1 []byte
	if err == nil {
		// Build message 1 before publishing hs in m.pending, so a response
		// handled concurrently never sees a half-built handshake.
		msg1, err = hs.BuildMessage1(time.Now().UnixNano())
	}
	if err != nil {
		if exists {
			// Restore previous state on failure.
			phs.retries--
		}
		m.mu.Unlock()
		return
	}
	// Preserve retry count when retrying an existing handshake.
	retries := 0
	if exists {
		retries = phs.retries
	}
	m.pending[entry.ID] = &pendingHS{hs: hs, peerID: entry.ID, createdAt: time.Now(), retries: retries}
	m.mu.Unlock()

	entry.SetState(peer.StateHandshaking)

	ep := entry.GetEndpoint()
	if !ep.IsValid() {
		m.mu.Lock()
		delete(m.pending, entry.ID)
		m.mu.Unlock()
		return
	}

	pkt := buildPacket(typeHandshakeInit, msg1)
	m.conn.WriteTo(pkt, net.UDPAddrFromAddrPort(ep))
}

// HandlePacket processes a received TypeHandshakeInit or TypeHandshakeResp packet.
// This is wired as dispatcher.OnHandshakePacket.
// pkt starts at byte 0 (full wire packet including 16-byte header).
func (m *Manager) HandlePacket(pkt []byte, addr net.Addr) {
	if len(pkt) < headerSize {
		return
	}
	pktType := binary.BigEndian.Uint32(pkt[0:4])
	noiseMsg := pkt[headerSize:]

	switch pktType {
	case typeHandshakeInit:
		m.handleInit(noiseMsg, addr)
	case typeHandshakeResp:
		m.handleResp(noiseMsg, addr)
	}
}

// HandleDataPacket attempts to decrypt a data packet using the peer's pending
// session (for handshake confirmation). If successful, promotes the pending
// session to active and calls OnSessionEstablished.
// Returns the decrypted plaintext, or nil if decryption failed or no pending session.
// This is called by the dispatcher when a data packet fails to decrypt with the active session.
func (m *Manager) HandleDataPacket(entry *peer.Entry, nonce uint64, ciphertext []byte) ([]byte, bool) {
	pending := entry.GetPendingSession()
	if pending == nil {
		return nil, false
	}
	plain, err := pending.Decrypt(nonce, ciphertext)
	if err != nil || plain == nil {
		return nil, false
	}
	// Pending session works -- promote it to active.
	if entry.PromotePendingSession() {
		if m.OnSessionEstablished != nil {
			m.OnSessionEstablished(entry)
		}
	}
	return plain, true
}

// OnPeerRemoved cleans up handshake state for a peer that has been removed.
// Call this when the peer table removes a peer (e.g., on Leave or expiration).
// The peer's last Init timestamp is kept until it ages out, so an Init
// recorded before the removal cannot be replayed if the peer comes back.
func (m *Manager) OnPeerRemoved(peerID [32]byte) {
	m.mu.Lock()
	delete(m.pending, peerID)
	m.mu.Unlock()
}

// replayFile is the on-disk form of initTimestamps.
type replayFile struct {
	Version int              `json:"version"`
	Peers   map[string]int64 `json:"peers"` // hex peer ID -> Init timestamp (ns)
}

// UseReplayState loads saved Init timestamps from path and saves them there
// from now on. A missing file is not an error. Call it before the manager
// handles any packet.
func (m *Manager) UseReplayState(path string) error {
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	var f replayFile
	if err == nil {
		// A damaged file only loses the saved timestamps; start without them.
		_ = json.Unmarshal(data, &f)
	}
	cutoff := time.Now().Add(-crypto.MaxTimestampSkew).UnixNano()
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, ts := range f.Peers {
		b, err := hex.DecodeString(k)
		if err != nil || len(b) != 32 || ts < cutoff {
			continue
		}
		var id [32]byte
		copy(id[:], b)
		if ts > m.initTimestamps[id] {
			m.initTimestamps[id] = ts
		}
	}
	m.replayPath = path
	return nil
}

// pruneTimestampsLocked drops Init timestamps too old to matter and returns
// a copy of the rest for saving. m.mu must be held.
func (m *Manager) pruneTimestampsLocked() map[string]int64 {
	cutoff := time.Now().Add(-crypto.MaxTimestampSkew).UnixNano()
	out := make(map[string]int64, len(m.initTimestamps))
	for id, ts := range m.initTimestamps {
		if ts < cutoff {
			delete(m.initTimestamps, id)
			continue
		}
		out[hex.EncodeToString(id[:])] = ts
	}
	return out
}

// saveReplayState writes peers to m.replayPath. Errors are ignored: the
// in-memory state still protects this run.
func (m *Manager) saveReplayState(peers map[string]int64) {
	data, err := json.Marshal(replayFile{Version: 1, Peers: peers})
	if err != nil {
		return
	}
	m.saveMu.Lock()
	defer m.saveMu.Unlock()
	tmp := m.replayPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return
	}
	_ = os.Rename(tmp, m.replayPath)
}

func (m *Manager) handleInit(noiseMsg []byte, addr net.Addr) {
	respHS, err := crypto.NewResponderHS(m.localID, m.peers.PeerLookupFn())
	if err != nil {
		return
	}
	// ProcessMessage1 now returns the raw timestamp from the decrypted payload.
	tsRaw, err := respHS.ProcessMessage1(noiseMsg, time.Now().UnixNano())
	if err != nil {
		return // silently drop unknown or tampered init
	}
	// Normalize timestamp to nanoseconds for replay protection comparison.
	ts := crypto.NormalizeTimestamp(tsRaw)

	msg2, result, err := respHS.BuildMessage2(time.Now().UnixNano())
	if err != nil {
		return
	}
	// The initiator names the network it is joining. A key that is a member
	// of several networks must not be able to carry a session from one into
	// another.
	if result.NetworkID != m.networkID {
		return
	}

	var peerID [32]byte
	copy(peerID[:], result.PeerEd25519Public)

	entry, ok := m.peers.LookupByID(peerID)
	if !ok {
		return
	}

	// Replay protection: reject Init if its timestamp is not strictly greater
	// than the greatest timestamp we've accepted from this peer.
	if ts == 0 {
		return // malformed
	}
	m.mu.Lock()
	if lastTS, ok := m.initTimestamps[peerID]; ok && ts <= lastTS {
		m.mu.Unlock()
		return // replayed or stale Init
	}
	m.initTimestamps[peerID] = ts
	var snapshot map[string]int64
	if m.replayPath != "" {
		snapshot = m.pruneTimestampsLocked()
	}
	m.mu.Unlock()
	if snapshot != nil {
		m.saveReplayState(snapshot)
	}

	// TOFU check: verify the initiator's fingerprint matches prior connections.
	if m.TOFUCheck != nil {
		if err := m.TOFUCheck(entry.VPNAddr.String(), result.PeerEd25519Public); err != nil {
			return // silently drop -- fingerprint mismatch
		}
	}

	// Record the initiator's actual source address.
	if ep, ok := addrToAddrPort(addr); ok {
		m.peers.ClaimEndpoint(peerID, ep)
	}

	// Store the new session as pending. It will be promoted to active when
	// the initiator sends a data packet that successfully decrypts with it
	// (WireGuard-style handshake confirmation). This prevents tunnel desync
	// if the Resp packet is lost.
	entry.SetPendingSession(session.New(result))

	pkt := buildPacket(typeHandshakeResp, msg2)
	m.conn.WriteTo(pkt, addr)
}

func (m *Manager) handleResp(noiseMsg []byte, addr net.Addr) {
	ep, ok := addrToAddrPort(addr)
	if !ok {
		return
	}

	entry, ok := m.peers.LookupByEndpoint(ep)
	if !ok {
		return
	}

	m.mu.Lock()
	phs, ok := m.pending[entry.ID]
	m.mu.Unlock()
	if !ok {
		return
	}

	// ProcessMessage2 leaves phs.hs unchanged on failure, so a response that
	// does not verify is dropped and the handshake stays pending for the
	// genuine one.
	result, err := phs.hs.ProcessMessage2(noiseMsg, time.Now().UnixNano())
	if err != nil {
		return
	}

	// Verify the responder's identity matches who we expected to talk to.
	// This catches a MitM that substitutes a different Ed25519 key.
	var responderID [32]byte
	copy(responderID[:], result.PeerEd25519Public)
	if responderID != entry.ID {
		return // identity mismatch -- silently drop
	}

	// TOFU check: verify the responder's fingerprint matches prior connections.
	if m.TOFUCheck != nil {
		if err := m.TOFUCheck(entry.VPNAddr.String(), result.PeerEd25519Public); err != nil {
			return // silently drop -- fingerprint mismatch
		}
	}

	// Complete the handshake only once, and only if it is still the current
	// attempt: a retry may have replaced it while the response was in flight.
	m.mu.Lock()
	if m.pending[entry.ID] != phs {
		m.mu.Unlock()
		return
	}
	delete(m.pending, entry.ID)
	m.mu.Unlock()

	// Initiator side: the handshake is confirmed when we successfully process
	// the Resp. Promote the session immediately.
	entry.SetSession(session.New(result))

	if m.OnSessionEstablished != nil {
		m.OnSessionEstablished(entry)
	}
}

// buildPacket assembles a wire-format handshake UDP payload.
// Uses the same 16-byte header as data packets, with bytes 4-15 zeroed.
func buildPacket(pktType uint32, msg []byte) []byte {
	buf := make([]byte, headerSize+len(msg))
	binary.BigEndian.PutUint32(buf[0:4], pktType)
	// bytes 4-15: reserved (zero)
	copy(buf[headerSize:], msg)
	return buf
}

// addrToAddrPort converts a net.Addr to netip.AddrPort.
// Normalizes IPv4-mapped IPv6 to plain IPv4 for consistent map lookups.
func addrToAddrPort(a net.Addr) (netip.AddrPort, bool) {
	if ua, ok := a.(*net.UDPAddr); ok {
		ap := ua.AddrPort()
		ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
		return ap, ap.IsValid()
	}
	ap, err := netip.ParseAddrPort(a.String())
	if err == nil {
		ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}
	return ap, err == nil
}
