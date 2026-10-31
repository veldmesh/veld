// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package peer

import (
	"net/netip"
	"sync"
	"time"

	internalsession "github.com/veldmesh/veld/internal/session"
)

// HoldQueueMax is the maximum number of packets held per peer awaiting a session.
const HoldQueueMax = 64

// State is the connection state of a peer.
type State uint8

const (
	StatePending     State = iota // known but no session established
	StateHandshaking              // handshake message sent, awaiting response
	StateConnected                // session active
)

// Entry is a single peer's complete state.
// ID, X25519Pub, VPNAddr, Name, and SubnetRoutes are immutable after insertion.
// All other fields are protected by mu.
type Entry struct {
	// Immutable after insertion.
	ID           [32]byte       // Ed25519 public key (used as the canonical identifier)
	X25519Pub    [32]byte       // X25519 static public key (used in Noise handshake)
	VPNAddr      netip.Addr     // assigned VPN IP
	Name         string         // peer name as registered (e.g. "server1")
	SubnetRoutes []netip.Prefix // LAN prefixes this peer advertises (e.g. 192.168.1.0/24)

	mu            sync.Mutex
	endpoint      netip.AddrPort
	session       *internalsession.Session
	pendingSession *internalsession.Session
	prevSession   *internalsession.Session
	state         State
	lastSeen      time.Time
	holdQueue     [][]byte
}

// GetEndpoint returns the peer's current UDP endpoint.
func (e *Entry) GetEndpoint() netip.AddrPort {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.endpoint
}

// SetEndpoint updates the peer's UDP endpoint.
func (e *Entry) SetEndpoint(ep netip.AddrPort) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.endpoint = ep
}

// GetSession returns the current session (nil if no session established).
func (e *Entry) GetSession() *internalsession.Session {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.session
}

// SetSession sets the session and transitions state to StateConnected. The
// replaced session is kept as the previous session, and any pending session
// is kept too: when both sides initiate at once, the peer may confirm the
// session it responded to instead of this one.
func (e *Entry) SetSession(s *internalsession.Session) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.session != nil && e.session != s {
		e.prevSession = e.session
	}
	e.session = s
	e.state = StateConnected
}

// GetPreviousSession returns the session replaced by the last SetSession or
// promotion (nil if none). It is only used to decrypt packets still in flight.
func (e *Entry) GetPreviousSession() *internalsession.Session {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.prevSession
}

// GetPendingSession returns the pending session (nil if none).
func (e *Entry) GetPendingSession() *internalsession.Session {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.pendingSession
}

// SetPendingSession sets the pending session (for handshake confirmation).
func (e *Entry) SetPendingSession(s *internalsession.Session) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.pendingSession = s
}

// PromotePendingSession promotes the pending session to the active session
// if a pending session exists. Returns true if promotion occurred.
func (e *Entry) PromotePendingSession() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.pendingSession != nil {
		if e.session != nil {
			e.prevSession = e.session
		}
		e.session = e.pendingSession
		e.pendingSession = nil
		e.state = StateConnected
		return true
	}
	return false
}

// GetState returns the current connection state.
func (e *Entry) GetState() State {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.state
}

// SetState sets the connection state.
func (e *Entry) SetState(s State) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.state = s
}

// Touch updates the last-seen timestamp to now.
func (e *Entry) Touch() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.lastSeen = time.Now()
}

// LastSeen returns the last-seen timestamp.
func (e *Entry) LastSeen() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.lastSeen
}

// Enqueue adds a packet copy to the hold queue if not full.
// Returns true if the packet was queued; false if the queue is full (packet is dropped).
func (e *Entry) Enqueue(pkt []byte) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.holdQueue) >= HoldQueueMax {
		return false
	}
	buf := make([]byte, len(pkt))
	copy(buf, pkt)
	e.holdQueue = append(e.holdQueue, buf)
	return true
}

// DrainQueue atomically removes and returns all queued packets.
// Returns nil if the queue is empty.
func (e *Entry) DrainQueue() [][]byte {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.holdQueue) == 0 {
		return nil
	}
	q := e.holdQueue
	e.holdQueue = nil
	return q
}