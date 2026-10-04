// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"sync"
	"time"

	coordv1 "github.com/veldmesh/veld/gen/veld/coord/v1"
)

// signalMsg is an opaque signal (ICE candidate etc.) from one peer to another.
type signalMsg struct {
	FromPeerID string
	ToPeerID   string
	Payload    []byte
}

// Limits for signals held for a registered peer whose Watch stream is not open
// yet. A client registers first and opens Watch afterwards; peers already
// watching see its JOIN in between and signal it immediately. Those signals
// used to be dropped, so the newcomer never received its peers' NAT
// candidates and hole punching succeeded on one side only.
const (
	pendingSignalTTL     = 30 * time.Second
	maxPendingPerPeer    = 16
	maxPendingRecipients = 4096
)

type pendingSignal struct {
	msg signalMsg
	at  time.Time
}

// Bus is an in-memory fanout bus for PeerEvents and peer-to-peer signals.
// Each Watch subscriber gets its own channel; signals are delivered directly
// to the target peer's subscriber(s), or held briefly (memory only) until the
// recipient subscribes.
type Bus struct {
	mu          sync.RWMutex
	subscribers map[string][]chan *coordv1.PeerEvent // key: networkID
	signals     map[string][]chan signalMsg           // key: peerID (recipient)
	pending     map[string][]pendingSignal            // key: peerID (recipient, not subscribed yet)
	now         func() time.Time
}

// NewBus creates an empty Bus.
func NewBus() *Bus {
	return &Bus{
		subscribers: make(map[string][]chan *coordv1.PeerEvent),
		signals:     make(map[string][]chan signalMsg),
		pending:     make(map[string][]pendingSignal),
		now:         time.Now,
	}
}

// Subscribe returns a channel that receives PeerEvents for networkID.
// Call Unsubscribe with the same channel when done.
func (b *Bus) Subscribe(networkID string) <-chan *coordv1.PeerEvent {
	ch := make(chan *coordv1.PeerEvent, 64)
	b.mu.Lock()
	b.subscribers[networkID] = append(b.subscribers[networkID], ch)
	b.mu.Unlock()
	return ch
}

// Unsubscribe removes and closes a subscriber channel.
func (b *Bus) Unsubscribe(networkID string, ch <-chan *coordv1.PeerEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()
	subs := b.subscribers[networkID]
	for i, s := range subs {
		if s == ch {
			b.subscribers[networkID] = append(subs[:i], subs[i+1:]...)
			close(s)
			return
		}
	}
}

// Publish sends an event to all Watch subscribers in the network.
// Non-blocking: drops if subscriber channel is full.
func (b *Bus) Publish(networkID string, ev *coordv1.PeerEvent) {
	b.mu.RLock()
	subs := b.subscribers[networkID]
	b.mu.RUnlock()
	for _, ch := range subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

// SubscribeSignals returns a channel that receives signals addressed to peerID.
// Signals held for peerID while it had no subscriber are delivered first.
func (b *Bus) SubscribeSignals(peerID string) <-chan signalMsg {
	ch := make(chan signalMsg, 64)
	b.mu.Lock()
	b.signals[peerID] = append(b.signals[peerID], ch)
	held := b.pending[peerID]
	delete(b.pending, peerID)
	cutoff := b.now().Add(-pendingSignalTTL)
	for _, p := range held {
		if p.at.After(cutoff) {
			ch <- p.msg // cannot block: len(held) <= maxPendingPerPeer < cap(ch)
		}
	}
	b.mu.Unlock()
	return ch
}

// UnsubscribeSignals removes and closes a signal channel.
func (b *Bus) UnsubscribeSignals(peerID string, ch <-chan signalMsg) {
	b.mu.Lock()
	defer b.mu.Unlock()
	sigs := b.signals[peerID]
	for i, s := range sigs {
		if s == ch {
			b.signals[peerID] = append(sigs[:i], sigs[i+1:]...)
			close(s)
			return
		}
	}
}

// SendSignal delivers a signal to all subscribers for toPeerID.
// Non-blocking: drops if channel full.
//
// If toPeerID has no subscriber and hold is true (the caller checked that the
// recipient is a registered peer), the signal is kept in memory for up to
// pendingSignalTTL and delivered when the recipient subscribes. Otherwise it
// is dropped, as before.
func (b *Bus) SendSignal(from, to string, payload []byte, hold bool) {
	msg := signalMsg{FromPeerID: from, ToPeerID: to, Payload: payload}
	b.mu.Lock()
	defer b.mu.Unlock()
	sigs := b.signals[to]
	if len(sigs) == 0 {
		if hold {
			b.holdLocked(msg)
		}
		return
	}
	for _, ch := range sigs {
		select {
		case ch <- msg:
		default:
		}
	}
}

// holdLocked queues msg for a recipient that is not subscribed. b.mu must be held.
func (b *Bus) holdLocked(msg signalMsg) {
	now := b.now()
	cutoff := now.Add(-pendingSignalTTL)
	if _, ok := b.pending[msg.ToPeerID]; !ok && len(b.pending) >= maxPendingRecipients {
		for id, held := range b.pending { // make room: forget recipients whose signals all expired
			if len(held) == 0 || !held[len(held)-1].at.After(cutoff) {
				delete(b.pending, id)
			}
		}
		if len(b.pending) >= maxPendingRecipients {
			return
		}
	}
	held := b.pending[msg.ToPeerID][:0:0]
	for _, p := range b.pending[msg.ToPeerID] {
		if p.at.After(cutoff) {
			held = append(held, p)
		}
	}
	held = append(held, pendingSignal{msg: msg, at: now})
	if len(held) > maxPendingPerPeer {
		held = held[len(held)-maxPendingPerPeer:]
	}
	b.pending[msg.ToPeerID] = held
}

// DropPendingSignals forgets signals held for peerID (e.g. when it leaves).
func (b *Bus) DropPendingSignals(peerID string) {
	b.mu.Lock()
	delete(b.pending, peerID)
	b.mu.Unlock()
}
