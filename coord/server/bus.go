// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"sync"

	coordv1 "github.com/veldmesh/veld/gen/veld/coord/v1"
)

// signalMsg is an opaque signal (ICE candidate etc.) from one peer to another.
type signalMsg struct {
	FromPeerID string
	ToPeerID   string
	Payload    []byte
}

// Bus is an in-memory fanout bus for PeerEvents and peer-to-peer signals.
// Each Watch subscriber gets its own channel; signals are delivered directly
// to the target peer's subscriber(s).
type Bus struct {
	mu          sync.RWMutex
	subscribers map[string][]chan *coordv1.PeerEvent // key: networkID
	signals     map[string][]chan signalMsg           // key: peerID (recipient)
}

// NewBus creates an empty Bus.
func NewBus() *Bus {
	return &Bus{
		subscribers: make(map[string][]chan *coordv1.PeerEvent),
		signals:     make(map[string][]chan signalMsg),
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
func (b *Bus) SubscribeSignals(peerID string) <-chan signalMsg {
	ch := make(chan signalMsg, 64)
	b.mu.Lock()
	b.signals[peerID] = append(b.signals[peerID], ch)
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
func (b *Bus) SendSignal(from, to string, payload []byte) {
	msg := signalMsg{FromPeerID: from, ToPeerID: to, Payload: payload}
	b.mu.RLock()
	sigs := b.signals[to]
	b.mu.RUnlock()
	for _, ch := range sigs {
		select {
		case ch <- msg:
		default:
		}
	}
}
