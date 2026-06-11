// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package tun

import (
	"errors"
	"net/netip"
	"sync"
)

// TUN is a virtual network interface that carries raw IP packets.
type TUN interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	Close() error
	Name() string
	Addr() netip.Prefix
	MTU() int
}

// ErrClosed is returned by Read/Write after Close is called.
var ErrClosed = errors.New("tun: device closed")

// MemTUN is an in-memory TUN device for testing.
//
// It separates the two directions of packet flow so dispatcher goroutines
// and test goroutines never race on the same channel:
//
//   - injectCh: test → dispatcher (Inject writes; dispatcher Read reads)
//   - delivCh:  dispatcher → test  (dispatcher Write writes; ReadDelivered reads)
//
// The dispatcher code is unchanged: it calls Read/Write via the TUN interface.
// Test code uses Inject and ReadDelivered instead of Write and Read.
type MemTUN struct {
	name     string
	addr     netip.Prefix
	mtu      int
	injectCh chan []byte // outbound direction: test→tunLoop
	delivCh  chan []byte // inbound direction: udpLoop→test
	once     sync.Once
	closed   chan struct{}
}

// NewMemTUN creates an in-memory TUN for testing.
func NewMemTUN(name string, addr netip.Prefix, mtu int) *MemTUN {
	return &MemTUN{
		name:     name,
		addr:     addr,
		mtu:      mtu,
		injectCh: make(chan []byte, 256),
		delivCh:  make(chan []byte, 256),
		closed:   make(chan struct{}),
	}
}

// Read is called by the dispatcher's tunLoop to obtain the next outbound packet.
// It blocks until Inject provides a packet or the device is closed.
func (m *MemTUN) Read(p []byte) (int, error) {
	select {
	case pkt := <-m.injectCh:
		n := copy(p, pkt)
		return n, nil
	case <-m.closed:
		return 0, ErrClosed
	}
}

// Write is called by the dispatcher's udpLoop to deliver a decrypted inbound packet.
// Test code reads delivered packets via ReadDelivered.
func (m *MemTUN) Write(p []byte) (int, error) {
	select {
	case <-m.closed:
		return 0, ErrClosed
	default:
	}
	buf := make([]byte, len(p))
	copy(buf, p)
	select {
	case m.delivCh <- buf:
		return len(p), nil
	case <-m.closed:
		return 0, ErrClosed
	}
}

// Inject writes an outbound packet to be picked up by the dispatcher's tunLoop.
// Use this in tests instead of Write when simulating traffic from the local app.
func (m *MemTUN) Inject(p []byte) (int, error) {
	select {
	case <-m.closed:
		return 0, ErrClosed
	default:
	}
	buf := make([]byte, len(p))
	copy(buf, p)
	select {
	case m.injectCh <- buf:
		return len(p), nil
	case <-m.closed:
		return 0, ErrClosed
	}
}

// ReadDelivered reads a packet delivered by the dispatcher's udpLoop.
// Use this in tests to receive packets that arrived from a remote peer.
func (m *MemTUN) ReadDelivered(p []byte) (int, error) {
	select {
	case pkt := <-m.delivCh:
		n := copy(p, pkt)
		return n, nil
	case <-m.closed:
		return 0, ErrClosed
	}
}

func (m *MemTUN) Close() error {
	m.once.Do(func() { close(m.closed) })
	return nil
}

func (m *MemTUN) Name() string       { return m.name }
func (m *MemTUN) Addr() netip.Prefix { return m.addr }
func (m *MemTUN) MTU() int           { return m.mtu }
