// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT

package relay

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sync"
)

// Proxy bridges a relay channel to the local data plane. It listens on a
// loopback UDP socket; datagrams the daemon sends to the proxy address are
// framed and forwarded over the relay channel, and datagrams arriving from
// the relay channel are injected into the local data-plane socket.
//
// To the dispatcher, the relay path looks like an ordinary peer endpoint:
// the peer table entry's endpoint is simply set to the proxy's local address.
type Proxy struct {
	stream *Conn
	udp    *net.UDPConn
	target *net.UDPAddr // local data-plane socket address

	closeOnce sync.Once
	done      chan struct{}
}

// NewProxy creates a Proxy that forwards datagrams between stream (a paired
// relay channel from Dial) and the local data-plane socket at target
// (typically "127.0.0.1:<daemon UDP port>").
//
// The proxy starts forwarding immediately. Set the peer's endpoint to
// LocalAddr() and initiate the Noise handshake through it.
func NewProxy(stream *Conn, target *net.UDPAddr) (*Proxy, error) {
	u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		return nil, fmt.Errorf("relay proxy listen: %w", err)
	}
	p := &Proxy{stream: stream, udp: u, target: target, done: make(chan struct{})}
	go p.udpToStream()
	go p.streamToUDP()
	return p, nil
}

// LocalAddr returns the loopback address the daemon should use as the
// peer's endpoint while the relay path is active.
func (p *Proxy) LocalAddr() netip.AddrPort {
	return p.udp.LocalAddr().(*net.UDPAddr).AddrPort()
}

// Close tears down the proxy and the relay channel.
func (p *Proxy) Close() error {
	p.closeOnce.Do(func() {
		close(p.done)
		_ = p.udp.Close()
		_ = p.stream.Close()
	})
	return nil
}

// udpToStream reads datagrams from the dispatcher (via the loopback socket)
// and forwards each as one framed message over the relay channel.
// Wire framing inside the channel: [uint16 big-endian length][datagram].
func (p *Proxy) udpToStream() {
	buf := make([]byte, 65535)
	for {
		n, _, err := p.udp.ReadFromUDP(buf)
		if err != nil {
			_ = p.Close()
			return
		}
		frame := make([]byte, 2+n)
		binary.BigEndian.PutUint16(frame[0:2], uint16(n))
		copy(frame[2:], buf[:n])
		if err := p.stream.WriteMessage(frame); err != nil {
			_ = p.Close()
			return
		}
	}
}

// streamToUDP reads framed datagrams from the relay channel and injects them
// into the local data-plane socket. The dispatcher sees them as arriving from
// this proxy's address (the peer's relay endpoint).
func (p *Proxy) streamToUDP() {
	for {
		frame, err := p.stream.ReadMessage()
		if err != nil {
			_ = p.Close()
			return
		}
		if len(frame) < 2 {
			continue
		}
		n := int(binary.BigEndian.Uint16(frame[0:2]))
		if n != len(frame)-2 {
			continue
		}
		if _, err := p.udp.WriteToUDP(frame[2:], p.target); err != nil {
			_ = p.Close()
			return
		}
	}
}
