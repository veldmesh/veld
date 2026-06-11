// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package dataplane

import (
	"errors"
	"net"
	"net/netip"
	"sync"

	"github.com/veldmesh/veld/internal/peer"
	"github.com/veldmesh/veld/internal/session"
	"github.com/veldmesh/veld/internal/tun"
)

const (
	maxMTU      = 1500
	authTagSize = 16 // ChaCha20-Poly1305 tag
	udpBufSize  = HeaderSize + maxMTU + authTagSize
)

// Dispatcher routes encrypted packets between TUN and UDP.
type Dispatcher struct {
	tun   tun.TUN
	conn  net.PacketConn
	peers *peer.Table

	// OnHandshakeRequired is called when a TUN packet is destined for a peer
	// that has no active session. The packet is already in the peer's hold queue.
	// The caller must eventually call entry.SetSession to drain the hold queue.
	// May be nil (hold queue fills and drops if no handler registered).
	OnHandshakeRequired func(entry *peer.Entry)

	// OnRekeyRequired is called when the current session hits the nonce threshold
	// (2^32 packets). The packet is already in the peer's hold queue. The caller
	// must clear the old session and initiate a fresh handshake — SetSession will
	// drain the hold queue once the new session is ready.
	// May be nil (packets queued until queue is full, then dropped).
	OnRekeyRequired func(entry *peer.Entry)

	// OnHandshakePacket is called for TypeHandshakeInit and TypeHandshakeResp packets.
	// pkt is the full wire packet (including 16-byte header); addr is the sender.
	OnHandshakePacket func(pkt []byte, addr net.Addr)

	// OnNATProbePacket is called for TypeNATProbe packets.
	// pkt is the full wire packet (including 16-byte header); addr is the sender.
	OnNATProbePacket func(pkt []byte, addr net.Addr)

	stopOnce sync.Once
	wg       sync.WaitGroup
}

// New creates a Dispatcher. Call Start to launch the I/O goroutines.
func New(t tun.TUN, conn net.PacketConn, peers *peer.Table) *Dispatcher {
	return &Dispatcher{
		tun:   t,
		conn:  conn,
		peers: peers,
	}
}

// Start launches the TUN→UDP and UDP→TUN goroutines.
func (d *Dispatcher) Start() {
	d.wg.Add(2)
	go d.tunLoop()
	go d.udpLoop()
}

// Stop closes the TUN and UDP conn, causing both loops to exit.
// Safe to call multiple times.
func (d *Dispatcher) Stop() {
	d.stopOnce.Do(func() {
		if d.tun != nil {
			d.tun.Close()
		}
		d.conn.Close()
	})
}

// Wait blocks until both loops have exited.
func (d *Dispatcher) Wait() {
	d.wg.Wait()
}

// FlushHoldQueue drains the peer's hold queue and sends all held packets as
// encrypted data over UDP. Called by handshake.Manager.OnSessionEstablished.
func (d *Dispatcher) FlushHoldQueue(entry *peer.Entry) {
	sess := entry.GetSession()
	if sess == nil {
		return
	}
	ep := entry.GetEndpoint()
	if !ep.IsValid() {
		return
	}
	for _, pkt := range entry.DrainQueue() {
		nonce, ct, err := sess.Encrypt(pkt)
		if err != nil {
			continue
		}
		d.conn.WriteTo(buildDataPacket(nonce, ct), net.UDPAddrFromAddrPort(ep))
	}
}

// tunLoop reads raw IP packets from TUN and sends them encrypted over UDP.
// If TUN is nil (coord mode before VPN address assignment), the loop exits immediately.
func (d *Dispatcher) tunLoop() {
	defer d.wg.Done()
	if d.tun == nil {
		return
	}
	plainBuf := make([]byte, maxMTU)

	for {
		n, err := d.tun.Read(plainBuf)
		if err != nil {
			return
		}
		if n == 0 {
			continue
		}
		d.handleTunPacket(plainBuf[:n])
	}
}

func (d *Dispatcher) handleTunPacket(pkt []byte) {
	destIP, ok := extractDestIP(pkt)
	if !ok {
		return
	}

	entry, ok := d.peers.LookupByVPN(destIP)
	if !ok {
		return
	}

	sess := entry.GetSession()
	if sess == nil {
		entry.Enqueue(pkt)
		if d.OnHandshakeRequired != nil {
			d.OnHandshakeRequired(entry)
		}
		return
	}

	nonce, ct, err := sess.Encrypt(pkt)
	if err != nil {
		if errors.Is(err, session.ErrRekeyRequired) {
			entry.Enqueue(pkt)
			if d.OnRekeyRequired != nil {
				d.OnRekeyRequired(entry)
			}
		}
		return
	}

	ep := entry.GetEndpoint()
	if !ep.IsValid() {
		return
	}

	udpPkt := buildDataPacket(nonce, ct)
	d.conn.WriteTo(udpPkt, net.UDPAddrFromAddrPort(ep))
}

// udpLoop reads UDP packets and injects decrypted IP packets into TUN.
func (d *Dispatcher) udpLoop() {
	defer d.wg.Done()
	recvBuf := make([]byte, udpBufSize)

	for {
		n, addr, err := d.conn.ReadFrom(recvBuf)
		if err != nil {
			return
		}
		if n < HeaderSize {
			continue
		}
		d.handleUDPPacket(recvBuf[:n], addr)
	}
}

func (d *Dispatcher) handleUDPPacket(pkt []byte, addr net.Addr) {
	pktType, _, nonce := parseHeader(pkt[:HeaderSize])
	payload := pkt[HeaderSize:]

	switch pktType {
	case TypeData:
		ep, ok := addrToAddrPort(addr)
		if !ok {
			return
		}
		entry, ok := d.peers.LookupByEndpoint(ep)
		if !ok {
			return
		}
		sess := entry.GetSession()
		if sess == nil {
			return
		}
		plain, err := sess.Decrypt(nonce, payload)
		if err != nil || plain == nil {
			return
		}
		entry.Touch()
		if d.tun != nil {
			d.tun.Write(plain)
		}

	case TypeKeepalive:
		ep, ok := addrToAddrPort(addr)
		if !ok {
			return
		}
		if entry, ok := d.peers.LookupByEndpoint(ep); ok {
			entry.Touch()
		}

	case TypeHandshakeInit, TypeHandshakeResp:
		if d.OnHandshakePacket != nil {
			pktCopy := make([]byte, len(pkt))
			copy(pktCopy, pkt)
			d.OnHandshakePacket(pktCopy, addr)
		}

	case TypeNATProbe:
		if d.OnNATProbePacket != nil {
			pktCopy := make([]byte, len(pkt))
			copy(pktCopy, pkt)
			d.OnNATProbePacket(pktCopy, addr)
		}
	}
}

// extractDestIP reads the destination IP from a raw IPv4 or IPv6 packet.
func extractDestIP(pkt []byte) (netip.Addr, bool) {
	if len(pkt) < 1 {
		return netip.Addr{}, false
	}
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom4([4]byte(pkt[16:20])), true
	case 6:
		if len(pkt) < 40 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom16([16]byte(pkt[24:40])), true
	}
	return netip.Addr{}, false
}

// addrToAddrPort converts a net.Addr to netip.AddrPort.
// Normalizes IPv4-mapped IPv6 addresses to plain IPv4 so map lookups
// match entries stored via netip.MustParseAddrPort("x.x.x.x:p").
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
