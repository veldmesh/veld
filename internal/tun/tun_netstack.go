// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
//go:build userspace

package tun

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"

	wgtun "golang.zx2c4.com/wireguard/tun"
	wgnetstack "golang.zx2c4.com/wireguard/tun/netstack"
)

// NetstackTUN implements the TUN interface using gVisor's netstack.
// It runs entirely in userspace without requiring root or a TUN device.
type NetstackTUN struct {
	dev      wgtun.Device
	netstack *wgnetstack.Net
	name     string
	addr     netip.Prefix
	mtu      int
	mu       sync.Mutex
	closed   bool
}

// createNetstackTUN creates a userspace TUN device backed by gVisor netstack.
// It does not require root, CAP_NET_ADMIN, or a TUN device.
// The addr parameter specifies the VPN address and prefix (e.g., "10.100.0.1/24").
// The netstack will be configured with this address and default routes.
func createNetstackTUN(name string, addr netip.Prefix, mtu int) (TUN, error) {
	if mtu <= 0 {
		mtu = 1420
	}

	localAddrs := []netip.Addr{addr.Addr()}
	// No DNS servers configured by default; applications using the netstack
	// for DNS resolution should configure their own resolvers.

	dev, netstack, err := wgnetstack.CreateNetTUN(localAddrs, nil, mtu)
	if err != nil {
		return nil, err
	}

	realName, err := dev.Name()
	if err != nil {
		_ = dev.Close()
		return nil, err
	}

	if name != "" {
		realName = name
	}

	return &NetstackTUN{
		dev:      dev,
		netstack: netstack,
		name:     realName,
		addr:     addr,
		mtu:      mtu,
	}, nil
}

// CreateNetstackTUN is the exported version of createNetstackTUN for use in tests
// and external callers that have the userspace build tag.
func CreateNetstackTUN(name string, addr netip.Prefix, mtu int) (TUN, error) {
	return createNetstackTUN(name, addr, mtu)
}

// Read reads an outbound IP packet from the netstack.
// Implements the TUN interface for the dispatcher's tunLoop.
func (t *NetstackTUN) Read(p []byte) (int, error) {
	t.mu.Lock()
	closed := t.closed
	t.mu.Unlock()
	if closed {
		return 0, ErrClosed
	}

	bufs := [][]byte{p}
	sizes := []int{0}
	_, err := t.dev.Read(bufs, sizes, 0)
	if err != nil {
		return 0, err
	}
	return sizes[0], nil
}

// Write writes an inbound IP packet to the netstack.
// Implements the TUN interface for the dispatcher's udpLoop.
func (t *NetstackTUN) Write(p []byte) (int, error) {
	t.mu.Lock()
	closed := t.closed
	t.mu.Unlock()
	if closed {
		return 0, ErrClosed
	}

	_, err := t.dev.Write([][]byte{p}, 0)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close closes the netstack TUN device.
func (t *NetstackTUN) Close() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	t.mu.Unlock()

	return t.dev.Close()
}

func (t *NetstackTUN) Name() string       { return t.name }
func (t *NetstackTUN) Addr() netip.Prefix { return t.addr }
func (t *NetstackTUN) MTU() int           { return t.mtu }

// DialContext dials a TCP connection through the netstack.
// This allows applications to make outbound connections using the VPN address.
func (t *NetstackTUN) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if t.netstack == nil {
		return nil, errors.New("netstack not initialized")
	}
	return t.netstack.DialContext(ctx, network, address)
}

// Dial dials a TCP connection through the netstack (without context).
func (t *NetstackTUN) Dial(network, address string) (net.Conn, error) {
	if t.netstack == nil {
		return nil, errors.New("netstack not initialized")
	}
	return t.netstack.Dial(network, address)
}

// ListenTCP listens for incoming TCP connections on the VPN address.
// Returns a gVisor netstack TCP listener (implements net.Listener).
func (t *NetstackTUN) ListenTCP(addr *net.TCPAddr) (net.Listener, error) {
	if t.netstack == nil {
		return nil, errors.New("netstack not initialized")
	}
	return t.netstack.ListenTCP(addr)
}

// ListenTCPAddrPort listens for incoming TCP connections on the VPN address.
// Returns a gVisor netstack TCP listener (implements net.Listener).
func (t *NetstackTUN) ListenTCPAddrPort(addr netip.AddrPort) (net.Listener, error) {
	if t.netstack == nil {
		return nil, errors.New("netstack not initialized")
	}
	return t.netstack.ListenTCPAddrPort(addr)
}

// ListenUDP listens for incoming UDP packets on the VPN address.
// Returns a gVisor netstack UDP connection (implements net.PacketConn).
func (t *NetstackTUN) ListenUDP(laddr *net.UDPAddr) (net.PacketConn, error) {
	if t.netstack == nil {
		return nil, errors.New("netstack not initialized")
	}
	return t.netstack.ListenUDP(laddr)
}

// ListenUDPAddrPort listens for incoming UDP packets on the VPN address.
// Returns a gVisor netstack UDP connection (implements net.PacketConn).
func (t *NetstackTUN) ListenUDPAddrPort(laddr netip.AddrPort) (net.PacketConn, error) {
	if t.netstack == nil {
		return nil, errors.New("netstack not initialized")
	}
	return t.netstack.ListenUDPAddrPort(laddr)
}
