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

type NetstackTUN struct {
	dev      wgtun.Device
	netstack *wgnetstack.Net
	name     string
	addr     netip.Prefix
	mtu      int
	mu       sync.Mutex
	closed   bool
	cond     *sync.Cond
	inFlight int
}

func createNetstackTUN(name string, addr netip.Prefix, mtu int) (TUN, error) {
	if mtu <= 0 {
		mtu = 1420
	}
	localAddrs := []netip.Addr{addr.Addr()}
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
	t := &NetstackTUN{dev: dev, netstack: netstack, name: realName, addr: addr, mtu: mtu}
	t.cond = sync.NewCond(&t.mu)
	return t, nil
}

func CreateNetstackTUN(name string, addr netip.Prefix, mtu int) (TUN, error) {
	return createNetstackTUN(name, addr, mtu)
}

func (t *NetstackTUN) Read(p []byte) (int, error) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return 0, ErrClosed
	}
	t.inFlight++
	t.mu.Unlock()

	bufs := [][]byte{p}
	sizes := []int{0}
	_, err := t.dev.Read(bufs, sizes, 0)

	t.mu.Lock()
	t.inFlight--
	if t.inFlight == 0 {
		t.cond.Broadcast()
	}
	t.mu.Unlock()

	if err != nil {
		return 0, err
	}
	return sizes[0], nil
}

func (t *NetstackTUN) Write(p []byte) (int, error) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return 0, ErrClosed
	}
	t.inFlight++
	t.mu.Unlock()

	_, err := t.dev.Write([][]byte{p}, 0)

	t.mu.Lock()
	t.inFlight--
	if t.inFlight == 0 {
		t.cond.Broadcast()
	}
	t.mu.Unlock()

	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (t *NetstackTUN) Close() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	t.mu.Unlock()

	// Close the device first, which will cause any blocking Read/Write to return errors.
	err := t.dev.Close()

	// Wait for any in-flight operations to complete.
	t.mu.Lock()
	for t.inFlight > 0 {
		t.cond.Wait()
	}
	t.mu.Unlock()

	return err
}

func (t *NetstackTUN) Name() string       { return t.name }
func (t *NetstackTUN) Addr() netip.Prefix { return t.addr }
func (t *NetstackTUN) MTU() int           { return t.mtu }

func (t *NetstackTUN) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if t.netstack == nil {
		return nil, errors.New("netstack not initialized")
	}
	return t.netstack.DialContext(ctx, network, address)
}

func (t *NetstackTUN) Dial(network, address string) (net.Conn, error) {
	if t.netstack == nil {
		return nil, errors.New("netstack not initialized")
	}
	return t.netstack.Dial(network, address)
}

func (t *NetstackTUN) ListenTCP(addr *net.TCPAddr) (net.Listener, error) {
	if t.netstack == nil {
		return nil, errors.New("netstack not initialized")
	}
	return t.netstack.ListenTCP(addr)
}

func (t *NetstackTUN) ListenTCPAddrPort(addr netip.AddrPort) (net.Listener, error) {
	if t.netstack == nil {
		return nil, errors.New("netstack not initialized")
	}
	return t.netstack.ListenTCPAddrPort(addr)
}

func (t *NetstackTUN) ListenUDP(laddr *net.UDPAddr) (net.PacketConn, error) {
	if t.netstack == nil {
		return nil, errors.New("netstack not initialized")
	}
	return t.netstack.ListenUDP(laddr)
}

func (t *NetstackTUN) ListenUDPAddrPort(laddr netip.AddrPort) (net.PacketConn, error) {
	if t.netstack == nil {
		return nil, errors.New("netstack not initialized")
	}
	return t.netstack.ListenUDPAddrPort(laddr)
}
