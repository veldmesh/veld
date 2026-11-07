// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
//go:build !linux && !darwin && !windows

package tun

import (
	"context"
	"errors"
	"net"
	"net/netip"
)

var errUnsupported = errors.New("tun: CreateTUN not supported on this OS (supported: linux, darwin, windows)")

// DefaultIfaceName returns the generic default interface name. CreateTUN
// fails on unsupported platforms anyway; the value only keeps config
// handling uniform across builds.
func DefaultIfaceName() string { return "veld0" }

// createTUN is not implemented on this platform.
func createTUN(_ string, _ netip.Prefix, _ int) (TUN, error) {
	return nil, errUnsupported
}

// unsupportedTUN is a stub TUN implementation for unsupported platforms.
type unsupportedTUN struct{}

func (t *unsupportedTUN) Read(p []byte) (int, error)  { return 0, errUnsupported }
func (t *unsupportedTUN) Write(p []byte) (int, error) { return 0, errUnsupported }
func (t *unsupportedTUN) Close() error                { return errUnsupported }
func (t *unsupportedTUN) Name() string                { return "" }
func (t *unsupportedTUN) Addr() netip.Prefix          { return netip.Prefix{} }
func (t *unsupportedTUN) MTU() int                    { return 0 }
func (t *unsupportedTUN) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return nil, errUnsupported
}
func (t *unsupportedTUN) Dial(network, address string) (net.Conn, error) {
	return nil, errUnsupported
}
func (t *unsupportedTUN) ListenTCP(addr *net.TCPAddr) (net.Listener, error) {
	return nil, errUnsupported
}
func (t *unsupportedTUN) ListenTCPAddrPort(addr netip.AddrPort) (net.Listener, error) {
	return nil, errUnsupported
}
func (t *unsupportedTUN) ListenUDP(laddr *net.UDPAddr) (net.PacketConn, error) {
	return nil, errUnsupported
}
func (t *unsupportedTUN) ListenUDPAddrPort(laddr netip.AddrPort) (net.PacketConn, error) {
	return nil, errUnsupported
}
