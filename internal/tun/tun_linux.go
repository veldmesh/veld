// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
//go:build linux

package tun

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
	wgtun "golang.zx2c4.com/wireguard/tun"
)

type linuxTUN struct {
	dev  wgtun.Device
	name string
	addr netip.Prefix
	mtu  int
}

// DefaultIfaceName is the default Linux TUN interface name. A dedicated
// name instead of the generic "tun0" matters for two reasons: TUNSETIFF
// with an already-taken name fails with EEXIST, so veld could not even
// start next to an OpenVPN-based VPN that owns tun0; and "veld0" does not
// match the generic tun|tap|utun|wg patterns used to spot VPN tunnels, so
// self-exclusion in coexistence checks is trivial and operators get a
// stable interface to reference in split-tunnel and firewall rules.
func DefaultIfaceName() string { return "veld0" }

// CreateTUN creates a Linux TUN device with the given name, assigns ip to it, and brings it up.
// Requires CAP_NET_ADMIN or root.
func CreateTUN(name string, ip netip.Prefix, mtu int) (TUN, error) {
	dev, err := wgtun.CreateTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("tun create %s: %w", name, err)
	}

	realName, err := dev.Name()
	if err != nil {
		_ = dev.Close()
		return nil, fmt.Errorf("tun get name: %w", err)
	}

	link, err := netlink.LinkByName(realName)
	if err != nil {
		_ = dev.Close()
		return nil, fmt.Errorf("netlink find %s: %w", realName, err)
	}

	nlAddr := &netlink.Addr{IPNet: prefixToIPNet(ip)}
	if err := netlink.AddrAdd(link, nlAddr); err != nil {
		_ = dev.Close()
		return nil, fmt.Errorf("netlink addr add %s on %s: %w", ip, realName, err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		_ = dev.Close()
		return nil, fmt.Errorf("netlink link up %s: %w", realName, err)
	}

	return &linuxTUN{dev: dev, name: realName, addr: ip, mtu: mtu}, nil
}

func (t *linuxTUN) Read(p []byte) (int, error) {
	bufs := [][]byte{p}
	sizes := []int{0}
	_, err := t.dev.Read(bufs, sizes, 0)
	if err != nil {
		return 0, err
	}
	return sizes[0], nil
}

func (t *linuxTUN) Write(p []byte) (int, error) {
	_, err := t.dev.Write([][]byte{p}, 0)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (t *linuxTUN) Close() error       { return t.dev.Close() }
func (t *linuxTUN) Name() string       { return t.name }
func (t *linuxTUN) Addr() netip.Prefix { return t.addr }
func (t *linuxTUN) MTU() int           { return t.mtu }

func prefixToIPNet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{
		IP:   net.IP(p.Addr().AsSlice()),
		Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen()),
	}
}
