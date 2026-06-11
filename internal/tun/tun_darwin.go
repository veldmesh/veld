// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
//go:build darwin

package tun

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

type darwinTUN struct {
	dev  wgtun.Device
	name string
	addr netip.Prefix
	mtu  int
}

// CreateTUN creates a macOS utun device, assigns ip to it, and brings it up.
// Requires root or an entitlement that allows virtual network interface creation.
func CreateTUN(name string, ip netip.Prefix, mtu int) (TUN, error) {
	dev, err := wgtun.CreateTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("tun create %s: %w", name, err)
	}

	realName, err := dev.Name()
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("tun get name: %w", err)
	}

	if err := darwinConfigureIface(realName, ip); err != nil {
		dev.Close()
		return nil, err
	}

	return &darwinTUN{dev: dev, name: realName, addr: ip, mtu: mtu}, nil
}

// darwinConfigureIface assigns ip to the named utun interface via ifconfig.
func darwinConfigureIface(name string, ip netip.Prefix) error {
	addr := ip.Addr().String()
	mask := net.CIDRMask(ip.Bits(), ip.Addr().BitLen())
	netmask := fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])

	// macOS utun interfaces require a destination address in ifconfig; using
	// the same address for both src and dst gives subnet (not pure p2p) semantics.
	out, err := exec.Command("ifconfig", name, "inet", addr, addr, "netmask", netmask).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ifconfig addr %s: %w: %s", name, err, out)
	}

	if out, err = exec.Command("ifconfig", name, "up").CombinedOutput(); err != nil {
		return fmt.Errorf("ifconfig up %s: %w: %s", name, err, out)
	}

	return nil
}

func (t *darwinTUN) Read(p []byte) (int, error) {
	bufs := [][]byte{p}
	sizes := []int{0}
	_, err := t.dev.Read(bufs, sizes, 0)
	if err != nil {
		return 0, err
	}
	return sizes[0], nil
}

func (t *darwinTUN) Write(p []byte) (int, error) {
	_, err := t.dev.Write([][]byte{p}, 0)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (t *darwinTUN) Close() error       { return t.dev.Close() }
func (t *darwinTUN) Name() string       { return t.name }
func (t *darwinTUN) Addr() netip.Prefix { return t.addr }
func (t *darwinTUN) MTU() int           { return t.mtu }
