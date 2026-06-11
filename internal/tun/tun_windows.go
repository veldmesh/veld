// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
//go:build windows

package tun

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

type windowsTUN struct {
	dev  wgtun.Device
	name string
	addr netip.Prefix
	mtu  int
}

// CreateTUN creates a Wintun adapter, assigns ip to it, and brings it up.
// Requires administrator privileges; wintun.dll must be on PATH or next to the binary.
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

	if err := windowsConfigureIface(realName, ip); err != nil {
		dev.Close()
		return nil, err
	}

	return &windowsTUN{dev: dev, name: realName, addr: ip, mtu: mtu}, nil
}

// windowsConfigureIface assigns ip to the named adapter via netsh.
func windowsConfigureIface(name string, ip netip.Prefix) error {
	addr := ip.Addr().String()
	mask := net.CIDRMask(ip.Bits(), ip.Addr().BitLen())
	netmask := fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])

	out, err := exec.Command(
		"netsh", "interface", "ip", "set", "address",
		"name="+name, "source=static", "address="+addr, "mask="+netmask,
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh addr %s: %w: %s", name, err, out)
	}

	return nil
}

func (t *windowsTUN) Read(p []byte) (int, error) {
	bufs := [][]byte{p}
	sizes := []int{0}
	_, err := t.dev.Read(bufs, sizes, 0)
	if err != nil {
		return 0, err
	}
	return sizes[0], nil
}

func (t *windowsTUN) Write(p []byte) (int, error) {
	_, err := t.dev.Write([][]byte{p}, 0)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (t *windowsTUN) Close() error       { return t.dev.Close() }
func (t *windowsTUN) Name() string       { return t.name }
func (t *windowsTUN) Addr() netip.Prefix { return t.addr }
func (t *windowsTUN) MTU() int           { return t.mtu }
