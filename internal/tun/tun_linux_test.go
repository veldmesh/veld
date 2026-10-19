// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
//go:build linux

package tun_test

import (
	"net/netip"
	"os"
	"testing"

	"github.com/veldmesh/veld/internal/tun"
)

// hasTunDevice reports whether the kernel TUN device exists. Privileged
// containers can run as root yet lack /dev/net/tun, in which case device
// creation cannot work and the test must skip rather than fail.
func hasTunDevice() bool {
	_, err := os.Stat("/dev/net/tun")
	return err == nil
}

// TestDefaultIfaceName_Linux pins the default Linux TUN name. "veld0" is a
// dedicated name: TUNSETIFF with an already-taken name (OpenVPN's tun0)
// fails with EEXIST, and the name must not match the generic tun|tap|utun|wg
// patterns so self-exclusion in VPN detection stays trivial.
func TestDefaultIfaceName_Linux(t *testing.T) {
	if got := tun.DefaultIfaceName(); got != "veld0" {
		t.Errorf("DefaultIfaceName() = %q, want veld0", got)
	}
}

func TestCreateTUN_Linux(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root (CAP_NET_ADMIN)")
	}
	if !hasTunDevice() {
		t.Skip("requires /dev/net/tun")
	}

	prefix, err := netip.ParsePrefix("10.100.99.1/24")
	if err != nil {
		t.Fatalf("parse prefix: %v", err)
	}

	dev, err := tun.CreateTUN("tuntst0", prefix, 1420)
	if err != nil {
		t.Fatalf("CreateTUN: %v", err)
	}
	defer dev.Close()

	if dev.Name() == "" {
		t.Error("Name should not be empty")
	}
	if dev.Addr() != prefix {
		t.Errorf("Addr: got %v, want %v", dev.Addr(), prefix)
	}
	if dev.MTU() != 1420 {
		t.Errorf("MTU: got %d, want 1420", dev.MTU())
	}
}

func TestCreateTUN_Linux_WriteRead(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root (CAP_NET_ADMIN)")
	}
	if !hasTunDevice() {
		t.Skip("requires /dev/net/tun")
	}

	prefix, err := netip.ParsePrefix("10.100.98.1/24")
	if err != nil {
		t.Fatalf("parse prefix: %v", err)
	}

	dev, err := tun.CreateTUN("tuntst1", prefix, 1420)
	if err != nil {
		t.Fatalf("CreateTUN: %v", err)
	}
	defer dev.Close()

	// Write a minimal IPv4 packet and verify no error.
	// (Reading it back would require the OS to echo it, which only happens for loopback.)
	pkt := make([]byte, 28)
	pkt[0] = 0x45 // IPv4, IHL=5
	pkt[9] = 0x11 // UDP protocol
	n, err := dev.Write(pkt)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(pkt) {
		t.Errorf("Write: got n=%d, want %d", n, len(pkt))
	}
}
