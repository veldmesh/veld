// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
//go:build linux

package tun_test

import (
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

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

	// A UDP datagram sent to another address in the TUN subnet is routed into
	// the device and must come out of Read as one plain IPv4 packet.
	c, err := net.Dial("udp4", "10.100.98.2:9")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	go func() {
		for i := 0; i < 20; i++ {
			c.Write([]byte("ping"))
			time.Sleep(50 * time.Millisecond)
		}
	}()
	got := make(chan string, 1)
	go func() {
		buf := make([]byte, 1500)
		for {
			n, err := dev.Read(buf)
			if err != nil {
				got <- "Read: " + err.Error()
				return
			}
			if n >= 20 && buf[0]>>4 == 4 && buf[9] == 0x11 &&
				netip.AddrFrom4([4]byte(buf[16:20])) == netip.MustParseAddr("10.100.98.2") {
				got <- string(buf[n-4 : n])
				return
			}
		}
	}()
	select {
	case s := <-got:
		if s != "ping" {
			t.Errorf("read from TUN: got %q, want ping payload", s)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout reading a packet from the TUN")
	}
}
