// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
//go:build windows

package tun_test

import (
	"net/netip"
	"testing"

	"github.com/veldmesh/veld/internal/tun"
)

func TestCreateTUN_Windows(t *testing.T) {
	prefix, err := netip.ParsePrefix("10.100.99.1/24")
	if err != nil {
		t.Fatalf("parse prefix: %v", err)
	}

	dev, err := tun.CreateTUN("veld-test0", prefix, 1420)
	if err != nil {
		// wintun requires admin + wintun.dll; skip gracefully in unprivileged CI
		t.Skipf("CreateTUN: %v (requires administrator + wintun.dll)", err)
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

func TestCreateTUN_Windows_WriteRead(t *testing.T) {
	prefix, err := netip.ParsePrefix("10.100.98.1/24")
	if err != nil {
		t.Fatalf("parse prefix: %v", err)
	}

	dev, err := tun.CreateTUN("veld-test1", prefix, 1420)
	if err != nil {
		t.Skipf("CreateTUN: %v (requires administrator + wintun.dll)", err)
	}
	defer dev.Close()

	pkt := make([]byte, 28)
	pkt[0] = 0x45 // IPv4, IHL=5
	pkt[9] = 0x11 // UDP
	n, err := dev.Write(pkt)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(pkt) {
		t.Errorf("Write: got n=%d, want %d", n, len(pkt))
	}
}
