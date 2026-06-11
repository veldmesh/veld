// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package tun_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/veldmesh/veld/internal/tun"
)

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("parse prefix %q: %v", s, err)
	}
	return p
}

// TestMemTUN_InjectReadDelivered verifies the primary test-path: Inject puts a packet
// in the dispatcher read queue; Write delivers it to the test read queue.
func TestMemTUN_InjectReadDelivered(t *testing.T) {
	m := tun.NewMemTUN("test0", mustPrefix(t, "10.100.0.1/24"), 1420)
	defer m.Close()

	// Inject an outbound packet — dispatcher tunLoop would pick this up via Read.
	want := []byte{0x45, 0x00, 0x00, 0x14}
	if _, err := m.Inject(want); err != nil {
		t.Fatalf("Inject: %v", err)
	}
	buf := make([]byte, 1500)
	n, err := m.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(buf[:n]) != string(want) {
		t.Errorf("Read: got %x, want %x", buf[:n], want)
	}

	// Write a delivered packet — dispatcher udpLoop would call Write; test uses ReadDelivered.
	if _, err := m.Write(want); err != nil {
		t.Fatalf("Write: %v", err)
	}
	n, err = m.ReadDelivered(buf)
	if err != nil {
		t.Fatalf("ReadDelivered: %v", err)
	}
	if string(buf[:n]) != string(want) {
		t.Errorf("ReadDelivered: got %x, want %x", buf[:n], want)
	}
}

func TestMemTUN_MultiplePackets(t *testing.T) {
	m := tun.NewMemTUN("test0", mustPrefix(t, "10.100.0.1/24"), 1420)
	defer m.Close()

	packets := [][]byte{
		{0x45, 0x00, 0x00, 0x01},
		{0x45, 0x00, 0x00, 0x02},
		{0x45, 0x00, 0x00, 0x03},
	}
	for _, pkt := range packets {
		m.Inject(pkt)
	}
	buf := make([]byte, 1500)
	for i, want := range packets {
		n, err := m.Read(buf)
		if err != nil {
			t.Fatalf("packet %d: Read: %v", i, err)
		}
		if string(buf[:n]) != string(want) {
			t.Errorf("packet %d: got %x, want %x", i, buf[:n], want)
		}
	}
}

func TestMemTUN_Metadata(t *testing.T) {
	addr := mustPrefix(t, "10.100.0.1/24")
	m := tun.NewMemTUN("tun99", addr, 1420)
	defer m.Close()

	if m.Name() != "tun99" {
		t.Errorf("Name: got %q, want %q", m.Name(), "tun99")
	}
	if m.Addr() != addr {
		t.Errorf("Addr: got %v, want %v", m.Addr(), addr)
	}
	if m.MTU() != 1420 {
		t.Errorf("MTU: got %d, want 1420", m.MTU())
	}
}

func TestMemTUN_Close_ReturnsError(t *testing.T) {
	m := tun.NewMemTUN("tun0", mustPrefix(t, "10.100.0.1/24"), 1420)

	if err := m.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	_, err := m.Inject([]byte{0x01})
	if err != tun.ErrClosed {
		t.Errorf("Inject after close: got %v, want ErrClosed", err)
	}
	_, err = m.Write([]byte{0x01})
	if err != tun.ErrClosed {
		t.Errorf("Write after close: got %v, want ErrClosed", err)
	}
}

func TestMemTUN_DoubleClose(t *testing.T) {
	m := tun.NewMemTUN("tun0", mustPrefix(t, "10.100.0.1/24"), 1420)
	m.Close()
	if err := m.Close(); err != nil {
		t.Errorf("double Close should not error: %v", err)
	}
}

func TestMemTUN_Read_Blocks_UntilInject(t *testing.T) {
	m := tun.NewMemTUN("tun0", mustPrefix(t, "10.100.0.1/24"), 1420)
	defer m.Close()

	want := []byte{0x45, 0x00, 0x00, 0x14}
	go func() {
		time.Sleep(10 * time.Millisecond)
		m.Inject(want)
	}()

	buf := make([]byte, 1500)
	n, err := m.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(buf[:n]) != string(want) {
		t.Errorf("got %x, want %x", buf[:n], want)
	}
}

func TestMemTUN_Read_Unblocks_OnClose(t *testing.T) {
	m := tun.NewMemTUN("tun0", mustPrefix(t, "10.100.0.1/24"), 1420)

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 1500)
		_, err := m.Read(buf)
		done <- err
	}()

	time.Sleep(10 * time.Millisecond)
	m.Close()

	select {
	case err := <-done:
		if err != tun.ErrClosed {
			t.Errorf("Read after close: got %v, want ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Read did not unblock after Close")
	}
}

func TestCreateTUN_PlatformBehavior(t *testing.T) {
	_, err := tun.CreateTUN("tuntst0", mustPrefix(t, "10.100.99.1/24"), 1420)
	if err == nil {
		t.Log("CreateTUN succeeded (Linux + root); this is expected only in privileged environments")
	}
}
