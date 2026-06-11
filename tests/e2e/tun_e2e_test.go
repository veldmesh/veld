// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package e2e_test

import (
	"net/netip"
	"testing"

	"github.com/veldmesh/veld/internal/tun"
)

// TestMemTUN_EndToEnd exercises both channels of MemTUN:
//   - Inject → Read (outbound direction: test → dispatcher tunLoop)
//   - Write → ReadDelivered (inbound direction: dispatcher udpLoop → test)
func TestMemTUN_EndToEnd(t *testing.T) {
	prefixA, err := netip.ParsePrefix("10.100.0.1/24")
	if err != nil {
		t.Fatalf("parse prefix: %v", err)
	}

	dev := tun.NewMemTUN("e2e0", prefixA, 1420)
	defer dev.Close()

	packets := []struct {
		name string
		pkt  []byte
	}{
		{"icmp", []byte{0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x40, 0x00, 0x40, 0x01, 0x00, 0x00, 0x0a, 0x64, 0x00, 0x01, 0x0a, 0x64, 0x00, 0x02}},
		{"tcp", []byte{0x45, 0x00, 0x00, 0x28, 0x00, 0x02, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0x0a, 0x64, 0x00, 0x01, 0x0a, 0x64, 0x00, 0x02}},
		{"udp", []byte{0x45, 0x00, 0x00, 0x20, 0x00, 0x03, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0x0a, 0x64, 0x00, 0x01, 0x0a, 0x64, 0x00, 0x02}},
	}

	buf := make([]byte, 1500)
	for _, tc := range packets {
		t.Run(tc.name, func(t *testing.T) {
			// Outbound direction: Inject then dispatcher Read
			n, err := dev.Inject(tc.pkt)
			if err != nil {
				t.Fatalf("Inject: %v", err)
			}
			if n != len(tc.pkt) {
				t.Errorf("Inject n=%d, want %d", n, len(tc.pkt))
			}
			n, err = dev.Read(buf)
			if err != nil {
				t.Fatalf("Read: %v", err)
			}
			if string(buf[:n]) != string(tc.pkt) {
				t.Errorf("Inject→Read mismatch: got %x, want %x", buf[:n], tc.pkt)
			}

			// Inbound direction: dispatcher Write then ReadDelivered
			if _, err := dev.Write(tc.pkt); err != nil {
				t.Fatalf("Write: %v", err)
			}
			n, err = dev.ReadDelivered(buf)
			if err != nil {
				t.Fatalf("ReadDelivered: %v", err)
			}
			if string(buf[:n]) != string(tc.pkt) {
				t.Errorf("Write→ReadDelivered mismatch: got %x, want %x", buf[:n], tc.pkt)
			}
		})
	}
}

// TestMemTUN_EndToEnd_SessionIntegration verifies MemTUN satisfies the TUN interface
// and models the correct bidirectional flow between two virtual interfaces.
func TestMemTUN_EndToEnd_SessionIntegration(t *testing.T) {
	prefix, err := netip.ParsePrefix("10.100.0.1/24")
	if err != nil {
		t.Fatalf("parse prefix: %v", err)
	}

	var _ tun.TUN = tun.NewMemTUN("iface", prefix, 1420)

	devA := tun.NewMemTUN("tunA", prefix, 1420)
	defer devA.Close()

	prefixB, _ := netip.ParsePrefix("10.100.0.2/24")
	devB := tun.NewMemTUN("tunB", prefixB, 1420)
	defer devB.Close()

	// Simulate: test injects outbound packet into A, dispatcher reads it, forwards to B.
	payload := []byte("test ip packet payload")
	if _, err := devA.Inject(payload); err != nil {
		t.Fatalf("devA.Inject: %v", err)
	}

	buf := make([]byte, 1500)
	n, err := devA.Read(buf)
	if err != nil {
		t.Fatalf("devA.Read: %v", err)
	}

	// Dispatcher delivers to B (simulating udpLoop after decryption).
	if _, err := devB.Write(buf[:n]); err != nil {
		t.Fatalf("devB.Write: %v", err)
	}

	n2, err := devB.ReadDelivered(buf)
	if err != nil {
		t.Fatalf("devB.ReadDelivered: %v", err)
	}
	if string(buf[:n2]) != string(payload) {
		t.Errorf("forwarded packet mismatch: got %q, want %q", buf[:n2], payload)
	}
}
