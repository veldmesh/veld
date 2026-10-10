// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package daemon

import (
	"net"
	"net/netip"
	"testing"

	"github.com/veldmesh/veld/internal/crypto"
	"github.com/veldmesh/veld/internal/peer"
	"github.com/veldmesh/veld/internal/tun"
)

// newTestDaemon builds a Daemon with real components but does not start it.
// A nil TUN mirrors coord mode at startup: the TUN is created only after
// the coordinator assigns the VPN address.
func newTestDaemon(t *testing.T, tdev tun.TUN) *Daemon {
	t.Helper()
	id, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	var networkID [16]byte
	return New(id, networkID, tdev, conn, peer.New())
}

func TestSelfInterfaceEmptyWithoutTUN(t *testing.T) {
	d := newTestDaemon(t, nil)
	if got := d.selfInterface(); got != "" {
		t.Errorf("selfInterface() = %q, want empty before the TUN exists", got)
	}
}

func TestSelfInterfaceFromStaticTUN(t *testing.T) {
	dev := tun.NewMemTUN("veld0", netip.MustParsePrefix("10.100.0.1/24"), 1420)
	d := newTestDaemon(t, dev)
	if got := d.selfInterface(); got != "veld0" {
		t.Errorf("selfInterface() = %q, want veld0", got)
	}
}

// TestSelfInterfaceResolvesTUNAfterConstruction is the coord-mode regression:
// the TUN appears only after the coordinator assigns the VPN address, so
// collision checks must resolve the interface name at check time. Capturing
// the name once at startup would pin the pre-TUN empty string forever and
// make every later check misattribute veld's own routes to a commercial VPN.
func TestSelfInterfaceResolvesTUNAfterConstruction(t *testing.T) {
	d := newTestDaemon(t, nil)
	if got := d.selfInterface(); got != "" {
		t.Fatalf("selfInterface() = %q, want empty before the TUN exists", got)
	}

	// The coordinator assigned the address; veld creates its TUN now.
	d.mu.Lock()
	d.tunDev = tun.NewMemTUN("veld1", netip.MustParsePrefix("10.100.0.1/24"), 1420)
	d.mu.Unlock()

	if got := d.selfInterface(); got != "veld1" {
		t.Errorf("selfInterface() = %q, want veld1 after the TUN was created", got)
	}
}
