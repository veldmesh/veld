// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package daemon

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/veldmesh/veld/internal/coexist"
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

// --- resolveIfaceName (node.iface_name -> TUN name to create) ---

func testPrintf(b *strings.Builder) coexist.Printf {
	return func(format string, args ...any) (int, error) {
		return fmt.Fprintf(b, format, args...)
	}
}

// TestResolveIfaceNameEmptyUsesPlatformDefault: a config without an
// explicit iface_name (what all new configs carry since the legacy tun0
// default was dropped) resolves to the platform default, without logging.
func TestResolveIfaceNameEmptyUsesPlatformDefault(t *testing.T) {
	var b strings.Builder
	if got := resolveIfaceName(testPrintf(&b), ""); got != tun.DefaultIfaceName() {
		t.Errorf("empty iface_name must resolve to the platform default %q, got %q", tun.DefaultIfaceName(), got)
	}
	if b.Len() != 0 {
		t.Errorf("empty iface_name must not log, got:\n%s", b.String())
	}
}

// TestResolveIfaceNameMigratesLegacyTun0: a config written by an older veld
// carries the legacy default "tun0". It must map to the platform default
// with a one-line notice — veld can no longer create a TUN named tun0 next
// to an OpenVPN-based VPN (TUNSETIFF fails with EEXIST).
func TestResolveIfaceNameMigratesLegacyTun0(t *testing.T) {
	var b strings.Builder
	if got := resolveIfaceName(testPrintf(&b), legacyIfaceName); got != tun.DefaultIfaceName() {
		t.Errorf("legacy iface_name must resolve to the platform default %q, got %q", tun.DefaultIfaceName(), got)
	}
	out := b.String()
	if !strings.Contains(out, legacyIfaceName) || !strings.Contains(out, tun.DefaultIfaceName()) {
		t.Errorf("migration must log one line naming the legacy value and the platform default, got:\n%s", out)
	}
}

// TestResolveIfaceNameHonorsOverride: any other value is honored verbatim,
// without logging.
func TestResolveIfaceNameHonorsOverride(t *testing.T) {
	var b strings.Builder
	if got := resolveIfaceName(testPrintf(&b), "custom1"); got != "custom1" {
		t.Errorf("iface_name custom1 must be honored verbatim, got %q", got)
	}
	if b.Len() != 0 {
		t.Errorf("an explicit iface_name must not log, got:\n%s", b.String())
	}
}
