// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package e2e_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/veldmesh/veld/internal/crypto"
	"github.com/veldmesh/veld/internal/mdns"
)

// TestMDNS_StartStop verifies that a Discovery can be created and stopped cleanly
// without hanging. Skipped with -short because it binds real multicast sockets.
func TestMDNS_StartStop(t *testing.T) {
	if testing.Short() {
		t.Skip("mdns uses real multicast sockets; skipped with -short")
	}

	id, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}

	disc, err := mdns.New(id, "e2e-node", netip.MustParseAddr("10.99.0.1"), 51820, nil)
	if err != nil {
		// Port 5353 may require elevated privileges (e.g. in CI without root).
		t.Skipf("mdns.New: %v", err)
	}

	disc.Start()
	time.Sleep(50 * time.Millisecond)
	disc.Stop() // must not hang or panic
}

// TestMDNS_NilCallbackSafe verifies that a nil onPeer callback does not panic.
func TestMDNS_NilCallbackSafe(t *testing.T) {
	if testing.Short() {
		t.Skip("skipped with -short")
	}

	id, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}

	disc, err := mdns.New(id, "nil-cb-node", netip.MustParseAddr("10.99.0.2"), 51821, nil)
	if err != nil {
		t.Skipf("mdns.New: %v", err)
	}
	disc.Start()
	disc.Stop()
}
