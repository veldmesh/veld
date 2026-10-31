// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package route

import (
	"fmt"
	"net/netip"
)

// Manager installs and removes OS-level routes for subnet routing.
// All routes added via Add are tracked internally and removed by Close.
type Manager interface {
	// Add installs a host route for prefix via the gateway at via.
	// Calling Add twice for the same prefix is idempotent (replaces the previous entry).
	Add(prefix netip.Prefix, via netip.Addr) error
	// Remove deletes the route for prefix. No-op if the route was never added.
	Remove(prefix netip.Prefix) error
	// Close removes all routes that were added via this manager.
	Close() error
}

// CheckPeerRoute reports whether a subnet route advertised by a peer may be
// installed. Routes come from the coordinator or from static config, and
// installing one sends that traffic to the peer, so prefixes that would
// capture the host's own traffic are refused: anything broader than /8 (IPv4)
// or /16 (IPv6), which includes default routes and their /1 halves; anything
// overlapping the mesh prefix; and loopback, link-local, multicast and
// unspecified addresses. mesh may be the zero Prefix when not yet known.
func CheckPeerRoute(pfx, mesh netip.Prefix) error {
	if !pfx.IsValid() {
		return fmt.Errorf("invalid prefix")
	}
	addr := pfx.Masked().Addr()
	if addr.Is4In6() {
		return fmt.Errorf("%s: IPv4-mapped prefixes are not supported", pfx)
	}
	min := 16
	if addr.Is4() {
		min = 8
	}
	if pfx.Bits() < min {
		return fmt.Errorf("%s: broader than /%d", pfx, min)
	}
	if addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() ||
		addr.IsInterfaceLocalMulticast() || addr.IsUnspecified() {
		return fmt.Errorf("%s: reserved address range", pfx)
	}
	if mesh.IsValid() && pfx.Overlaps(mesh.Masked()) {
		return fmt.Errorf("%s: overlaps the mesh %s", pfx, mesh.Masked())
	}
	return nil
}
