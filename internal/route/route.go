// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package route

import "net/netip"

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
