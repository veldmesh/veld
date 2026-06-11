// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
//go:build !linux

package route

import "net/netip"

// New returns a no-op route manager on non-Linux platforms.
// Subnet routing requires Linux netlink; other platforms log nothing and succeed silently.
func New() Manager { return &noopManager{} }

// EnableIPForward is a no-op on non-Linux platforms.
func EnableIPForward() error { return nil }

type noopManager struct{}

func (m *noopManager) Add(prefix netip.Prefix, via netip.Addr) error { return nil }
func (m *noopManager) Remove(prefix netip.Prefix) error              { return nil }
func (m *noopManager) Close() error                                   { return nil }
