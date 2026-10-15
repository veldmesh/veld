// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
//go:build !linux && !darwin && !windows

package tun

import (
	"errors"
	"net/netip"
)

var errUnsupported = errors.New("tun: CreateTUN not supported on this OS (supported: linux, darwin, windows)")

// DefaultIfaceName returns the generic default interface name. CreateTUN
// fails on unsupported platforms anyway; the value only keeps config
// handling uniform across builds.
func DefaultIfaceName() string { return "veld0" }

// CreateTUN is not implemented on this platform.
func CreateTUN(_ string, _ netip.Prefix, _ int) (TUN, error) {
	return nil, errUnsupported
}
