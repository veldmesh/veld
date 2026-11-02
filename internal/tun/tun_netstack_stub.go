// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
//go:build !userspace

package tun

import (
	"errors"
	"net/netip"
)

// createNetstackTUN is a stub for when userspace build tag is not set.
func createNetstackTUN(_ string, _ netip.Prefix, _ int) (TUN, error) {
	return nil, errors.New("userspace netstack not available: build with -tags userspace")
}
