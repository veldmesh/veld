// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
//go:build !userspace

package tun

import (
	"errors"
	"net/netip"
)

// createNetstackTUN is a stub for when the userspace build tag is not set.
// This allows non-userspace builds (kernel TUN only) to compile without the
// gVisor netstack dependency. When userspace mode is requested but the tag
// is missing, CreateTUN returns a clear error message.
func createNetstackTUN(_ string, _ netip.Prefix, _ int) (TUN, error) {
	return nil, errors.New("userspace netstack not available: build with -tags userspace")
}
