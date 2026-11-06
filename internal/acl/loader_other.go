// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
//go:build !linux

package acl

import (
	"os"
)

// checkRootOrCurrentOwnership is a no-op on non-Linux platforms.
func checkRootOrCurrentOwnership(path string, info os.FileInfo) error {
	return nil
}
