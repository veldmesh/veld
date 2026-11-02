// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
//go:build linux

package acl

import (
	"fmt"
	"os"
	"syscall"
)

// checkRootOrCurrentOwnership checks that the policy file is owned by root (UID 0)
// or the current effective user on Linux.
func checkRootOrCurrentOwnership(path string, info os.FileInfo) error {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		currentUID := os.Geteuid()
		if stat.Uid != 0 && stat.Uid != uint32(currentUID) {
			return fmt.Errorf("policy file %q is not owned by root (uid=0) or current user (uid=%d); got uid=%d", path, currentUID, stat.Uid)
		}
	}
	return nil
}
