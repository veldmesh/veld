// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
//go:build unix

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/veldmesh/veld/internal/config"
)

func TestWriteConfigNotWorldReadable(t *testing.T) {
	old := syscall.Umask(0o022)
	defer syscall.Umask(old)

	dir := t.TempDir()
	fresh := filepath.Join(dir, "config.toml")
	if err := writeConfig(fresh, &config.Config{}); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(fresh); fi.Mode().Perm() != 0o600 {
		t.Errorf("new config mode = %v, want 0600", fi.Mode().Perm())
	}

	// An existing group-readable file keeps its group bits but loses
	// access for everyone else.
	shared := filepath.Join(dir, "shared.toml")
	if err := os.WriteFile(shared, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeConfig(shared, &config.Config{}); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(shared); fi.Mode().Perm() != 0o640 {
		t.Errorf("existing config mode = %v, want 0640", fi.Mode().Perm())
	}
}
