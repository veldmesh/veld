// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
//go:build unix

package daemon

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestIPCServer_SocketPermissions(t *testing.T) {
	old := syscall.Umask(0o022)
	defer syscall.Umask(old)

	sock := tempSock(t)
	srv := NewIPCServer(sock, func() {})
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()
	fi, err := os.Stat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o660 {
		t.Errorf("socket mode %v, want 0660", perm)
	}
}

func TestIPCServer_RefusesSharedDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	srv := NewIPCServer(filepath.Join(dir, "daemon.sock"), func() {})
	if err := srv.Start(); err == nil {
		srv.Stop()
		t.Fatal("started in a world-writable directory")
	}
}
