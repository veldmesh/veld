// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package e2e_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/veldmesh/veld/internal/config"
	"github.com/veldmesh/veld/internal/crypto"
	"github.com/veldmesh/veld/internal/relay"
)

// buildRelayBinary compiles the veld-relay binary into a temp dir.
func buildRelayBinary(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	root := moduleRoot(t)

	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}
	out := filepath.Join(dir, "veld-relay"+ext)
	cmd := exec.Command("go", "build", "-o", out, "github.com/veldmesh/veld/cmd/veld-relay")
	cmd.Dir = root
	if buildOut, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build veld-relay: %v\n%s", err, buildOut)
	}
	return out
}

// TestRelayBinary_GenIdentity verifies the -gen-identity flag: it creates the
// identity keystore on first run, prints the X25519 public key as a single
// base64 line, writes the keystore mode 0600, and is idempotent — a second
// run against an existing keystore prints the same key without regenerating.
// scripts/relay-identity.sh relies on all of this.
func TestRelayBinary_GenIdentity(t *testing.T) {
	if testing.Short() {
		t.Skip("binary tests skipped with -short")
	}

	relayBin := buildRelayBinary(t)
	idPath := filepath.Join(t.TempDir(), "relay-identity.json")

	run := func() string {
		out, err := exec.Command(relayBin, "-gen-identity", "-identity", idPath).CombinedOutput()
		if err != nil {
			t.Fatalf("veld-relay -gen-identity: %v\n%s", err, out)
		}
		key := strings.TrimSpace(string(out))
		raw, err := base64.StdEncoding.DecodeString(key)
		if err != nil || len(raw) != 32 {
			t.Fatalf("-gen-identity printed %q: want a single base64-encoded 32-byte X25519 key", key)
		}
		return key
	}

	key1 := run()

	// Keystore must exist and be readable only by its owner.
	fi, err := os.Stat(idPath)
	if err != nil {
		t.Fatalf("keystore not created: %v", err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0600 {
		t.Errorf("keystore mode is %04o, want 0600", fi.Mode().Perm())
	}

	// The printed key must match the keystore contents.
	id, err := config.Load(idPath)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	raw1, err := base64.StdEncoding.DecodeString(key1)
	if err != nil {
		t.Fatalf("decode key1: %v", err)
	}
	if !bytes.Equal(raw1, id.X25519Public[:]) {
		t.Errorf("printed key does not match keystore: printed %x, keystore %x", raw1, id.X25519Public[:])
	}

	// Idempotent: a second run must not rotate the key.
	if key2 := run(); key2 != key1 {
		t.Errorf("-gen-identity rotated an existing identity: first %q, second %q", key1, key2)
	}
}

// TestRelayBinary_Serve runs the real veld-relay binary with a pre-generated
// identity keystore (as the systemd unit does) and verifies two peers can
// complete Noise IK handshakes against the pinned key and exchange frames
// through the binary.
func TestRelayBinary_Serve(t *testing.T) {
	if testing.Short() {
		t.Skip("binary tests skipped with -short")
	}

	relayBin := buildRelayBinary(t)
	dir := t.TempDir()
	idPath := filepath.Join(dir, "relay-identity.json")

	// Generate the keystore up front, exactly like make relay-identity does.
	genOut, err := exec.Command(relayBin, "-gen-identity", "-identity", idPath).CombinedOutput()
	if err != nil {
		t.Fatalf("veld-relay -gen-identity: %v\n%s", err, genOut)
	}
	relayKeyB64 := strings.TrimSpace(string(genOut))
	relayKeyRaw, err := base64.StdEncoding.DecodeString(relayKeyB64)
	if err != nil || len(relayKeyRaw) != 32 {
		t.Fatalf("-gen-identity printed %q: want a base64 32-byte key", relayKeyB64)
	}
	var relayKey [32]byte
	copy(relayKey[:], relayKeyRaw)

	addr := fmt.Sprintf("127.0.0.1:%d", pickFreePort(t))
	var stdout bytes.Buffer
	cmd := exec.Command(relayBin, "-listen", addr, "-identity", idPath)
	cmd.Stdout = &stdout
	cmd.Stderr = os.Stderr
	startProcess(t, cmd)
	waitForTCP(t, addr, 5*time.Second)

	// Two peers handshake against the pinned key and exchange one frame
	// each through the running binary.
	idA, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate idA: %v", err)
	}
	idB, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate idB: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	connA, err := relay.Dial(ctx, addr, relayKey, idA, idB.X25519Public)
	if err != nil {
		t.Fatalf("peer A relay dial: %v", err)
	}
	defer connA.Close()
	connB, err := relay.Dial(ctx, addr, relayKey, idB, idA.X25519Public)
	if err != nil {
		t.Fatalf("peer B relay dial: %v", err)
	}
	defer connB.Close()

	ping := []byte("ping over veld-relay binary")
	if err := connA.WriteMessage(ping); err != nil {
		t.Fatalf("A write: %v", err)
	}
	got, err := connB.ReadMessage()
	if err != nil {
		t.Fatalf("B read: %v", err)
	}
	if !bytes.Equal(got, ping) {
		t.Errorf("B got %q, want %q", got, ping)
	}
	pong := []byte("pong over veld-relay binary")
	if err := connB.WriteMessage(pong); err != nil {
		t.Fatalf("B write: %v", err)
	}
	got, err = connA.ReadMessage()
	if err != nil {
		t.Fatalf("A read: %v", err)
	}
	if !bytes.Equal(got, pong) {
		t.Errorf("A got %q, want %q", got, pong)
	}

	// Startup output must print the relay's X25519 public key so operators
	// can copy it into peer configs. Safe to read after process exit.
	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("kill veld-relay: %v", err)
	}
	_ = cmd.Wait()
	if out := stdout.String(); !strings.Contains(out, relayKeyB64) {
		t.Errorf("startup output does not print the X25519 public key %q:\n%s", relayKeyB64, out)
	}
}
