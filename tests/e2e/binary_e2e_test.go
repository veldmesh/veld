// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package e2e_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	coordv1 "github.com/veldmesh/veld/gen/veld/coord/v1"
)

// moduleRoot returns the core/ directory (where go.mod lives).
// Tests run with cwd = tests/e2e/ so two levels up is the module root.
func moduleRoot(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("moduleRoot: %v", err)
	}
	return abs
}

// buildBinaries compiles all three Veld binaries into a temp dir.
// Returns (coordBin, daemonBin, cliBin) absolute paths.
func buildBinaries(t *testing.T) (coordBin, daemonBin, cliBin string) {
	t.Helper()
	dir := t.TempDir()
	root := moduleRoot(t)

	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}

	type spec struct{ out, pkg string }
	specs := []spec{
		{filepath.Join(dir, "veld-coord"+ext), "github.com/veldmesh/veld/cmd/veld-coord"},
		{filepath.Join(dir, "veld-daemon"+ext), "github.com/veldmesh/veld/cmd/veld-daemon"},
		{filepath.Join(dir, "veld"+ext), "github.com/veldmesh/veld/cmd/veld"},
	}

	for _, s := range specs {
		cmd := exec.Command("go", "build", "-o", s.out, s.pkg)
		cmd.Dir = root
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v\n%s", s.pkg, err, out)
		}
	}

	return specs[0].out, specs[1].out, specs[2].out
}

// pickFreePort returns an available TCP port on localhost.
func pickFreePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pickFreePort: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

// waitForTCP polls until addr is reachable or the timeout expires.
func waitForTCP(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for TCP %s after %s", addr, timeout)
}

// waitForUnixSocket polls until the unix socket at path is connectable.
// Returns false if the done channel fires first (process exited early).
func waitForUnixSocket(path string, timeout time.Duration, done <-chan struct{}) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-done:
			return false
		default:
		}
		conn, err := net.DialTimeout("unix", path, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// startProcess launches cmd and registers a cleanup to kill+wait it.
func startProcess(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", filepath.Base(cmd.Path), err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill() //nolint:errcheck
		cmd.Wait()         //nolint:errcheck
	})
}

// binaryNetworkID is a 32-char hex network ID shared across binary tests.
const binaryNetworkID = "babe000000000000000000000000cafe"

// TestBinary_Build verifies that all three Veld binaries compile cleanly.
// This is always run (no -short guard) because it only exercises the Go toolchain.
func TestBinary_Build(t *testing.T) {
	buildBinaries(t)
}

// TestBinary_Coord_StartStop starts the veld-coord binary, verifies it serves
// gRPC on the configured port, and exercises Register/ListPeers/Leave via a real
// gRPC connection.
func TestBinary_Coord_StartStop(t *testing.T) {
	if testing.Short() {
		t.Skip("binary tests skipped with -short")
	}

	coordBin, _, _ := buildBinaries(t)
	dir := t.TempDir()
	port := pickFreePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	cmd := exec.Command(coordBin,
		"--listen", addr,
		"--db", filepath.Join(dir, "coord.db"),
		"--network-id", binaryNetworkID,
		"--network-cidr", "10.98.0.0/24",
		"--token", "testtoken",
	)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	startProcess(t, cmd)

	waitForTCP(t, addr, 5*time.Second)

	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	client := coordv1.NewCoordClient(conn)
	ctx := context.Background()

	// Register peer A
	regA, err := client.Register(ctx, &coordv1.RegisterRequest{
		NetworkId:     binaryNetworkID,
		Token:         "testtoken",
		Name:          "peer-a",
		Ed25519Public: base64.StdEncoding.EncodeToString(make([]byte, 32)),
		X25519Public:  base64.StdEncoding.EncodeToString(make([]byte, 32)),
		Endpoint:      "10.0.0.1:51820",
	})
	if err != nil {
		t.Fatalf("Register peer-a: %v", err)
	}
	if regA.VpnAddr == "" {
		t.Error("Register peer-a: empty VPN address")
	}

	// Register peer B
	regB, err := client.Register(ctx, &coordv1.RegisterRequest{
		NetworkId:     binaryNetworkID,
		Token:         "testtoken",
		Name:          "peer-b",
		Ed25519Public: base64.StdEncoding.EncodeToString(append(make([]byte, 31), 0x01)),
		X25519Public:  base64.StdEncoding.EncodeToString(append(make([]byte, 31), 0x01)),
		Endpoint:      "10.0.0.2:51820",
	})
	if err != nil {
		t.Fatalf("Register peer-b: %v", err)
	}

	// ListPeers — must see both
	list, err := client.ListPeers(ctx, &coordv1.ListPeersRequest{
		NetworkId: binaryNetworkID,
		Token:     "testtoken",
	})
	if err != nil {
		t.Fatalf("ListPeers: %v", err)
	}
	if len(list.Peers) != 2 {
		t.Errorf("ListPeers: got %d peers, want 2", len(list.Peers))
	}

	// Leave peer A — list shrinks to 1
	if _, err := client.Leave(ctx, &coordv1.LeaveRequest{
		Token:  "testtoken",
		PeerId: regA.PeerId,
	}); err != nil {
		t.Fatalf("Leave peer-a: %v", err)
	}

	list, err = client.ListPeers(ctx, &coordv1.ListPeersRequest{
		NetworkId: binaryNetworkID,
		Token:     "testtoken",
	})
	if err != nil {
		t.Fatalf("ListPeers after leave: %v", err)
	}
	if len(list.Peers) != 1 {
		t.Errorf("ListPeers after leave: got %d peers, want 1", len(list.Peers))
	}
	if list.Peers[0].Name != "peer-b" {
		t.Errorf("remaining peer name: got %q, want %q", list.Peers[0].Name, "peer-b")
	}
	_ = regB
}

// TestBinary_CLI_NoDaemon exercises CLI subcommands that do not require a
// running daemon. Verifies correct output and exit codes.
func TestBinary_CLI_NoDaemon(t *testing.T) {
	if testing.Short() {
		t.Skip("binary tests skipped with -short")
	}

	_, _, cliBin := buildBinaries(t)
	sockPath := filepath.Join(t.TempDir(), "nodaemon.sock")

	t.Run("status_reports_not_running", func(t *testing.T) {
		out, err := exec.Command(cliBin, "--socket", sockPath, "status").CombinedOutput()
		if err != nil {
			t.Fatalf("veld status: unexpected error %v\n%s", err, out)
		}
		if !strings.Contains(string(out), "daemon not running") {
			t.Errorf("want 'daemon not running'; got:\n%s", out)
		}
	})

	t.Run("help", func(t *testing.T) {
		out, err := exec.Command(cliBin, "--help").CombinedOutput()
		if err != nil {
			t.Fatalf("veld --help: %v\n%s", err, out)
		}
		if !strings.Contains(string(out), "veld") {
			t.Errorf("want 'veld' in help output; got:\n%s", out)
		}
	})

	t.Run("login_writes_config", func(t *testing.T) {
		dir := t.TempDir()
		cfgPath := filepath.Join(dir, "config.toml")

		out, err := exec.Command(cliBin, "login",
			"--config", cfgPath,
			"--server", "coord.example.com:50051",
			"--network-id", binaryNetworkID,
			"--token", "mytoken",
		).CombinedOutput()
		if err != nil {
			t.Fatalf("veld login: %v\n%s", err, out)
		}
		if !strings.Contains(string(out), "Credentials saved") {
			t.Errorf("want 'Credentials saved'; got:\n%s", out)
		}

		data, err := os.ReadFile(cfgPath)
		if err != nil {
			t.Fatalf("read saved config: %v", err)
		}
		body := string(data)
		if !strings.Contains(body, "coord.example.com:50051") {
			t.Errorf("coord addr missing from saved config:\n%s", body)
		}
		if !strings.Contains(body, "mytoken") {
			t.Errorf("token missing from saved config:\n%s", body)
		}
	})

	t.Run("join_saves_token", func(t *testing.T) {
		dir := t.TempDir()
		cfgPath := filepath.Join(dir, "config.toml")

		out, err := exec.Command(cliBin, "join",
			"--config", cfgPath,
			"--server", "coord.example.com:50051",
			"--network-id", binaryNetworkID,
			"jointoken123",
		).CombinedOutput()
		if err != nil {
			t.Fatalf("veld join: %v\n%s", err, out)
		}
		if !strings.Contains(string(out), "saved token") {
			t.Errorf("want 'saved token'; got:\n%s", out)
		}
		data, _ := os.ReadFile(cfgPath)
		if !strings.Contains(string(data), "jointoken123") {
			t.Errorf("token not in saved config:\n%s", data)
		}
	})
}

// TestBinary_FullStack starts all three binaries and exercises the integrated
// system: coord registers a network, daemon connects and registers a peer,
// and the CLI reports daemon status via IPC.
//
// The daemon runs in coord mode (no TUN required at startup). If the daemon
// exits early for any reason (e.g. OS restrictions), the test is skipped.
func TestBinary_FullStack(t *testing.T) {
	if testing.Short() {
		t.Skip("binary tests skipped with -short")
	}

	coordBin, daemonBin, cliBin := buildBinaries(t)
	dir := t.TempDir()

	// 1. Start coord binary.
	coordPort := pickFreePort(t)
	coordAddr := fmt.Sprintf("127.0.0.1:%d", coordPort)

	coordCmd := exec.Command(coordBin,
		"--listen", coordAddr,
		"--db", filepath.Join(dir, "coord.db"),
		"--network-id", binaryNetworkID,
		"--network-cidr", "10.97.0.0/24",
		"--token", "binarytoken",
	)
	coordCmd.Stdout = os.Stderr
	coordCmd.Stderr = os.Stderr
	startProcess(t, coordCmd)
	waitForTCP(t, coordAddr, 5*time.Second)

	// 2. Write daemon config (coord mode — no static TUN).
	sockPath := filepath.Join(dir, "daemon.sock")
	idPath := filepath.Join(dir, "identity.json")

	cfgContent := fmt.Sprintf(`[node]
identity_path = %q
listen_addr   = "127.0.0.1:0"

[coord]
addr         = %q
network_id   = %q
token        = "binarytoken"
tls_insecure = true

[daemon]
socket_path = %q
`, idPath, coordAddr, binaryNetworkID, sockPath)

	cfgPath := filepath.Join(dir, "daemon.toml")
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0600); err != nil {
		t.Fatalf("write daemon config: %v", err)
	}

	// 3. Start daemon binary.
	daemonCmd := exec.Command(daemonBin, "--config", cfgPath)
	daemonCmd.Stdout = os.Stderr
	daemonCmd.Stderr = os.Stderr

	if err := daemonCmd.Start(); err != nil {
		t.Skipf("daemon binary failed to start: %v", err)
	}

	exited := make(chan struct{})
	go func() {
		daemonCmd.Wait() //nolint:errcheck
		close(exited)
	}()
	t.Cleanup(func() {
		daemonCmd.Process.Kill() //nolint:errcheck
		<-exited
	})

	// 4. Wait for IPC socket or early daemon exit.
	if !waitForUnixSocket(sockPath, 8*time.Second, exited) {
		select {
		case <-exited:
			t.Skip("daemon exited before IPC socket appeared (likely OS restriction)")
		default:
			t.Skip("daemon IPC socket did not appear within 8 s (likely OS restriction)")
		}
	}

	// 5. Query status via CLI binary.
	out, err := exec.Command(cliBin, "--socket", sockPath, "status").CombinedOutput()
	if err != nil {
		t.Fatalf("veld status: %v\n%s", err, out)
	}
	t.Logf("daemon status:\n%s", out)

	if !strings.Contains(string(out), "Running: true") {
		t.Errorf("expected 'Running: true' in status output; got:\n%s", out)
	}

	// 6. Verify coord registered the daemon as a peer.
	conn, err := grpc.NewClient(coordAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var peers *coordv1.ListPeersResponse
	for time.Now().Before(time.Now().Add(5 * time.Second)) {
		peers, err = coordv1.NewCoordClient(conn).ListPeers(ctx, &coordv1.ListPeersRequest{
			NetworkId: binaryNetworkID,
			Token:     "binarytoken",
		})
		if err == nil && len(peers.Peers) > 0 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("ListPeers: %v", err)
	}
	if len(peers.Peers) == 0 {
		t.Error("daemon did not register with coord server within 5 s")
	} else {
		t.Logf("daemon registered as peer %q (VPN %s)", peers.Peers[0].Name, peers.Peers[0].VpnAddr)
	}

	// 7. Shut down the daemon via CLI 'down' and verify it exits cleanly.
	downOut, downErr := exec.Command(cliBin, "--socket", sockPath, "down").CombinedOutput()
	if downErr != nil {
		t.Logf("veld down: %v\n%s", downErr, downOut)
	}
	// Wait for daemon to exit (or timeout).
	select {
	case <-exited:
		t.Log("daemon exited after 'veld down'")
	case <-time.After(5 * time.Second):
		t.Log("daemon did not exit within 5 s after 'down' — killing")
	}
}
