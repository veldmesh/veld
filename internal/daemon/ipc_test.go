// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package daemon

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/veldmesh/veld/internal/peer"
)

func TestIPCServer_Status(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "daemon.sock")

	stopCh := make(chan struct{})
	srv := NewIPCServer(socketPath, func() { close(stopCh) })

	err := srv.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Stop()

	time.Sleep(50 * time.Millisecond) // let socket settle

	// Initial status should be empty
	st := StatusResponse{Running: true}
	srv.UpdateStatus(st)

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
			},
		},
	}

	resp, err := client.Get("http://daemon/api/status")
	if err != nil {
		t.Fatalf("Get /api/status: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	var result StatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if !result.Running {
		t.Errorf("expected Running=true, got false")
	}
}

func TestIPCServer_UpdateStatus(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "daemon.sock")

	srv := NewIPCServer(socketPath, func() {})
	err := srv.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Stop()

	time.Sleep(50 * time.Millisecond)

	// Update status with peer info
	st := StatusResponse{
		Running:   true,
		VPNAddr:   "10.0.0.1",
		NetworkID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1",
		Peers: []PeerStatus{
			{
				VPNAddr:  "10.0.0.2",
				Endpoint: "192.168.1.1:51820",
				State:    "connected",
			},
		},
	}
	srv.UpdateStatus(st)

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
			},
		},
	}

	resp, err := client.Get("http://daemon/api/status")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()

	var result StatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if result.VPNAddr != "10.0.0.1" {
		t.Errorf("expected VPNAddr=10.0.0.1, got %q", result.VPNAddr)
	}
	if result.NetworkID != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1" {
		t.Errorf("expected NetworkID, got %q", result.NetworkID)
	}
	if len(result.Peers) != 1 {
		t.Errorf("expected 1 peer, got %d", len(result.Peers))
	}
	if result.Peers[0].State != "connected" {
		t.Errorf("expected state=connected, got %q", result.Peers[0].State)
	}
}

func TestIPCServer_Shutdown(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "daemon.sock")

	stopped := make(chan struct{})
	srv := NewIPCServer(socketPath, func() { close(stopped) })

	err := srv.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Stop()

	time.Sleep(50 * time.Millisecond)

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
			},
		},
	}

	resp, err := client.Post("http://daemon/api/shutdown", "application/json", nil)
	if err != nil {
		t.Fatalf("Post /api/shutdown: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	// stopFn should have been called
	select {
	case <-stopped:
		// success
	case <-time.After(1 * time.Second):
		t.Errorf("stopFn not called within 1s")
	}
}

func TestIPCServer_MethodNotAllowed(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "daemon.sock")

	srv := NewIPCServer(socketPath, func() {})
	err := srv.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Stop()

	time.Sleep(50 * time.Millisecond)

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
			},
		},
	}

	// POST to /api/status should fail
	resp, err := client.Post("http://daemon/api/status", "application/json", nil)
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", resp.StatusCode)
	}
}

func TestPeerTableSnapshot(t *testing.T) {
	tbl := peer.New()

	// Add a peer
	var vpnAddr [4]byte
	copy(vpnAddr[:], []byte{10, 0, 0, 2})

	e1 := &peer.Entry{
		ID:        [32]byte{1},
		X25519Pub: [32]byte{2},
		VPNAddr:   netip.AddrFrom4(vpnAddr),
	}

	tbl.Upsert(e1)

	// Snapshot
	ps := peerTableSnapshot(tbl)
	if len(ps) != 1 {
		t.Errorf("expected 1 peer, got %d", len(ps))
	}
	if ps[0].State != "pending" {
		t.Errorf("expected state=pending, got %q", ps[0].State)
	}
}

func TestIPCServer_StartStop(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "daemon.sock")

	srv := NewIPCServer(socketPath, func() {})

	// Test that Start/Stop work
	err := srv.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	// Verify socket exists
	if _, err := os.Stat(socketPath); err != nil {
		t.Errorf("socket not created: %v", err)
	}

	// Make a request
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
			},
		},
	}

	resp, err := client.Get("http://daemon/api/status")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	// Stop should clean up
	srv.Stop()

	// Socket should be removed
	time.Sleep(50 * time.Millisecond)
	if _, err := os.Stat(socketPath); err == nil {
		t.Errorf("socket still exists after Stop")
	}

}
