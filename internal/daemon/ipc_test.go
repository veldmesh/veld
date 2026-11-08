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

	"github.com/veldmesh/veld/internal/acl"
	"github.com/veldmesh/veld/internal/daemon/ipctypes"
	"github.com/veldmesh/veld/internal/peer"
)

// tempSock returns a socket path short enough for macOS's 104-byte sun_path limit.
// t.TempDir() embeds the full test name and can exceed that limit.
func tempSock(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "v-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "d.sock")
}

func TestIPCServer_Status(t *testing.T) {
	socketPath := tempSock(t)

	stopCh := make(chan struct{})
	srv := NewIPCServer(socketPath, func() { close(stopCh) }, nil)

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
	socketPath := tempSock(t)

	srv := NewIPCServer(socketPath, func() {}, nil)
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
	socketPath := tempSock(t)

	stopped := make(chan struct{})
	srv := NewIPCServer(socketPath, func() { close(stopped) }, nil)

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
	socketPath := tempSock(t)

	srv := NewIPCServer(socketPath, func() {}, nil)
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
	socketPath := tempSock(t)

	srv := NewIPCServer(socketPath, func() {}, nil)

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

// mockPolicyProvider implements PolicyStatusProvider for testing.
type mockPolicyProvider struct {
	localPolicy  ipctypes.LocalPolicyStatus
	dropCounters *acl.DropCounters
	recentDrops  []ipctypes.DropEvent
}

func (m *mockPolicyProvider) LocalPolicyStatus() ipctypes.LocalPolicyStatus {
	return m.localPolicy
}

func (m *mockPolicyProvider) DropCounters() *acl.DropCounters {
	return m.dropCounters
}

func (m *mockPolicyProvider) RecentDrops() []ipctypes.DropEvent {
	return m.recentDrops
}

// TestIPCServer_PolicyStatus tests the /api/policy/status endpoint.
func TestIPCServer_PolicyStatus(t *testing.T) {
	socketPath := tempSock(t)

	// Create a valid policy file for testing
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "policy.toml")
	validPolicy := `
version = 2
default = "deny"
[peers]
alice = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
bob   = "ed25519:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
[[rule]]
from = "alice"
to   = "bob"
ports = ["tcp/22"]
`
	if err := os.WriteFile(policyPath, []byte(validPolicy), 0o600); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	// Create drop counters and record some drops
	dc := acl.NewDropCounters()
	var peer1ID [32]byte
	peer1ID[1] = 1
	var peer2ID [32]byte
	peer2ID[2] = 2
	dc.RecordDrop(peer1ID, acl.ProtoTCP, 22, 0)
	dc.RecordDrop(peer2ID, acl.ProtoUDP, 53, -1)
	dc.IncrementPeer(peer1ID)
	dc.IncrementRule(0)

	// Create mock provider
	mock := &mockPolicyProvider{
		localPolicy: ipctypes.LocalPolicyStatus{
			Path:    policyPath,
			Hash:    "sha256:abcdef123456",
			Version: 2,
			Default: "deny",
			Rules:   1,
		},
		dropCounters: dc,
		recentDrops: []ipctypes.DropEvent{
			{
				Time:    time.Now(),
				PeerID:  "0100000000000000000000000000000000000000000000000000000000000000",
				Proto:   "TCP",
				Port:    22,
				RuleIdx: 0,
			},
			{
				Time:    time.Now(),
				PeerID:  "0002000000000000000000000000000000000000000000000000000000000000",
				Proto:   "UDP",
				Port:    53,
				RuleIdx: -1,
			},
		},
	}

	srv := NewIPCServer(socketPath, func() {}, mock)

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

	resp, err := client.Get("http://daemon/api/policy/status")
	if err != nil {
		t.Fatalf("Get /api/policy/status: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	var result ipctypes.PolicyStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Verify local policy info
	if result.LocalPolicy.Path != policyPath {
		t.Errorf("expected Path=%q, got %q", policyPath, result.LocalPolicy.Path)
	}
	if result.LocalPolicy.Version != 2 {
		t.Errorf("expected Version=2, got %d", result.LocalPolicy.Version)
	}
	if result.LocalPolicy.Default != "deny" {
		t.Errorf("expected Default=deny, got %q", result.LocalPolicy.Default)
	}
	if result.LocalPolicy.Rules != 1 {
		t.Errorf("expected Rules=1, got %d", result.LocalPolicy.Rules)
	}
	if result.LocalPolicy.Hash == "" {
		t.Error("expected non-empty Hash")
	}

	// Verify network policy is placeholder
	if result.NetworkPolicy.Version != 0 {
		t.Errorf("expected NetworkPolicy.Version=0 (placeholder), got %d", result.NetworkPolicy.Version)
	}

	// Verify drop counters
	if result.DropCounters.ByPeer == nil {
		t.Error("expected ByPeer map")
	} else {
		peer1Hex := "0001000000000000000000000000000000000000000000000000000000000000"
		if result.DropCounters.ByPeer[peer1Hex] != 1 {
			t.Errorf("expected ByPeer[%s]=1, got %d", peer1Hex, result.DropCounters.ByPeer[peer1Hex])
		}
	}
	if result.DropCounters.ByRule[0] != 1 {
		t.Errorf("expected ByRule[0]=1, got %d", result.DropCounters.ByRule[0])
	}

	// Verify recent drops
	if len(result.RecentDrops) != 2 {
		t.Errorf("expected 2 recent drops, got %d", len(result.RecentDrops))
	}
	for i, drop := range result.RecentDrops {
		if drop.PeerID == "" {
			t.Errorf("drop %d: empty PeerID", i)
		}
		if drop.Proto == "" {
			t.Errorf("drop %d: empty Proto", i)
		}
		if drop.Time.IsZero() {
			t.Errorf("drop %d: zero Time", i)
		}
	}
	if result.RecentDrops[0].Port != 22 {
		t.Errorf("drop 0: expected Port=22, got %d", result.RecentDrops[0].Port)
	}
	if result.RecentDrops[0].RuleIdx != 0 {
		t.Errorf("drop 0: expected RuleIdx=0, got %d", result.RecentDrops[0].RuleIdx)
	}
	if result.RecentDrops[1].Port != 53 {
		t.Errorf("drop 1: expected Port=53, got %d", result.RecentDrops[1].Port)
	}
	if result.RecentDrops[1].RuleIdx != -1 {
		t.Errorf("drop 1: expected RuleIdx=-1, got %d", result.RecentDrops[1].RuleIdx)
	}
}

// TestIPCServer_PolicyStatus_NoPolicy tests the endpoint when no policy is loaded.
func TestIPCServer_PolicyStatus_NoPolicy(t *testing.T) {
	socketPath := tempSock(t)

	mock := &mockPolicyProvider{
		localPolicy:  ipctypes.LocalPolicyStatus{},
		dropCounters: acl.NewDropCounters(),
		recentDrops:  nil,
	}

	srv := NewIPCServer(socketPath, func() {}, mock)

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

	resp, err := client.Get("http://daemon/api/policy/status")
	if err != nil {
		t.Fatalf("Get /api/policy/status: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	var result ipctypes.PolicyStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// All fields should be empty/zero
	if result.LocalPolicy.Path != "" {
		t.Errorf("expected empty Path, got %q", result.LocalPolicy.Path)
	}
	if result.LocalPolicy.Version != 0 {
		t.Errorf("expected Version=0, got %d", result.LocalPolicy.Version)
	}
	if len(result.RecentDrops) != 0 {
		t.Errorf("expected no recent drops, got %d", len(result.RecentDrops))
	}
	if len(result.DropCounters.ByPeer) != 0 {
		t.Errorf("expected empty ByPeer, got %d entries", len(result.DropCounters.ByPeer))
	}
	if len(result.DropCounters.ByRule) != 0 {
		t.Errorf("expected empty ByRule, got %d entries", len(result.DropCounters.ByRule))
	}
}

// TestIPCServer_PolicyStatus_MethodNotAllowed tests that POST to the policy status endpoint fails.
func TestIPCServer_PolicyStatus_MethodNotAllowed(t *testing.T) {
	socketPath := tempSock(t)

	srv := NewIPCServer(socketPath, func() {}, nil)
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

	resp, err := client.Post("http://daemon/api/policy/status", "application/json", nil)
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", resp.StatusCode)
	}
}
