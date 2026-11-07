// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package daemon

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/veldmesh/veld/internal/acl"
	"github.com/veldmesh/veld/internal/daemon/ipctypes"
	"github.com/veldmesh/veld/internal/peer"
)

// StatusResponse is returned by GET /api/status.
type StatusResponse struct {
	Running   bool         `json:"running"`
	VPNAddr   string       `json:"vpn_addr,omitempty"`
	PeerID    string       `json:"peer_id,omitempty"`
	NetworkID string       `json:"network_id,omitempty"`
	CoordAddr string       `json:"coord_addr,omitempty"`
	Peers     []PeerStatus `json:"peers"`
}

type PeerStatus struct {
	VPNAddr  string `json:"vpn_addr"`
	Endpoint string `json:"endpoint"`
	State    string `json:"state"`
}

// PolicyStatusProvider provides policy status for the IPC endpoint.
type PolicyStatusProvider interface {
	LocalPolicyStatus() ipctypes.LocalPolicyStatus
	DropCounters() *acl.DropCounters
	RecentDrops() []ipctypes.DropEvent
}

// IPCServer is an HTTP server on a Unix domain socket that exposes daemon state.
type IPCServer struct {
	socketPath     string
	mu             sync.Mutex
	status         StatusResponse
	stopFn         func()
	srv            *http.Server
	listener       net.Listener
	policyProvider PolicyStatusProvider
}

// NewIPCServer creates an IPC server at the given socket path.
// stopFn is invoked when POST /api/shutdown is received.
// policyProvider provides policy status for /api/policy/status.
func NewIPCServer(socketPath string, stopFn func(), policyProvider PolicyStatusProvider) *IPCServer {
	s := &IPCServer{
		socketPath:     socketPath,
		stopFn:         stopFn,
		policyProvider: policyProvider,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/shutdown", s.handleShutdown)
	mux.HandleFunc("/api/policy/status", s.handlePolicyStatus)
	s.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	return s
}

// SetPolicyProvider sets the policy status provider.
// This should only be used if the provider wasn't available at construction time.
func (s *IPCServer) SetPolicyProvider(p PolicyStatusProvider) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policyProvider = p
}

// UpdateStatus atomically replaces the cached status.
func (s *IPCServer) UpdateStatus(st StatusResponse) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status = st
}

// Start begins listening. Returns an error if the socket cannot be created.
func (s *IPCServer) Start() error {
	dir := filepath.Dir(s.socketPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	// The socket accepts shutdown requests and is trusted by `veld status`:
	// in a directory others can write to, another user could replace it
	// between the Remove and the Listen below.
	if fi, err := os.Stat(dir); err == nil && runtime.GOOS != "windows" && fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("socket directory %s is writable by other users; use a private directory for socket_path", dir)
	}
	os.Remove(s.socketPath) // remove stale socket
	ln, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return err
	}
	// Owner and group only, whatever the umask.
	if runtime.GOOS != "windows" {
		if err := os.Chmod(s.socketPath, 0o660); err != nil {
			_ = ln.Close()
			return err
		}
	}
	s.listener = ln
	go s.srv.Serve(ln)
	return nil
}

// Stop shuts down the IPC server and removes the socket file.
func (s *IPCServer) Stop() {
	s.srv.Shutdown(context.Background())
	if s.listener != nil {
		_ = s.listener.Close()
	}
	os.Remove(s.socketPath)
}

func (s *IPCServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	st := s.status
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(st); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

func (s *IPCServer) handleShutdown(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.WriteHeader(http.StatusOK)
	go s.stopFn()
}

func (s *IPCServer) handlePolicyStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var resp ipctypes.PolicyStatusResponse
	s.mu.Lock()
	provider := s.policyProvider
	s.mu.Unlock()

	if provider != nil {
		resp.LocalPolicy = provider.LocalPolicyStatus()
		resp.DropCounters = dropCountersToStatus(provider.DropCounters())
		resp.RecentDrops = provider.RecentDrops()
	}
	// Network policy is a placeholder until the signed-policy story
	resp.NetworkPolicy = ipctypes.NetworkPolicyStatus{}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

func dropCountersToStatus(dc *acl.DropCounters) ipctypes.DropCountersStatus {
	if dc == nil {
		return ipctypes.DropCountersStatus{
			ByPeer:         make(map[string]uint64),
			ByRule:         make(map[int]uint64),
			ByOutboundOnly: make(map[string]uint64),
		}
	}
	byPeer, byRule, byOO := dc.Snapshot()
	resp := ipctypes.DropCountersStatus{
		ByPeer:         make(map[string]uint64, len(byPeer)),
		ByRule:         make(map[int]uint64, len(byRule)),
		ByOutboundOnly: make(map[string]uint64, len(byOO)),
	}
	for k, v := range byPeer {
		resp.ByPeer[hex.EncodeToString(k[:])] = v
	}
	for k, v := range byRule {
		resp.ByRule[k] = v
	}
	for k, v := range byOO {
		resp.ByOutboundOnly[hex.EncodeToString(k[:])] = v
	}
	return resp
}

// peerTableSnapshot returns the current peer table as PeerStatus slice.
func peerTableSnapshot(tbl *peer.Table) []PeerStatus {
	entries := tbl.List()
	out := make([]PeerStatus, 0, len(entries))
	for _, e := range entries {
		ep := e.GetEndpoint()
		var epStr string
		if ep.IsValid() {
			epStr = ep.String()
		}
		state := "pending"
		switch e.GetState() {
		case peer.StateHandshaking:
			state = "handshaking"
		case peer.StateConnected:
			state = "connected"
		}
		out = append(out, PeerStatus{
			VPNAddr:  e.VPNAddr.String(),
			Endpoint: epStr,
			State:    state,
		})
	}
	return out
}
