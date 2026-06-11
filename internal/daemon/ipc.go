// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package daemon

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"

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

// IPCServer is an HTTP server on a Unix domain socket that exposes daemon state.
type IPCServer struct {
	socketPath string
	mu         sync.Mutex
	status     StatusResponse
	stopFn     func()
	srv        *http.Server
	listener   net.Listener
}

// NewIPCServer creates an IPC server at the given socket path.
// stopFn is invoked when POST /api/shutdown is received.
func NewIPCServer(socketPath string, stopFn func()) *IPCServer {
	s := &IPCServer{socketPath: socketPath, stopFn: stopFn}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/shutdown", s.handleShutdown)
	s.srv = &http.Server{Handler: mux}
	return s
}

// UpdateStatus atomically replaces the cached status.
func (s *IPCServer) UpdateStatus(st StatusResponse) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status = st
}

// Start begins listening. Returns an error if the socket cannot be created.
func (s *IPCServer) Start() error {
	if err := os.MkdirAll(filepath.Dir(s.socketPath), 0700); err != nil {
		return err
	}
	os.Remove(s.socketPath) // remove stale socket
	ln, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return err
	}
	s.listener = ln
	go s.srv.Serve(ln)
	return nil
}

// Stop shuts down the IPC server and removes the socket file.
func (s *IPCServer) Stop() {
	s.srv.Shutdown(context.Background())
	if s.listener != nil {
		s.listener.Close()
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
	json.NewEncoder(w).Encode(st)
}

func (s *IPCServer) handleShutdown(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.WriteHeader(http.StatusOK)
	go s.stopFn()
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
