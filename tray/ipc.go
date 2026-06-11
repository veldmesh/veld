// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// status mirrors internal/daemon.StatusResponse. Duplicated here so the tray
// binary has no compile-time dependency on the core module.
type status struct {
	Running   bool         `json:"running"`
	VPNAddr   string       `json:"vpn_addr,omitempty"`
	PeerID    string       `json:"peer_id,omitempty"`
	NetworkID string       `json:"network_id,omitempty"`
	CoordAddr string       `json:"coord_addr,omitempty"`
	Peers     []peerStatus `json:"peers"`
}

type peerStatus struct {
	VPNAddr  string `json:"vpn_addr"`
	Endpoint string `json:"endpoint"`
	State    string `json:"state"`
}

func defaultSocketPath() string {
	switch runtime.GOOS {
	case "windows":
		// Named pipe — not yet supported via this HTTP client.
		return `\\.\pipe\veld`
	default:
		dir, err := os.UserConfigDir()
		if err != nil {
			dir = os.TempDir()
		}
		return filepath.Join(dir, "veld", "daemon.sock")
	}
}

func newIPCClient(sockPath string) *http.Client {
	return &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", sockPath)
			},
			// No keep-alives — the socket may vanish between polls.
			DisableKeepAlives: true,
		},
	}
}

// queryStatus contacts the daemon IPC and returns the current status.
// Returns nil if the daemon is not reachable.
func queryStatus(client *http.Client) *status {
	resp, err := client.Get("http://daemon/api/status")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var st status
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return nil
	}
	return &st
}

// sendShutdown asks the daemon to shut down via POST /api/shutdown.
func sendShutdown(client *http.Client) {
	resp, err := client.Post("http://daemon/api/shutdown", "application/json", nil)
	if err != nil {
		return
	}
	resp.Body.Close()
}
