// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package config

import (
	"errors"
	"os"
	"testing"
)

const validTOML = `
[node]
identity_path = "/etc/veld/identity.key"
vpn_addr      = "10.100.0.1/24"
listen_addr   = "0.0.0.0:51820"
network_id    = "deadbeef000000000000000000000000"

[[peers]]
name           = "peer-b"
ed25519_public = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
x25519_public  = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
vpn_addr       = "10.100.0.2"
endpoint       = "1.2.3.4:51820"
`

func TestParseConfig_Valid(t *testing.T) {
	cfg, err := ParseConfig(validTOML)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if cfg.Node.IdentityPath != "/etc/veld/identity.key" {
		t.Errorf("IdentityPath: got %q", cfg.Node.IdentityPath)
	}
	if cfg.Node.VPNAddr != "10.100.0.1/24" {
		t.Errorf("VPNAddr: got %q", cfg.Node.VPNAddr)
	}
	if cfg.Node.NetworkID != "deadbeef000000000000000000000000" {
		t.Errorf("NetworkID: got %q", cfg.Node.NetworkID)
	}
	if len(cfg.Peers) != 1 {
		t.Fatalf("Peers: got %d, want 1", len(cfg.Peers))
	}
	if cfg.Peers[0].Name != "peer-b" {
		t.Errorf("Peer name: got %q", cfg.Peers[0].Name)
	}
	if cfg.Peers[0].Endpoint != "1.2.3.4:51820" {
		t.Errorf("Peer endpoint: got %q", cfg.Peers[0].Endpoint)
	}
}

func TestParseConfig_InvalidTOML(t *testing.T) {
	_, err := ParseConfig("not valid toml }{")
	if err == nil {
		t.Error("expected error for invalid TOML")
	}
}

func TestParseConfig_MissingIdentityPath(t *testing.T) {
	src := `
[node]
vpn_addr    = "10.0.0.1/24"
listen_addr = "0.0.0.0:51820"
network_id  = "deadbeef000000000000000000000000"
`
	_, err := ParseConfig(src)
	if err == nil {
		t.Error("expected error for missing identity_path")
	}
}

func TestParseConfig_MissingNetworkID(t *testing.T) {
	src := `
[node]
identity_path = "/key"
vpn_addr      = "10.0.0.1/24"
listen_addr   = "0.0.0.0:51820"
network_id    = "tooshort"
`
	_, err := ParseConfig(src)
	if err == nil {
		t.Error("expected error for short network_id")
	}
}

func TestParseConfig_MissingPeerKey(t *testing.T) {
	src := `
[node]
identity_path = "/key"
vpn_addr      = "10.0.0.1/24"
listen_addr   = "0.0.0.0:51820"
network_id    = "deadbeef000000000000000000000000"

[[peers]]
name     = "x"
vpn_addr = "10.0.0.2"
`
	_, err := ParseConfig(src)
	if err == nil {
		t.Error("expected error for missing peer ed25519_public")
	}
}

func TestDefaultCoordAddr(t *testing.T) {
	if DefaultCoordAddr != "api.veldmesh.io:443" {
		t.Errorf("DefaultCoordAddr: got %q, want %q", DefaultCoordAddr, "api.veldmesh.io:443")
	}
}

func TestDefaultConfigPath(t *testing.T) {
	p := DefaultConfigPath()
	if p == "" {
		t.Fatal("DefaultConfigPath returned empty string")
	}
	if len(p) < len("config.toml") {
		t.Fatalf("DefaultConfigPath too short: %q", p)
	}
	if p[len(p)-len("config.toml"):] != "config.toml" {
		t.Errorf("DefaultConfigPath does not end in config.toml: %q", p)
	}
}

func TestDefaultSocketPath(t *testing.T) {
	p := DefaultSocketPath()
	if p == "" {
		t.Fatal("DefaultSocketPath returned empty string")
	}
}

const coordModeTOML = `
[node]
identity_path = "/key"

[coord]
addr       = "api.veldmesh.io:443"
network_id = "deadbeef000000000000000000000000"
token      = "tok"
`

func TestParseConfig_CoordMode(t *testing.T) {
	cfg, err := ParseConfig(coordModeTOML)
	if err != nil {
		t.Fatalf("ParseConfig coord mode: %v", err)
	}
	if cfg.Node.VPNAddr != "" {
		t.Errorf("coord mode: VPNAddr should be empty, got %q", cfg.Node.VPNAddr)
	}
	if cfg.Node.ListenAddr != "" {
		t.Errorf("coord mode: ListenAddr should be empty, got %q", cfg.Node.ListenAddr)
	}
	if cfg.Coord.Addr != "api.veldmesh.io:443" {
		t.Errorf("coord.addr: got %q, want %q", cfg.Coord.Addr, "api.veldmesh.io:443")
	}
	if cfg.Coord.NetworkID != "deadbeef000000000000000000000000" {
		t.Errorf("coord.network_id: got %q", cfg.Coord.NetworkID)
	}
	if cfg.Coord.Token != "tok" {
		t.Errorf("coord.token: got %q, want %q", cfg.Coord.Token, "tok")
	}
}

func TestLoadFile_OK(t *testing.T) {
	path := t.TempDir() + "/config.toml"
	if err := os.WriteFile(path, []byte(validTOML), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if cfg.Node.IdentityPath != "/etc/veld/identity.key" {
		t.Errorf("IdentityPath: got %q", cfg.Node.IdentityPath)
	}
	if cfg.Node.VPNAddr != "10.100.0.1/24" {
		t.Errorf("VPNAddr: got %q", cfg.Node.VPNAddr)
	}
}

func TestLoadFile_NotExist(t *testing.T) {
	path := t.TempDir() + "/nonexistent.toml"
	_, err := LoadFile(path)
	if err == nil {
		t.Fatal("expected error for non-existent file")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected os.ErrNotExist, got %v", err)
	}
}
