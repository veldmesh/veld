// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

// DNSConfig configures the local DNS stub resolver.
// All fields are optional; if Enabled is false the resolver is not started.
type DNSConfig struct {
	Enabled    bool   `toml:"enabled"`
	Domain     string `toml:"domain"`      // e.g. "veld"; default "veld" if empty
	ListenAddr string `toml:"listen_addr"` // e.g. "127.0.0.1:5353"; default if empty
}

// MDNSConfig configures LAN-mode peer discovery via mDNS/DNS-SD.
type MDNSConfig struct {
	Enabled bool   `toml:"enabled"`
	Name    string `toml:"name"` // peer name to advertise; defaults to hostname if empty
}

// Config is the top-level node configuration loaded from a TOML file.
type Config struct {
	Node   NodeConfig   `toml:"node"`
	Coord  CoordConfig  `toml:"coord"`
	Daemon DaemonConfig `toml:"daemon"`
	DNS    DNSConfig    `toml:"dns"`
	MDNS   MDNSConfig   `toml:"mdns"`
	Peers  []PeerConfig `toml:"peers"`
}

// NodeConfig holds local node settings.
type NodeConfig struct {
	IdentityPath string   `toml:"identity_path"` // path to JSON identity keystore
	VPNAddr      string   `toml:"vpn_addr"`      // e.g. "10.100.0.1/24"
	ListenAddr   string   `toml:"listen_addr"`   // e.g. "0.0.0.0:51820"
	NetworkID    string   `toml:"network_id"`    // 32 lowercase hex chars (16 bytes)
	IfaceName    string   `toml:"iface_name"`    // TUN interface name; default "tun0"
	MTU          int      `toml:"mtu"`           // 0 → default 1420
	SubnetRoutes []string `toml:"subnet_routes"` // CIDR prefixes this node advertises
}

// CoordConfig holds settings for connecting to a coord server.
// All fields are optional; if Addr is empty, coord mode is disabled.
type CoordConfig struct {
	Addr        string `toml:"addr"`             // e.g. "coord.example.com:50051"
	NetworkID   string `toml:"network_id"`
	Token       string `toml:"token"`
	TLSInsecure bool   `toml:"tls_insecure"`
	STUNServer  string `toml:"stun_server"`      // e.g. "stun.l.google.com:19302"; empty = skip STUN
}

// DaemonConfig holds daemon process settings.
type DaemonConfig struct {
	SocketPath string `toml:"socket_path"` // IPC Unix socket path; empty = platform default
}

// PeerConfig holds the static configuration for one remote peer.
type PeerConfig struct {
	Name          string   `toml:"name"`
	Ed25519Public string   `toml:"ed25519_public"` // base64-standard, 32 bytes
	X25519Public  string   `toml:"x25519_public"`  // base64-standard, 32 bytes
	VPNAddr       string   `toml:"vpn_addr"`       // e.g. "10.100.0.2"
	Endpoint      string   `toml:"endpoint"`       // e.g. "1.2.3.4:51820"; empty = no known endpoint
	SubnetRoutes  []string `toml:"subnet_routes"`  // CIDR prefixes this peer advertises
}

// LoadFile loads and validates a Config from a TOML file.
func LoadFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}
	return ParseConfig(string(data))
}

// ParseConfig parses and validates a Config from a TOML string. Used in tests.
func ParseConfig(src string) (*Config, error) {
	var cfg Config
	if _, err := toml.Decode(src, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Validate checks that required fields are present and well-formed.
func (c *Config) Validate() error {
	n := &c.Node
	if n.IdentityPath == "" {
		return fmt.Errorf("config: node.identity_path is required")
	}

	// When running in coord mode, VPNAddr and ListenAddr are assigned dynamically.
	// When running in static mode, they must be configured.
	if c.Coord.Addr == "" {
		// Static mode: require VPNAddr and ListenAddr
		if n.VPNAddr == "" {
			return fmt.Errorf("config: node.vpn_addr is required (or use coord.addr for dynamic assignment)")
		}
		if n.ListenAddr == "" {
			return fmt.Errorf("config: node.listen_addr is required")
		}
	}

	// NetworkID is required (can come from node or coord config)
	networkID := n.NetworkID
	if networkID == "" {
		networkID = c.Coord.NetworkID
	}
	if len(strings.TrimSpace(networkID)) != 32 {
		return fmt.Errorf("config: network_id must be 32 hex characters (in node.network_id or coord.network_id)")
	}

	// Validate peers only if any are present
	for i, p := range c.Peers {
		if p.Ed25519Public == "" {
			return fmt.Errorf("config: peers[%d] (%q): ed25519_public is required", i, p.Name)
		}
		if p.X25519Public == "" {
			return fmt.Errorf("config: peers[%d] (%q): x25519_public is required", i, p.Name)
		}
		if p.VPNAddr == "" {
			return fmt.Errorf("config: peers[%d] (%q): vpn_addr is required", i, p.Name)
		}
	}
	return nil
}

// DefaultCoordAddr is the managed SaaS coordination server.
// Self-hosters override this via config.toml or --coord flag.
const DefaultCoordAddr = "api.veldmesh.io:443"

// DefaultConfigPath returns the platform-appropriate configuration file path.
//
//	Linux:   ~/.config/veld/config.toml
//	macOS:   ~/Library/Application Support/veld/config.toml
//	Windows: %AppData%\veld\config.toml
func DefaultConfigPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = os.TempDir()
	}
	return filepath.Join(dir, "veld", "config.toml")
}

// DefaultSocketPath returns the platform-appropriate IPC socket path.
func DefaultSocketPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = os.TempDir()
	}
	return filepath.Join(dir, "veld", "daemon.sock")
}
