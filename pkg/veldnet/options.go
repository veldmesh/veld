// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package veldnet

import (
	"io"
	"time"
)

// Options configures a veld Node.
type Options struct {
	// IdentityPath is the path to the identity file (Ed25519/X25519 keypair).
	// If the file does not exist, a new identity is generated and written with 0600 permissions.
	IdentityPath string

	// CoordAddr is the coordinator gRPC address (e.g., "coord.example.com:50051").
	CoordAddr string

	// CoordTLSInsecure disables TLS for the coordinator connection (plaintext; testing only).
	// When false (default), the system CA pool is used to verify the server certificate.
	CoordTLSInsecure bool

	// Token is the enrollment token. If empty, TokenReader is used.
	// The token is never logged.
	Token string

	// TokenReader reads the enrollment token from an io.Reader (e.g., stdin, a file, a secret manager).
	// If both Token and TokenReader are set, Token takes precedence.
	// The reader is read once at Start time. The token is never logged.
	TokenReader io.Reader

	// NodeName is the name this node registers with the coordinator.
	// Defaults to the hostname if empty.
	NodeName string

	// OutboundOnly sets the local ACL policy to "outbound_only = [\"self\"]"
	// when ACLs are present, preventing inbound connections from other peers.
	OutboundOnly bool

	// PolicyPath is the path to a local ACL policy file (TOML).
	// If empty, defaults to policy.toml next to the identity file.
	// If the file does not exist, no local policy is enforced (defer to network).
	PolicyPath string

	// Userspace forces userspace networking (netstack TUN). No root, no TUN device,
	// no OS routes. Always enabled for the embeddable package.
	Userspace bool

	// STUNServer is the STUN server for NAT traversal (e.g., "stun.l.google.com:19302").
	STUNServer string

	// RelayAddr is the relay server address for fallback (e.g., "relay.example.com:7878").
	RelayAddr string

	// RelayX25519 is the base64-encoded 32-byte X25519 public key of the relay server.
	RelayX25519 string

	// SubnetRoutes are CIDR prefixes this node advertises (e.g., "192.168.1.0/24").
	SubnetRoutes []string

	// NetworkID is the 32-char hex network ID. If empty, it is inferred from the token.
	NetworkID string

	// ListenAddr is the UDP listen address for the data plane (default "0.0.0.0:51820").
	ListenAddr string

	// MTU is the TUN MTU (default 1420).
	MTU int

	// DialTimeout is the timeout for establishing a connection via DialContext.
	// If zero, a default of 10 seconds is used.
	DialTimeout time.Duration
}
