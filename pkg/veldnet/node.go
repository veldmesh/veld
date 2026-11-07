// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package veldnet

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/veldmesh/veld/internal/config"
	"github.com/veldmesh/veld/internal/coord"
	"github.com/veldmesh/veld/internal/crypto"
	"github.com/veldmesh/veld/internal/daemon"
)

const (
	defaultListenAddr  = "0.0.0.0:51820"
	defaultMTU         = 1420
	defaultDialTimeout = 10 * time.Second
)

// Node is an embeddable veld mesh node.
type Node struct {
	opts      Options
	localID   *crypto.Identity
	networkID [16]byte

	mu          sync.Mutex
	d           *daemon.Daemon
	vpnAddr     netip.Addr
	peerID      string
	started     bool
	closed      bool
	coordClient *coord.Client
	policyDir   string // temp dir for outbound-only policy, cleaned up on Close
}

// New creates a new Node from options.
// The identity is loaded from IdentityPath or generated and saved (0600).
// Call Start to connect to the coordinator and begin processing.
func New(opts Options) (*Node, error) {
	if opts.IdentityPath == "" {
		return nil, errors.New("IdentityPath is required")
	}
	if opts.CoordAddr == "" {
		return nil, errors.New("CoordAddr is required")
	}

	// Ensure identity directory exists
	if err := os.MkdirAll(filepath.Dir(opts.IdentityPath), 0700); err != nil {
		return nil, fmt.Errorf("create identity dir: %w", err)
	}

	// Load or generate identity using internal config package
	localID, err := config.LoadOrGenerate(opts.IdentityPath)
	if err != nil {
		return nil, fmt.Errorf("load identity: %w", err)
	}

	// Validate and parse NetworkID if provided
	var networkID [16]byte
	if opts.NetworkID != "" {
		netIDBytes, err := hex.DecodeString(opts.NetworkID)
		if err != nil || len(netIDBytes) != 16 {
			return nil, errors.New("NetworkID must be 32 hex characters (16 bytes)")
		}
		copy(networkID[:], netIDBytes)
	}

	// Set defaults
	if opts.ListenAddr == "" {
		opts.ListenAddr = defaultListenAddr
	}
	if opts.MTU == 0 {
		opts.MTU = defaultMTU
	}
	if opts.DialTimeout == 0 {
		opts.DialTimeout = defaultDialTimeout
	}

	// Userspace is always on for the embeddable package
	opts.Userspace = true

	n := &Node{
		opts:      opts,
		localID:   localID,
		networkID: networkID,
	}

	return n, nil
}

// LocalID returns the node's identity.
func (n *Node) LocalID() *crypto.Identity {
	return n.localID
}

// Start connects to the coordinator and begins processing.
// It blocks until the node is registered and has a VPN address, or ctx is cancelled.
func (n *Node) Start(ctx context.Context) error {
	n.mu.Lock()
	if n.started {
		n.mu.Unlock()
		return errors.New("node already started")
	}
	if n.closed {
		n.mu.Unlock()
		return errors.New("node already closed")
	}
	n.started = true
	n.mu.Unlock()

	// Resolve token
	token := n.opts.Token
	if token == "" && n.opts.TokenReader != nil {
		data, err := io.ReadAll(n.opts.TokenReader)
		if err != nil {
			return fmt.Errorf("read token: %w", err)
		}
		token = string(data)
	}
	if token == "" {
		return errors.New("token is required (Token or TokenReader)")
	}

	// Determine local policy file path
	var policyPath string

	if n.opts.OutboundOnly {
		// If OutboundOnly is enabled, create a local ACL policy with outbound_only = ["self"]
		// in a private temp directory. If a policy.toml already exists next to the identity,
		// or PolicyPath is set, return an error since they cannot be combined.
		if n.opts.PolicyPath != "" {
			return errors.New("OutboundOnly cannot be used with PolicyPath; choose one")
		}
		var err error
		policyPath, err = n.prepareOutboundOnlyPolicy()
		if err != nil {
			return fmt.Errorf("prepare outbound-only policy: %w", err)
		}
	} else if n.opts.PolicyPath != "" {
		// Use custom policy file if provided
		policyPath = n.opts.PolicyPath
	}
	// If neither OutboundOnly nor PolicyPath is set, the daemon will default to
	// policy.toml next to the identity file (handled in daemon.NewFromConfig).

	// Build internal config for daemon (coord mode with userspace TUN)
	cfg := &config.Config{
		Node: config.NodeConfig{
			IdentityPath: n.opts.IdentityPath,
			ListenAddr:   n.opts.ListenAddr,
			NetworkID:    hex.EncodeToString(n.networkID[:]),
			IfaceName:    "",
			MTU:          n.opts.MTU,
			SubnetRoutes: n.opts.SubnetRoutes,
			Userspace:    n.opts.Userspace,
		},
		Coord: config.CoordConfig{
			Addr:        n.opts.CoordAddr,
			NetworkID:   hex.EncodeToString(n.networkID[:]),
			Token:       token,
			TLSInsecure: n.opts.CoordTLSInsecure,
			STUNServer:  n.opts.STUNServer,
			RelayAddr:   n.opts.RelayAddr,
			RelayX25519: n.opts.RelayX25519,
		},
		MDNS: config.MDNSConfig{
			Enabled: false,
			Name:    n.opts.NodeName,
		},
		DNS: config.DNSConfig{
			Enabled: false,
		},
		Daemon: config.DaemonConfig{
			SocketPath: "",
			Policy: config.PolicyConfig{
				LocalFile: policyPath,
			},
		},
		Peers: nil,
	}

	// Create daemon in coord mode
	d, err := daemon.NewFromConfig(cfg)
	if err != nil {
		if n.policyDir != "" {
			if cleanupErr := os.RemoveAll(n.policyDir); cleanupErr != nil {
				log.Printf("cleanup policy dir: %v", cleanupErr)
			}
		}
		return fmt.Errorf("create daemon: %w", err)
	}

	// Get the coord client from the daemon (already configured with onVPNAddrAssigned)
	coordCli := d.CoordClient()
	if coordCli == nil {
		d.Stop()
		d.Wait()
		if n.policyDir != "" {
			if cleanupErr := os.RemoveAll(n.policyDir); cleanupErr != nil {
				log.Printf("cleanup policy dir: %v", cleanupErr)
			}
		}
		return errors.New("coord client not created")
	}

	// Start daemon (dispatcher, handshake manager, etc.)
	d.Start()

	// Wait for VPN address assignment by polling the coord client
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			coordCli.Stop()
			coordCli.Wait()
			d.Stop()
			d.Wait()
			if n.policyDir != "" {
				if cleanupErr := os.RemoveAll(n.policyDir); cleanupErr != nil {
					log.Printf("cleanup policy dir: %v", cleanupErr)
				}
			}
			return ctx.Err()
		case <-ticker.C:
			vpnAddr := coordCli.VPNAddr()
			if vpnAddr.IsValid() {
				n.mu.Lock()
				n.vpnAddr = vpnAddr
				n.peerID = coordCli.PeerID()
				n.d = d
				n.coordClient = coordCli
				n.mu.Unlock()
				return nil
			}
		}
	}
}

// prepareOutboundOnlyPolicy creates a private temp directory and writes a local ACL
// policy file with outbound_only = ["self"] into it. Returns the path to the
// policy file, or an error if a policy.toml already exists next to the identity.
func (n *Node) prepareOutboundOnlyPolicy() (string, error) {
	identityDir := filepath.Dir(n.opts.IdentityPath)
	existingPolicyPath := filepath.Join(identityDir, "policy.toml")

	// If a policy.toml already exists next to the identity, we cannot combine
	// OutboundOnly with a custom policy. Return an error.
	if _, err := os.Stat(existingPolicyPath); err == nil {
		return "", fmt.Errorf("OutboundOnly cannot be used with an existing policy.toml at %s; remove the file or disable OutboundOnly", existingPolicyPath)
	}

	// Create a private temp directory owned by this Node.
	policyDir, err := os.MkdirTemp("", "veldnet-outbound-*")
	if err != nil {
		return "", fmt.Errorf("create temp policy dir: %w", err)
	}
	n.policyDir = policyDir

	// Build policy with self peer and outbound_only = ["self"]
	ed25519Pub := base64.StdEncoding.EncodeToString(n.localID.Ed25519Public)
	selfKey := "ed25519:" + ed25519Pub

	policy := fmt.Sprintf(`version = 1
default = "allow"
[peers]
self = "%s"
[outbound_only]
peers = ["self"]
`, selfKey)

	policyPath := filepath.Join(policyDir, "policy.toml")
	if err := os.WriteFile(policyPath, []byte(policy), 0600); err != nil {
		if cleanupErr := os.RemoveAll(policyDir); cleanupErr != nil {
			log.Printf("cleanup policy dir: %v", cleanupErr)
		}
		n.policyDir = ""
		return "", fmt.Errorf("write outbound-only policy: %w", err)
	}

	return policyPath, nil
}

// VPNAddr returns the VPN address assigned by the coordinator.
// Returns the zero value until Start completes successfully.
func (n *Node) VPNAddr() netip.Addr {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.vpnAddr
}

// PeerID returns the peer ID assigned by the coordinator.
// Returns empty string until Start completes successfully.
func (n *Node) PeerID() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.peerID
}

// DialContext establishes a connection to a peer in the mesh.
// network must be "tcp", "tcp4", or "tcp6".
// addr is the peer's VPN address and port (e.g., "10.100.0.5:8080").
// The connection is routed through the mesh VPN using the netstack.
func (n *Node) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	n.mu.Lock()
	d := n.d
	n.mu.Unlock()

	if d == nil {
		return nil, errors.New("node not started")
	}

	// Get the TUN device (netstack in userspace mode)
	tunDev := d.TUN()
	if tunDev == nil {
		return nil, errors.New("TUN not ready (VPN address not assigned yet)")
	}

	// Use the netstack's DialContext to route through the mesh
	return tunDev.DialContext(ctx, network, addr)
}

// Close stops the node and deregisters from the coordinator.
func (n *Node) Close() error {
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return nil // idempotent
	}
	n.closed = true
	d := n.d
	coordCli := n.coordClient
	policyDir := n.policyDir
	n.mu.Unlock()

	var closeErr error
	if coordCli != nil {
		coordCli.Stop()
		coordCli.Wait()
	}
	if d != nil {
		d.Stop()
		d.Wait()
	}
	if policyDir != "" {
		if err := os.RemoveAll(policyDir); err != nil {
			closeErr = fmt.Errorf("remove policy dir: %w", err)
		}
	}
	return closeErr
}
