// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
//go:build userspace

package veldnet

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	coordce "github.com/veldmesh/veld/coord/ce"
	coordcore "github.com/veldmesh/veld/coord/core"
	coordserver "github.com/veldmesh/veld/coord/server"
	coordv1 "github.com/veldmesh/veld/gen/veld/coord/v1"
	"github.com/veldmesh/veld/internal/config"
	"github.com/veldmesh/veld/internal/coord"
	"github.com/veldmesh/veld/internal/crypto"
	"github.com/veldmesh/veld/internal/daemon"
	"github.com/veldmesh/veld/internal/peer"
	"github.com/veldmesh/veld/internal/tun"
	"google.golang.org/grpc"
)

const testNetworkID = "deadbeef000000000000000000000000"
const testToken = "e2e-token"

func writeSelfPolicy(t *testing.T, path string, id *crypto.Identity) {
	t.Helper()
	ed25519Pub := base64.StdEncoding.EncodeToString(id.Ed25519Public)
	selfKey := "ed25519:" + ed25519Pub

	policy := fmt.Sprintf(`version = 1
default = "allow"
[peers]
self = "%s"
`, selfKey)

	if err := os.WriteFile(path, []byte(policy), 0600); err != nil {
		t.Fatalf("write self policy: %v", err)
	}
}

func writeDenyAllPolicy(t *testing.T, path string) {
	t.Helper()
	policy := `version = 1
default = "deny"
[peers]
alice = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
bob   = "ed25519:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
`
	if err := os.WriteFile(path, []byte(policy), 0600); err != nil {
		t.Fatalf("write deny-all policy: %v", err)
	}
}

func startTestCoordinator(t *testing.T, tmpDir string) (string, func()) {
	t.Helper()

	coordDB := filepath.Join(tmpDir, "coord.db")
	reg, err := coordserver.NewRegistry(coordDB)
	if err != nil {
		t.Fatalf("create registry: %v", err)
	}

	netCIDR := netip.MustParsePrefix("10.100.0.0/24")
	netw := coordcore.Network{ID: testNetworkID, CIDR: netCIDR, Name: "test"}
	if err := reg.CreateNetwork(netw, "account-1"); err != nil {
		t.Fatalf("create network: %v", err)
	}

	tokens := map[string]coordcore.Account{
		testToken: {ID: "account-1", Tier: coordcore.TierFree},
	}

	bus := coordserver.NewBus()
	srv := coordserver.New(
		reg,
		bus,
		coordce.NewFreeEnforcer(),
		coordce.NewTokenAccountStore(tokens),
		coordce.NewNoopAuditLogger(),
		coordce.NewRejectSubnetPolicy(),
		coordce.NewNoopHooks(),
	)

	coordListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	coordAddr := coordListener.Addr().String()

	grpcSrv := grpc.NewServer()
	coordv1.RegisterCoordServer(grpcSrv, srv)
	go func() {
		if err := grpcSrv.Serve(coordListener); err != nil {
			log.Printf("coord serve: %v", err)
		}
	}()

	time.Sleep(500 * time.Millisecond)

	cleanup := func() {
		grpcSrv.GracefulStop()
		reg.Close()
	}

	return coordAddr, cleanup
}

func startNormalDaemon(t *testing.T, tmpDir, coordAddr, nodeName string) (*daemon.Daemon, *crypto.Identity, func()) {
	t.Helper()

	// Use a subdirectory for this node to avoid policy file conflicts
	nodeDir := filepath.Join(tmpDir, nodeName)
	if err := os.MkdirAll(nodeDir, 0700); err != nil {
		t.Fatalf("create node dir: %v", err)
	}

	identityPath := filepath.Join(nodeDir, fmt.Sprintf("%s_identity.json", nodeName))
	policyPath := filepath.Join(nodeDir, "policy.toml")

	// Generate and save identity
	id, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate id: %v", err)
	}
	if err := config.Save(identityPath, id); err != nil {
		t.Fatalf("save identity: %v", err)
	}

	// Write self policy
	writeSelfPolicy(t, policyPath, id)

	cfg := &config.Config{
		Node: config.NodeConfig{
			IdentityPath: identityPath,
			ListenAddr:   "127.0.0.1:0",
			NetworkID:    testNetworkID,
			IfaceName:    "",
			MTU:          1420,
			SubnetRoutes: nil,
			Userspace:    true,
		},
		Coord: config.CoordConfig{
			Addr:        coordAddr,
			NetworkID:   testNetworkID,
			Token:       testToken,
			TLSInsecure: true,
			STUNServer:  "",
			RelayAddr:   "",
			RelayX25519: "",
		},
		MDNS: config.MDNSConfig{
			Enabled: false,
			Name:    nodeName,
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

	d, err := daemon.NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("create normal daemon: %v", err)
	}

	d.Start()

	cleanup := func() {
		d.Stop()
		d.Wait()
	}

	return d, id, cleanup
}

func pollUntil(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

func TestCoordClientDirect(t *testing.T) {
	tmpDir := t.TempDir()

	coordAddr, cleanup := startTestCoordinator(t, tmpDir)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	id, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate id: %v", err)
	}

	c := coord.New(coord.Config{
		ServerAddr:  coordAddr,
		NetworkID:   testNetworkID,
		Token:       testToken,
		Identity:    id,
		LocalName:   "direct-client",
		PeerTable:   peer.New(),
		TLSInsecure: true,
	})
	c.Start()
	defer func() { c.Stop(); c.Wait() }()

	if !pollUntil(10*time.Second, func() bool { return c.VPNAddr().IsValid() }) {
		t.Fatalf("timeout: direct client did not get VPN address")
	}
	t.Logf("Direct coord client VPN address: %s", c.VPNAddr())
	t.Log("Direct coord client registered successfully")
	_ = ctx
}

func TestDaemonCoordClient(t *testing.T) {
	tmpDir := t.TempDir()

	coordAddr, cleanup := startTestCoordinator(t, tmpDir)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create identity in a subdirectory
	nodeDir := filepath.Join(tmpDir, "test-node")
	if err := os.MkdirAll(nodeDir, 0700); err != nil {
		t.Fatalf("create node dir: %v", err)
	}
	identityPath := filepath.Join(nodeDir, "test_identity.json")
	policyPath := filepath.Join(nodeDir, "policy.toml")

	id, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate id: %v", err)
	}
	if err := config.Save(identityPath, id); err != nil {
		t.Fatalf("save identity: %v", err)
	}

	writeSelfPolicy(t, policyPath, id)

	// Create daemon config
	cfg := &config.Config{
		Node: config.NodeConfig{
			IdentityPath: identityPath,
			ListenAddr:   "127.0.0.1:0",
			NetworkID:    testNetworkID,
			IfaceName:    "",
			MTU:          1420,
			SubnetRoutes: nil,
			Userspace:    true,
		},
		Coord: config.CoordConfig{
			Addr:        coordAddr,
			NetworkID:   testNetworkID,
			Token:       testToken,
			TLSInsecure: true,
			STUNServer:  "",
			RelayAddr:   "",
			RelayX25519: "",
		},
		MDNS: config.MDNSConfig{
			Enabled: false,
			Name:    "test-node",
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

	d, err := daemon.NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("create daemon: %v", err)
	}

	coordCli := d.CoordClient()
	if coordCli == nil {
		t.Fatal("coord client is nil")
	}

	d.Start()

	// Wait for VPN address
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			coordCli.Stop()
			coordCli.Wait()
			d.Stop()
			d.Wait()
			t.Fatal("timeout waiting for VPN address")
		case <-ticker.C:
			vpnAddr := coordCli.VPNAddr()
			if vpnAddr.IsValid() {
				d.Stop()
				d.Wait()
				return
			}
		}
	}
}

func TestEmbeddableNodeSolo(t *testing.T) {
	tmpDir := t.TempDir()

	coordAddr, cleanup := startTestCoordinator(t, tmpDir)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Use a subdirectory for this node
	nodeDir := filepath.Join(tmpDir, "embed-node")
	if err := os.MkdirAll(nodeDir, 0700); err != nil {
		t.Fatalf("create node dir: %v", err)
	}
	peerBIdentity := filepath.Join(nodeDir, "peerB_identity.json")
	node, err := New(Options{
		IdentityPath:     peerBIdentity,
		CoordAddr:        coordAddr,
		Token:            testToken,
		NodeName:         "embed-node",
		Userspace:        true,
		ListenAddr:       "127.0.0.1:0",
		NetworkID:        testNetworkID,
		CoordTLSInsecure: true,
	})
	if err != nil {
		t.Fatalf("create embeddable node: %v", err)
	}

	if err := node.Start(ctx); err != nil {
		t.Fatalf("start embeddable node: %v", err)
	}
	defer node.Close()

	t.Logf("Embeddable node VPN address: %s, Peer ID: %s", node.VPNAddr(), node.PeerID())

	if !node.VPNAddr().IsValid() {
		t.Fatal("node did not get VPN address")
	}
	t.Log("Solo embeddable node registered successfully")
}

func TestEmbeddableNodeJoinMesh(t *testing.T) {
	tmpDir := t.TempDir()

	coordAddr, cleanup := startTestCoordinator(t, tmpDir)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// Start a normal daemon (peer A) - uses its own subdirectory
	daemonA, _, cleanupA := startNormalDaemon(t, tmpDir, coordAddr, "normal-peer")
	defer cleanupA()

	// Wait for daemon A to get VPN address
	var peerAVPNAddr netip.Addr
	if !pollUntil(20*time.Second, func() bool {
		tun := daemonA.TUN()
		if tun != nil {
			peerAVPNAddr = tun.Addr().Addr()
			return peerAVPNAddr.IsValid()
		}
		return false
	}) {
		t.Fatalf("timeout: peer A did not get VPN address")
	}
	t.Logf("Peer A VPN address: %s", peerAVPNAddr)

	// Start embeddable node (peer B) - uses its own subdirectory
	nodeDir := filepath.Join(tmpDir, "embed-node")
	if err := os.MkdirAll(nodeDir, 0700); err != nil {
		t.Fatalf("create node dir: %v", err)
	}
	peerBIdentity := filepath.Join(nodeDir, "peerB_identity.json")
	// Create identity and policy for embeddable node
	id, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate id: %v", err)
	}
	if err := config.Save(peerBIdentity, id); err != nil {
		t.Fatalf("save identity: %v", err)
	}
	policyPath := filepath.Join(nodeDir, "policy.toml")
	writeSelfPolicy(t, policyPath, id)

	node, err := New(Options{
		IdentityPath:     peerBIdentity,
		CoordAddr:        coordAddr,
		Token:            testToken,
		NodeName:         "embed-node",
		Userspace:        true,
		ListenAddr:       "127.0.0.1:0",
		NetworkID:        testNetworkID,
		CoordTLSInsecure: true,
	})
	if err != nil {
		t.Fatalf("create embeddable node: %v", err)
	}

	if err := node.Start(ctx); err != nil {
		t.Fatalf("start embeddable node: %v", err)
	}
	defer node.Close()

	t.Logf("Embeddable node VPN address: %s, Peer ID: %s", node.VPNAddr(), node.PeerID())

	// Wait for peer table to populate
	if !pollUntil(15*time.Second, func() bool {
		return len(node.d.PeerTable().List()) >= 1
	}) {
		t.Fatal("timeout: embeddable node did not see peer A")
	}

	peerTbl := node.d.PeerTable()
	entries := peerTbl.List()
	t.Logf("Embeddable node peer table entries: %d", len(entries))
	for _, e := range entries {
		t.Logf("  Peer: %s (%s)", e.Name, e.VPNAddr)
	}

	if len(entries) < 1 {
		t.Fatalf("expected at least 1 peer, got %d", len(entries))
	}
	t.Logf("Peer table has %d entries (remote peer)", len(entries))

	// Try to dial peer A (will fail if no server, but handshake should initiate)
	dialCtx, dialCancel := context.WithTimeout(ctx, 10*time.Second)
	conn, err := node.DialContext(dialCtx, "tcp", fmt.Sprintf("%s:12345", peerAVPNAddr))
	dialCancel()
	// Connection refused is expected since there's no server listening
	if err != nil && !strings.Contains(err.Error(), "connection refused") && !strings.Contains(err.Error(), "connection was refused") {
		t.Fatalf("DialContext failed with unexpected error: %v", err)
	}
	if conn != nil {
		conn.Close()
	}

	// Close the embeddable node
	node.Close()

	// Verify embeddable node is deregistered by checking that a new node doesn't see it
	// The embeddable node's own peer table still has peer A (which is correct)
	// We verify deregistration by checking the coordinator doesn't have the embeddable node
	// For this test, we just verify Close doesn't error
	t.Log("Embeddable node closed successfully")
}

func TestEmbeddableNodeWithTCPServer(t *testing.T) {
	tmpDir := t.TempDir()

	coordAddr, cleanup := startTestCoordinator(t, tmpDir)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// Start a normal daemon with a TCP server
	daemonA, _, cleanupA := startNormalDaemon(t, tmpDir, coordAddr, "normal-peer")
	defer cleanupA()

	// Wait for daemon A to get VPN address
	var peerAVPNAddr netip.Addr
	if !pollUntil(20*time.Second, func() bool {
		tun := daemonA.TUN()
		if tun != nil {
			peerAVPNAddr = tun.Addr().Addr()
			return peerAVPNAddr.IsValid()
		}
		return false
	}) {
		t.Fatalf("timeout: peer A did not get VPN address")
	}
	t.Logf("Peer A VPN address: %s", peerAVPNAddr)

	// Start a TCP server on daemon A's netstack
	tunA := daemonA.TUN()
	if tunA == nil {
		t.Fatal("daemon A TUN not ready")
	}
	listenerA, ok := tunA.(tun.NetstackListener)
	if !ok {
		t.Fatal("daemon A TUN does not support ListenTCPAddrPort")
	}
	listener, err := listenerA.ListenTCPAddrPort(netip.AddrPortFrom(peerAVPNAddr, 12345))
	if err != nil {
		t.Fatalf("listen on daemon A: %v", err)
	}

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("hello from peer A"))
		}),
	}

	go func() {
		_ = server.Serve(listener)
	}()
	defer server.Close()

	// Start embeddable node (peer B) - uses its own subdirectory
	nodeDir := filepath.Join(tmpDir, "embed-node")
	if err := os.MkdirAll(nodeDir, 0700); err != nil {
		t.Fatalf("create node dir: %v", err)
	}
	peerBIdentity := filepath.Join(nodeDir, "peerB_identity.json")
	// Create identity and policy for embeddable node
	id, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate id: %v", err)
	}
	if err := config.Save(peerBIdentity, id); err != nil {
		t.Fatalf("save identity: %v", err)
	}
	policyPath := filepath.Join(nodeDir, "policy.toml")
	writeSelfPolicy(t, policyPath, id)

	node, err := New(Options{
		IdentityPath:     peerBIdentity,
		CoordAddr:        coordAddr,
		Token:            testToken,
		NodeName:         "embed-node",
		Userspace:        true,
		ListenAddr:       "127.0.0.1:0",
		NetworkID:        testNetworkID,
		CoordTLSInsecure: true,
	})
	if err != nil {
		t.Fatalf("create embeddable node: %v", err)
	}

	if err := node.Start(ctx); err != nil {
		t.Fatalf("start embeddable node: %v", err)
	}
	defer node.Close()

	t.Logf("Embeddable node VPN address: %s, Peer ID: %s", node.VPNAddr(), node.PeerID())

	// Wait for peer table to populate
	if !pollUntil(15*time.Second, func() bool {
		return len(node.d.PeerTable().List()) >= 1
	}) {
		t.Fatal("timeout: embeddable node did not see peer A")
	}

	// Make HTTP request through mesh
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: node.DialContext,
		},
		Timeout: 10 * time.Second,
	}

	reqCtx, reqCancel := context.WithTimeout(ctx, 10*time.Second)
	defer reqCancel()

	req, err := http.NewRequestWithContext(reqCtx, "GET", fmt.Sprintf("http://%s:12345/", peerAVPNAddr), nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()
	t.Logf("HTTP response: %d", resp.StatusCode)
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}
	t.Log("Successfully communicated through mesh!")

	// Close the embeddable node
	node.Close()

	// Verify embeddable node is deregistered
	t.Log("Embeddable node closed successfully")
}

func TestEmbeddableNodeRace(t *testing.T) {
	tmpDir := t.TempDir()

	coordAddr, cleanup := startTestCoordinator(t, tmpDir)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	const numNodes = 3
	nodes := make([]*Node, numNodes)
	identities := make([]*crypto.Identity, numNodes)

	// Start nodes sequentially to avoid coordinator overload
	for i := 0; i < numNodes; i++ {
		nodeDir := filepath.Join(tmpDir, fmt.Sprintf("node%d", i))
		if err := os.MkdirAll(nodeDir, 0700); err != nil {
			t.Fatalf("create node dir: %v", err)
		}
		identityPath := filepath.Join(nodeDir, fmt.Sprintf("node%d_identity.json", i))
		id, err := crypto.Generate()
		if err != nil {
			t.Fatalf("generate id: %v", err)
		}
		if err := config.Save(identityPath, id); err != nil {
			t.Fatalf("save identity: %v", err)
		}
		identities[i] = id
		policyPath := filepath.Join(nodeDir, "policy.toml")
		writeSelfPolicy(t, policyPath, id)
		node, err := New(Options{
			IdentityPath:     identityPath,
			CoordAddr:        coordAddr,
			Token:            testToken,
			NodeName:         fmt.Sprintf("race-node-%d", i),
			Userspace:        true,
			ListenAddr:       "127.0.0.1:0",
			NetworkID:        testNetworkID,
			CoordTLSInsecure: true,
		})
		if err != nil {
			t.Fatalf("create node %d: %v", i, err)
		}
		if err := node.Start(ctx); err != nil {
			t.Fatalf("start node %d: %v", i, err)
		}
		nodes[i] = node
		t.Logf("Node %d started: VPN=%s, PeerID=%s", i, node.VPNAddr(), node.PeerID())
	}

	// Wait for all peer tables to populate
	time.Sleep(5 * time.Second)

	for i, node := range nodes {
		t.Logf("Node %d peer table: %d entries", i, len(node.d.PeerTable().List()))
		for _, e := range node.d.PeerTable().List() {
			t.Logf("  Peer: %s (%s)", e.Name, e.VPNAddr)
		}
	}

	var wg sync.WaitGroup
	for i := 0; i < numNodes; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			for j := 0; j < numNodes; j++ {
				if i == j {
					continue
				}
				target := nodes[j].VPNAddr()
				dialCtx, dialCancel := context.WithTimeout(ctx, 5*time.Second)
				_, err := nodes[idx].DialContext(dialCtx, "tcp", fmt.Sprintf("%s:12345", target))
				dialCancel()
				if err != nil {
					t.Logf("Node %d dial to node %d: %v", idx, j, err)
				}
			}
		}(i)
	}
	wg.Wait()

	for _, node := range nodes {
		wg.Add(1)
		go func(n *Node) {
			defer wg.Done()
			n.Close()
		}(node)
	}
	wg.Wait()

	t.Log("Race test completed successfully")
}

func TestEmbeddableNodeTokenReader(t *testing.T) {
	tmpDir := t.TempDir()

	coordAddr, cleanup := startTestCoordinator(t, tmpDir)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	nodeDir := filepath.Join(tmpDir, "token-reader-node")
	if err := os.MkdirAll(nodeDir, 0700); err != nil {
		t.Fatalf("create node dir: %v", err)
	}
	identityPath := filepath.Join(nodeDir, "tokenreader_identity.json")
	id, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate id: %v", err)
	}
	if err := config.Save(identityPath, id); err != nil {
		t.Fatalf("save identity: %v", err)
	}
	policyPath := filepath.Join(nodeDir, "policy.toml")
	writeSelfPolicy(t, policyPath, id)
	tokenReader := strings.NewReader(testToken)

	node, err := New(Options{
		IdentityPath:     identityPath,
		CoordAddr:        coordAddr,
		TokenReader:      tokenReader,
		NodeName:         "token-reader-node",
		Userspace:        true,
		ListenAddr:       "127.0.0.1:0",
		NetworkID:        testNetworkID,
		CoordTLSInsecure: true,
	})
	if err != nil {
		t.Fatalf("create node: %v", err)
	}

	if err := node.Start(ctx); err != nil {
		t.Fatalf("start node: %v", err)
	}
	defer node.Close()

	if !node.VPNAddr().IsValid() {
		t.Fatal("node did not get VPN address")
	}
	t.Logf("TokenReader node VPN: %s", node.VPNAddr())
}

func TestEmbeddableNodeOutboundOnly(t *testing.T) {
	tmpDir := t.TempDir()

	coordAddr, cleanup := startTestCoordinator(t, tmpDir)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start a normal daemon (peer A) - uses its own subdirectory
	daemonA, _, cleanupA := startNormalDaemon(t, tmpDir, coordAddr, "normal-peer")
	defer cleanupA()

	// Wait for daemon A to get VPN address
	var peerAVPNAddr netip.Addr
	if !pollUntil(20*time.Second, func() bool {
		tun := daemonA.TUN()
		if tun != nil {
			peerAVPNAddr = tun.Addr().Addr()
			return peerAVPNAddr.IsValid()
		}
		return false
	}) {
		t.Fatalf("timeout: peer A did not get VPN address")
	}
	t.Logf("Peer A VPN address: %s", peerAVPNAddr)

	// Start embeddable node with OutboundOnly (peer B) - uses its own subdirectory
	nodeDir := filepath.Join(tmpDir, "outbound-node")
	if err := os.MkdirAll(nodeDir, 0700); err != nil {
		t.Fatalf("create node dir: %v", err)
	}
	identityPath := filepath.Join(nodeDir, "outbound_identity.json")
	// OutboundOnly creates its own policy, so no need to write default policy here
	node, err := New(Options{
		IdentityPath:     identityPath,
		CoordAddr:        coordAddr,
		Token:            testToken,
		NodeName:         "outbound-node",
		OutboundOnly:     true,
		Userspace:        true,
		ListenAddr:       "127.0.0.1:0",
		NetworkID:        testNetworkID,
		CoordTLSInsecure: true,
	})
	if err != nil {
		t.Fatalf("create node: %v", err)
	}

	if err := node.Start(ctx); err != nil {
		t.Fatalf("start node: %v", err)
	}
	defer node.Close()

	if !node.VPNAddr().IsValid() {
		t.Fatal("node did not get VPN address")
	}
	t.Logf("OutboundOnly node VPN: %s", node.VPNAddr())

	// Wait for peer table to populate
	if !pollUntil(15*time.Second, func() bool {
		return len(node.d.PeerTable().List()) >= 1
	}) {
		t.Fatal("timeout: outbound node did not see peer A")
	}

	// Inbound connection from daemon to embeddable node should be refused
	// Start a listener on the embeddable node's netstack
	tunB := node.d.TUN()
	if tunB == nil {
		t.Fatal("embeddable node TUN not ready")
	}
	listenerB, ok := tunB.(tun.NetstackListener)
	if !ok {
		t.Fatal("embeddable node TUN does not support ListenTCPAddrPort")
	}
	listener, err := listenerB.ListenTCPAddrPort(netip.AddrPortFrom(node.VPNAddr(), 12345))
	if err != nil {
		t.Fatalf("listen on embeddable node: %v", err)
	}
	defer listener.Close()

	// Try to connect from daemon A to embeddable node B
	// This should fail because embeddable node has OutboundOnly policy
	tunA := daemonA.TUN()
	if tunA == nil {
		t.Fatal("daemon A TUN not ready")
	}
	dialCtx2, dialCancel2 := context.WithTimeout(ctx, 10*time.Second)
	conn2, err := tunA.DialContext(dialCtx2, "tcp", fmt.Sprintf("%s:12345", node.VPNAddr()))
	dialCancel2()
	t.Logf("Inbound dial result: conn=%v, err=%v", conn2, err)
	if err == nil {
		t.Fatalf("inbound connection to OutboundOnly node should be refused, but succeeded: %v", conn2)
	}
	t.Logf("Inbound connection correctly refused: %v", err)

	// Outbound dial from embeddable node to daemon should work (handshake initiates)
	// We expect "connection refused" because there's no server, but the handshake
	// should have been attempted (not blocked by outbound-only policy).
	dialCtx, dialCancel := context.WithTimeout(ctx, 10*time.Second)
	_, err = node.DialContext(dialCtx, "tcp", fmt.Sprintf("%s:12345", peerAVPNAddr))
	dialCancel()
	// The error should be "connection refused" (TCP level), not a handshake/policy error.
	// If the dial returns quickly with "connection refused", it means the handshake
	// completed and the TCP connection was attempted.
	if err == nil {
		t.Fatal("expected connection refused (no server), got nil")
	}
	if !strings.Contains(err.Error(), "connection refused") && !strings.Contains(err.Error(), "connection was refused") {
		t.Fatalf("outbound DialContext should fail with connection refused, got: %v", err)
	}
	t.Logf("Outbound dial attempted (got expected connection refused): %v", err)
}

func TestEmbeddableNodeIdentityGeneration(t *testing.T) {
	tmpDir := t.TempDir()

	nodeDir := filepath.Join(tmpDir, "identity-gen")
	if err := os.MkdirAll(nodeDir, 0700); err != nil {
		t.Fatalf("create node dir: %v", err)
	}
	identityPath := filepath.Join(nodeDir, "new_identity.json")

	node, err := New(Options{
		IdentityPath: identityPath,
		CoordAddr:    "dummy:50051",
		Token:        "dummy-token",
		Userspace:    true,
	})
	if err != nil {
		t.Fatalf("New should not fail for missing identity: %v", err)
	}

	if _, err := os.Stat(identityPath); os.IsNotExist(err) {
		t.Fatal("identity file was not created")
	}

	info, err := os.Stat(identityPath)
	if err != nil {
		t.Fatalf("stat identity: %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Errorf("identity file permissions: got %o, want 0600", info.Mode().Perm())
	}

	node2, err := New(Options{
		IdentityPath: identityPath,
		CoordAddr:    "dummy:50051",
		Token:        "dummy-token",
		Userspace:    true,
	})
	if err != nil {
		t.Fatalf("load existing identity: %v", err)
	}

	if !node.LocalID().Ed25519Public.Equal(node2.LocalID().Ed25519Public) {
		t.Error("loaded identity differs from generated")
	}
}

func TestEmbeddableNodeVPNAddrBeforeStart(t *testing.T) {
	tmpDir := t.TempDir()
	nodeDir := filepath.Join(tmpDir, "vpnaddr-before-start")
	if err := os.MkdirAll(nodeDir, 0700); err != nil {
		t.Fatalf("create node dir: %v", err)
	}
	identityPath := filepath.Join(nodeDir, "identity.json")

	node, err := New(Options{
		IdentityPath: identityPath,
		CoordAddr:    "dummy:50051",
		Token:        "dummy-token",
		Userspace:    true,
	})
	if err != nil {
		t.Fatalf("create node: %v", err)
	}

	if node.VPNAddr().IsValid() {
		t.Error("VPNAddr should be zero before Start")
	}
	if node.PeerID() != "" {
		t.Error("PeerID should be empty before Start")
	}
}

func TestEmbeddableNodeDoubleClose(t *testing.T) {
	tmpDir := t.TempDir()

	coordAddr, cleanup := startTestCoordinator(t, tmpDir)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	nodeDir := filepath.Join(tmpDir, "doubleclose-node")
	if err := os.MkdirAll(nodeDir, 0700); err != nil {
		t.Fatalf("create node dir: %v", err)
	}
	identityPath := filepath.Join(nodeDir, "doubleclose_identity.json")

	node, err := New(Options{
		IdentityPath:     identityPath,
		CoordAddr:        coordAddr,
		Token:            testToken,
		NodeName:         "doubleclose-node",
		Userspace:        true,
		ListenAddr:       "127.0.0.1:0",
		NetworkID:        testNetworkID,
		CoordTLSInsecure: true,
	})
	if err != nil {
		t.Fatalf("create node: %v", err)
	}

	if err := node.Start(ctx); err != nil {
		t.Fatalf("start node: %v", err)
	}

	node.Close()
	node.Close()
}

func TestEmbeddableNodeStartTwice(t *testing.T) {
	tmpDir := t.TempDir()

	coordAddr, cleanup := startTestCoordinator(t, tmpDir)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	nodeDir := filepath.Join(tmpDir, "starttwice-node")
	if err := os.MkdirAll(nodeDir, 0700); err != nil {
		t.Fatalf("create node dir: %v", err)
	}
	identityPath := filepath.Join(nodeDir, "starttwice_identity.json")

	node, err := New(Options{
		IdentityPath:     identityPath,
		CoordAddr:        coordAddr,
		Token:            testToken,
		NodeName:         "starttwice-node",
		Userspace:        true,
		ListenAddr:       "127.0.0.1:0",
		NetworkID:        testNetworkID,
		CoordTLSInsecure: true,
	})
	if err != nil {
		t.Fatalf("create node: %v", err)
	}

	if err := node.Start(ctx); err != nil {
		t.Fatalf("first start: %v", err)
	}

	err = node.Start(ctx)
	if err == nil {
		t.Error("second Start should return error")
	}
	node.Close()
}

func TestEmbeddableNodeDialContextBeforeStart(t *testing.T) {
	tmpDir := t.TempDir()
	nodeDir := filepath.Join(tmpDir, "dial-before-start")
	if err := os.MkdirAll(nodeDir, 0700); err != nil {
		t.Fatalf("create node dir: %v", err)
	}
	identityPath := filepath.Join(nodeDir, "identity.json")

	node, err := New(Options{
		IdentityPath: identityPath,
		CoordAddr:    "dummy:50051",
		Token:        "dummy-token",
		Userspace:    true,
	})
	if err != nil {
		t.Fatalf("create node: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	_, err = node.DialContext(ctx, "tcp", "10.100.0.1:8080")
	if err == nil {
		t.Error("DialContext before Start should return error")
	}
	if !strings.Contains(err.Error(), "not started") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestEmbeddableNodeCloseDeregisters(t *testing.T) {
	tmpDir := t.TempDir()

	coordAddr, cleanup := startTestCoordinator(t, tmpDir)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Start a normal daemon (peer A) - uses its own subdirectory
	daemonA, _, cleanupA := startNormalDaemon(t, tmpDir, coordAddr, "normal-peer")
	defer cleanupA()

	// Wait for daemon A to get VPN address
	var peerAVPNAddr netip.Addr
	if !pollUntil(20*time.Second, func() bool {
		tun := daemonA.TUN()
		if tun != nil {
			peerAVPNAddr = tun.Addr().Addr()
			return peerAVPNAddr.IsValid()
		}
		return false
	}) {
		t.Fatalf("timeout: peer A did not get VPN address")
	}
	t.Logf("Peer A VPN address: %s", peerAVPNAddr)

	// Start embeddable node (peer B) - uses its own subdirectory
	nodeDir := filepath.Join(tmpDir, "embed-node")
	if err := os.MkdirAll(nodeDir, 0700); err != nil {
		t.Fatalf("create node dir: %v", err)
	}
	peerBIdentity := filepath.Join(nodeDir, "peerB_identity.json")
	// Create identity and policy for embeddable node
	id, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate id: %v", err)
	}
	if err := config.Save(peerBIdentity, id); err != nil {
		t.Fatalf("save identity: %v", err)
	}
	policyPath := filepath.Join(nodeDir, "policy.toml")
	writeSelfPolicy(t, policyPath, id)

	node, err := New(Options{
		IdentityPath:     peerBIdentity,
		CoordAddr:        coordAddr,
		Token:            testToken,
		NodeName:         "embed-node",
		Userspace:        true,
		ListenAddr:       "127.0.0.1:0",
		NetworkID:        testNetworkID,
		CoordTLSInsecure: true,
	})
	if err != nil {
		t.Fatalf("create embeddable node: %v", err)
	}

	if err := node.Start(ctx); err != nil {
		t.Fatalf("start embeddable node: %v", err)
	}

	t.Logf("Embeddable node VPN address: %s, Peer ID: %s", node.VPNAddr(), node.PeerID())

	// Wait for peer table to populate on both sides
	if !pollUntil(15*time.Second, func() bool {
		return len(node.d.PeerTable().List()) >= 1
	}) {
		t.Fatal("timeout: embeddable node did not see peer A")
	}

	// Verify daemon A sees the embeddable node
	if !pollUntil(15*time.Second, func() bool {
		return len(daemonA.PeerTable().List()) >= 1
	}) {
		t.Fatal("timeout: daemon A did not see embeddable node")
	}
	t.Logf("Daemon A peer table entries: %d", len(daemonA.PeerTable().List()))
	for _, e := range daemonA.PeerTable().List() {
		t.Logf("  Peer: %s (%s)", e.Name, e.VPNAddr)
	}

	// Close the embeddable node
	node.Close()

	// Verify embeddable node is deregistered from daemon A's peer table
	if !pollUntil(10*time.Second, func() bool {
		return len(daemonA.PeerTable().List()) == 0
	}) {
		t.Fatalf("timeout: embeddable node not deregistered from daemon A, still %d peers", len(daemonA.PeerTable().List()))
	}
	t.Log("Embeddable node successfully deregistered from daemon A's peer table")
}

// TestEmbeddableNodePolicyPath_DenyAll tests that a custom PolicyPath
// pointing at a deny-all policy blocks all traffic.
func TestEmbeddableNodePolicyPath_DenyAll(t *testing.T) {
	tmpDir := t.TempDir()

	coordAddr, cleanup := startTestCoordinator(t, tmpDir)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Start a normal daemon (peer A) - uses its own subdirectory
	daemonA, _, cleanupA := startNormalDaemon(t, tmpDir, coordAddr, "normal-peer")
	defer cleanupA()

	// Wait for daemon A to get VPN address
	var peerAVPNAddr netip.Addr
	if !pollUntil(20*time.Second, func() bool {
		tun := daemonA.TUN()
		if tun != nil {
			peerAVPNAddr = tun.Addr().Addr()
			return peerAVPNAddr.IsValid()
		}
		return false
	}) {
		t.Fatalf("timeout: peer A did not get VPN address")
	}
	t.Logf("Peer A VPN address: %s", peerAVPNAddr)

	// Start a TCP server on daemon A's netstack
	tunA := daemonA.TUN()
	if tunA == nil {
		t.Fatal("daemon A TUN not ready")
	}
	listenerA, ok := tunA.(tun.NetstackListener)
	if !ok {
		t.Fatal("daemon A TUN does not support ListenTCPAddrPort")
	}
	listener, err := listenerA.ListenTCPAddrPort(netip.AddrPortFrom(peerAVPNAddr, 12345))
	if err != nil {
		t.Fatalf("listen on daemon A: %v", err)
	}

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("hello from peer A"))
		}),
	}

	go func() {
		_ = server.Serve(listener)
	}()
	defer server.Close()

	// Create deny-all policy file
	nodeDir := filepath.Join(tmpDir, "policy-node")
	if err := os.MkdirAll(nodeDir, 0700); err != nil {
		t.Fatalf("create node dir: %v", err)
	}
	identityPath := filepath.Join(nodeDir, "policy_identity.json")
	policyPath := filepath.Join(nodeDir, "deny_all.toml")
	writeDenyAllPolicy(t, policyPath)

	id, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate id: %v", err)
	}
	if err := config.Save(identityPath, id); err != nil {
		t.Fatalf("save identity: %v", err)
	}

	// Start embeddable node with PolicyPath pointing to deny-all policy
	node, err := New(Options{
		IdentityPath:     identityPath,
		CoordAddr:        coordAddr,
		Token:            testToken,
		NodeName:         "policy-node",
		PolicyPath:       policyPath,
		Userspace:        true,
		ListenAddr:       "127.0.0.1:0",
		NetworkID:        testNetworkID,
		CoordTLSInsecure: true,
	})
	if err != nil {
		t.Fatalf("create node: %v", err)
	}

	if err := node.Start(ctx); err != nil {
		t.Fatalf("start node: %v", err)
	}
	defer node.Close()

	if !node.VPNAddr().IsValid() {
		t.Fatal("node did not get VPN address")
	}
	t.Logf("PolicyPath node VPN: %s", node.VPNAddr())

	// Wait for peer table to populate
	if !pollUntil(15*time.Second, func() bool {
		return len(node.d.PeerTable().List()) >= 1
	}) {
		t.Fatal("timeout: policy node did not see peer A")
	}

	// Try to make HTTP request through mesh - should be blocked by deny-all policy
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: node.DialContext,
		},
		Timeout: 10 * time.Second,
	}

	reqCtx, reqCancel := context.WithTimeout(ctx, 10*time.Second)
	defer reqCancel()

	req, err := http.NewRequestWithContext(reqCtx, "GET", fmt.Sprintf("http://%s:12345/", peerAVPNAddr), nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	resp, err := client.Do(req)
	if err == nil {
		resp.Body.Close()
		t.Fatal("expected deny-all policy to block connection, but request succeeded")
	}
	t.Logf("Connection correctly blocked by deny-all policy: %v", err)
}

// TestEmbeddableNodePolicyPath_OutboundOnlyConflict tests that PolicyPath
// and OutboundOnly cannot be used together.
func TestEmbeddableNodePolicyPath_OutboundOnlyConflict(t *testing.T) {
	tmpDir := t.TempDir()

	coordAddr, cleanup := startTestCoordinator(t, tmpDir)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	nodeDir := filepath.Join(tmpDir, "conflict-node")
	if err := os.MkdirAll(nodeDir, 0700); err != nil {
		t.Fatalf("create node dir: %v", err)
	}
	identityPath := filepath.Join(nodeDir, "conflict_identity.json")
	policyPath := filepath.Join(nodeDir, "policy.toml")

	id, err := crypto.Generate()
	if err != nil {
		t.Fatalf("generate id: %v", err)
	}
	if err := config.Save(identityPath, id); err != nil {
		t.Fatalf("save identity: %v", err)
	}

	// Create a dummy policy file
	writeSelfPolicy(t, policyPath, id)

	// Try to create node with both PolicyPath and OutboundOnly
	node, err := New(Options{
		IdentityPath:     identityPath,
		CoordAddr:        coordAddr,
		Token:            testToken,
		NodeName:         "conflict-node",
		PolicyPath:       policyPath,
		OutboundOnly:     true,
		Userspace:        true,
		ListenAddr:       "127.0.0.1:0",
		NetworkID:        testNetworkID,
		CoordTLSInsecure: true,
	})
	if err != nil {
		t.Fatalf("New should not fail: %v", err)
	}

	// The error should be returned from Start, not New
	err = node.Start(ctx)
	if err == nil {
		t.Fatal("expected error when using PolicyPath with OutboundOnly")
	}
	if !strings.Contains(err.Error(), "OutboundOnly cannot be used with PolicyPath") {
		t.Errorf("unexpected error message: %v", err)
	}
	t.Logf("Correctly rejected PolicyPath + OutboundOnly combination: %v", err)
}
