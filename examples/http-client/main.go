// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package main

import (
	"context"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/veldmesh/veld/pkg/veldnet"
)

func main() {
	var (
		identityPath = flag.String("identity", "", "path to identity file (created if missing)")
		coordAddr    = flag.String("coord", "", "coordinator address (e.g., coord.example.com:50051)")
		token        = flag.String("token", "", "enrollment token (or - for stdin)")
		nodeName     = flag.String("name", "", "node name (default: hostname)")
		target       = flag.String("target", "", "target URL (e.g., http://10.100.0.5:8080/)")
		outboundOnly = flag.Bool("outbound-only", false, "if set, node drops inbound connections (sets outbound_only=[\"self\"] in local ACL)")
		policyPath   = flag.String("policy", "", "path to local ACL policy file (optional)")
		tlsInsecure  = flag.Bool("tls-insecure", false, "disable TLS for coordinator connection (testing only)")
	)
	flag.Parse()

	if *identityPath == "" {
		log.Fatal("-identity is required")
	}
	if *coordAddr == "" {
		log.Fatal("-coord is required")
	}
	if *token == "" {
		log.Fatal("-token is required (use - to read from stdin)")
	}
	if *target == "" {
		log.Fatal("-target is required")
	}

	// Resolve token
	var tokenStr string
	if *token == "-" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			log.Fatalf("read token from stdin: %v", err)
		}
		tokenStr = string(data)
	} else {
		tokenStr = *token
	}

	opts := veldnet.Options{
		IdentityPath:     *identityPath,
		CoordAddr:        *coordAddr,
		Token:            tokenStr,
		NodeName:         *nodeName,
		Userspace:        true,
		OutboundOnly:     *outboundOnly,
		CoordTLSInsecure: *tlsInsecure,
	}
	if *policyPath != "" {
		opts.PolicyPath = *policyPath
	}

	// Create node
	node, err := veldnet.New(opts)
	if err != nil {
		log.Fatalf("create node: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("Shutting down...")
		cancel()
	}()

	// Start node
	log.Println("Starting node...")
	if err := node.Start(ctx); err != nil {
		log.Fatalf("start node: %v", err)
	}
	defer func() {
		if err := node.Close(); err != nil {
			log.Printf("close node: %v", err)
		}
	}()

	log.Printf("Node started! VPN address: %s, Peer ID: %s", node.VPNAddr(), node.PeerID())

	// Make HTTP request through mesh
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: node.DialContext,
		},
		Timeout: 10 * time.Second,
	}

	log.Printf("Making request to %s", *target)
	resp, err := client.Get(*target)
	if err != nil {
		log.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("read response: %v", err)
	}

	log.Printf("Response: %d %s", resp.StatusCode, resp.Status)
	log.Printf("Body: %s", string(body))
}
