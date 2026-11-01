// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	coordce "github.com/veldmesh/veld/coord/ce"
	coordcore "github.com/veldmesh/veld/coord/core"
	coordserver "github.com/veldmesh/veld/coord/server"
	coordv1 "github.com/veldmesh/veld/gen/veld/coord/v1"
)

func main() {
	listenAddr := flag.String("listen", ":50051", "gRPC listen address")
	dbPath := flag.String("db", "coord.db", "bbolt database path")
	networkID := flag.String("network-id", "", "auto-create network with this ID if missing")
	networkCIDR := flag.String("network-cidr", "10.100.0.0/24", "CIDR for auto-created network")
	networkName := flag.String("network-name", "default", "name for auto-created network")
	tokenStr := flag.String("token", "", "auth token to pre-register (prefer -token-file or $VELD_COORD_TOKEN: flags are visible in the process list)")
	tokenFile := flag.String("token-file", "", "file holding the auth token to pre-register")
	tlsCert := flag.String("tls-cert", "", "TLS certificate file (PEM); serve gRPC over TLS with -tls-key")
	tlsKey := flag.String("tls-key", "", "TLS private key file (PEM)")
	proxyProtoFrom := flag.String("proxy-protocol-from", "",
		"accept PROXY protocol (v1/v2) headers only from these CIDRs, e.g. the load balancer's address; empty disables")
	peerTTL := flag.Duration("peer-ttl", coordserver.DefaultPeerTTL,
		"peer registration TTL; peers not seen for this long are pruned (0 disables the sweep)")
	sweepInterval := flag.Duration("sweep-interval", coordserver.DefaultSweepInterval,
		"how often the stale-peer sweep runs (minimum one minute; shorter values are clamped up)")
	flag.Parse()
	if *tokenStr == "" {
		*tokenStr = os.Getenv("VELD_COORD_TOKEN")
	}
	if *tokenFile != "" {
		b, err := os.ReadFile(*tokenFile)
		if err != nil {
			log.Fatalf("read -token-file: %v", err)
		}
		*tokenStr = strings.TrimSpace(string(b))
	}

	reg, err := coordserver.NewRegistry(*dbPath)
	if err != nil {
		log.Fatalf("registry: %v", err)
	}
	defer func() { _ = reg.Close() }()

	// Auto-create network if --network-id is set
	if *networkID != "" {
		cidr, err := netip.ParsePrefix(*networkCIDR)
		if err != nil {
			log.Fatalf("invalid --network-cidr: %v", err)
		}
		net := coordcore.Network{ID: *networkID, CIDR: cidr, Name: *networkName}
		if err := reg.CreateNetwork(net, "account-1"); err != nil {
			// Check if it's an "already exists" error
			if err.Error() != fmt.Sprintf("network %q already exists", *networkID) {
				log.Printf("warn: CreateNetwork: %v", err)
			}
		}
	}

	// Build token store
	tokens := make(map[string]coordcore.Account)
	if *tokenStr != "" {
		tokens[*tokenStr] = coordcore.Account{ID: "account-1", Tier: coordcore.TierFree}
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	coordserver.StartPeerSweeper(ctx, srv, *peerTTL, *sweepInterval, log.Printf)

	ln, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	// Wrap the raw listener so PROXY headers are read before any TLS handshake.
	ln, err = coordserver.WrapProxyProtocolListener(ln, *proxyProtoFrom)
	if err != nil {
		log.Fatalf("-proxy-protocol-from: %v", err)
	}
	if *proxyProtoFrom != "" {
		log.Printf("accepting PROXY protocol headers from %s", *proxyProtoFrom)
	}

	rl := coordserver.NewIPRateLimiter(20, 40)
	opts := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(coordserver.UnaryRateLimitInterceptor(rl)),
		grpc.ChainStreamInterceptor(coordserver.StreamRateLimitInterceptor(rl)),
		// Bound what one connection can hold open: Watch streams are
		// long-lived, and the rate limit only gates their start.
		grpc.MaxConcurrentStreams(64),
		grpc.KeepaliveParams(keepalive.ServerParameters{MaxConnectionIdle: 15 * time.Minute}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 20 * time.Second, PermitWithoutStream: true}),
	}
	switch {
	case *tlsCert != "" && *tlsKey != "":
		creds, err := credentials.NewServerTLSFromFile(*tlsCert, *tlsKey)
		if err != nil {
			log.Fatalf("tls: %v", err)
		}
		opts = append(opts, grpc.Creds(creds))
	case *tlsCert != "" || *tlsKey != "":
		log.Fatalf("-tls-cert and -tls-key must be set together")
	default:
		// The token and every peer's keys and endpoints cross this link.
		log.Printf("warning: serving plaintext gRPC: use -tls-cert/-tls-key or a TLS-terminating proxy in front")
	}
	grpcSrv := grpc.NewServer(opts...)
	coordv1.RegisterCoordServer(grpcSrv, srv)

	log.Printf("veld-coord listening on %s", *listenAddr)

	go func() {
		if err := grpcSrv.Serve(ln); err != nil {
			log.Printf("grpc serve: %v", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("shutting down...")
	cancel()
	rl.Stop()
	grpcSrv.GracefulStop()
}
