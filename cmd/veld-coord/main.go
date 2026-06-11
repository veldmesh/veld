// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"google.golang.org/grpc"

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
	tokenStr := flag.String("token", "", "auth token to pre-register (format: token)")
	flag.Parse()

	reg, err := coordserver.NewRegistry(*dbPath)
	if err != nil {
		log.Fatalf("registry: %v", err)
	}
	defer reg.Close()

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

	ln, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}

	rl := coordserver.NewIPRateLimiter(20, 40)
	grpcSrv := grpc.NewServer(
		grpc.ChainUnaryInterceptor(coordserver.UnaryRateLimitInterceptor(rl)),
		grpc.ChainStreamInterceptor(coordserver.StreamRateLimitInterceptor(rl)),
	)
	coordv1.RegisterCoordServer(grpcSrv, srv)

	log.Printf("veld-coord listening on %s", *listenAddr)

	go grpcSrv.Serve(ln)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("shutting down...")
	grpcSrv.GracefulStop()
}
