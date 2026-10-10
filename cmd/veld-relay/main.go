// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: BUSL-1.1

// veld-relay runs a DERP-style relay service on a volunteer mesh peer. It
// accepts Noise IK-encrypted client connections and splices the two ends of
// a peer pair that cannot hole-punch directly. The relay is blind: all
// payloads are end-to-end session-encrypted between the peers.
//
// Usage:
//
//	veld-relay -listen :41820 -identity ~/.config/veld/relay.json
//
// On first start it generates an identity and prints its X25519 public key;
// configure peers with that key as coord.relay_x25519 and this host's address
// as coord.relay_addr.
//
// By default only startup output is printed; no per-connection events
// (channel IDs, client addresses) are logged. The -verbose flag re-enables
// per-connection debug logs — with client addresses truncated — for local
// debugging only; it is off by default and not intended for production.
package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/veldmesh/veld/internal/config"
	relaysrv "github.com/veldmesh/veld/relay"
)

func main() {
	listen := flag.String("listen", ":41820", "TCP address to listen on")
	identity := flag.String("identity", "relay-identity.json", "path to identity keystore (created on first run)")
	verbose := flag.Bool("verbose", false, "log per-connection events (channel IDs, truncated client addresses); for local debugging only, not for production")
	flag.Parse()

	id, err := config.LoadOrGenerate(*identity)
	if err != nil {
		fmt.Fprintf(os.Stderr, "veld-relay: identity: %v\n", err)
		os.Exit(1)
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "veld-relay: listen %s: %v\n", *listen, err)
		os.Exit(1)
	}

	fmt.Printf("veld-relay listening on %s\n", ln.Addr())
	fmt.Printf("relay X25519 public key (set as coord.relay_x25519 on peers): %s\n",
		base64.StdEncoding.EncodeToString(id.X25519Public[:]))

	var opts []relaysrv.Option
	if *verbose {
		opts = append(opts, relaysrv.Verbose())
	}
	svc := relaysrv.NewService(id, ln, opts...)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := svc.Serve(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "veld-relay: serve: %v\n", err)
		os.Exit(1)
	}
}
