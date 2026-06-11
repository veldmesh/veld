// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/veldmesh/veld/internal/config"
	"github.com/veldmesh/veld/internal/daemon"
)

func main() {
	cfgPath := flag.String("config", config.DefaultConfigPath(), "path to config file")
	flag.Parse()

	cfg, err := config.LoadFile(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "veld-daemon: %v\n", err)
		os.Exit(1)
	}

	d, err := daemon.NewFromConfig(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "veld-daemon: init: %v\n", err)
		os.Exit(1)
	}

	d.Start()

	// doneCh is closed when d.Wait() returns — i.e. all internal components have stopped.
	// This can happen via an OS signal OR via the IPC /api/shutdown endpoint calling d.Stop().
	doneCh := make(chan struct{})
	go func() {
		d.Wait()
		close(doneCh)
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-sig:
		// OS signal: drive shutdown ourselves, then wait.
		d.Stop()
		<-doneCh
	case <-doneCh:
		// IPC /api/shutdown fired d.Stop() internally; components already done.
	}
}
