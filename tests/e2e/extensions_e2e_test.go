// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package e2e_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	coordce "github.com/veldmesh/veld/coord/ce"
	coordcore "github.com/veldmesh/veld/coord/core"
)

func TestExtensions_CEWiring(t *testing.T) {
	ctx := context.Background()

	// Create all five CE implementations
	enforcer := coordce.NewFreeEnforcer()
	accounts := coordce.NewTokenAccountStore(map[string]coordcore.Account{
		"secret": {ID: "acc1", Tier: coordcore.TierFree},
	})
	audit := coordce.NewNoopAuditLogger()
	subnet := coordce.NewRejectSubnetPolicy()
	hooks := coordce.NewNoopHooks()

	// Test PlanEnforcer: CanRegisterMachine
	if err := enforcer.CanRegisterMachine(ctx, "net1", 4); err != nil {
		t.Fatalf("CanRegisterMachine(4) = %v, want nil", err)
	}
	if err := enforcer.CanRegisterMachine(ctx, "net1", 5); err == nil {
		t.Fatal("CanRegisterMachine(5) = nil, want error")
	} else {
		if !errors.Is(err, coordcore.ErrMachineLimitReached) {
			t.Fatalf("CanRegisterMachine(5) = %v, want wrapped ErrMachineLimitReached", err)
		}
	}

	// Test PlanEnforcer: CanAddNetwork
	if err := enforcer.CanAddNetwork(ctx, "acc1", 0); err != nil {
		t.Fatalf("CanAddNetwork(0) = %v, want nil", err)
	}
	if err := enforcer.CanAddNetwork(ctx, "acc1", 1); err == nil {
		t.Fatal("CanAddNetwork(1) = nil, want error")
	} else {
		if !errors.Is(err, coordcore.ErrNetworkLimitReached) {
			t.Fatalf("CanAddNetwork(1) = %v, want wrapped ErrNetworkLimitReached", err)
		}
	}

	// Test PlanEnforcer: CanUseSubnetRouting
	if err := enforcer.CanUseSubnetRouting(ctx, "net1"); err == nil {
		t.Fatal("CanUseSubnetRouting() = nil, want error")
	} else {
		if !errors.Is(err, coordcore.ErrSubnetNotAvailable) {
			t.Fatalf("CanUseSubnetRouting() = %v, want ErrSubnetNotAvailable", err)
		}
	}

	// Test PlanEnforcer: MachineLimitFor
	if got := enforcer.MachineLimitFor(ctx, "net1"); got != coordce.FreeMachineLimit {
		t.Fatalf("MachineLimitFor() = %d, want %d", got, coordce.FreeMachineLimit)
	}

	// Test AccountStore: Resolve with known token
	acc, err := accounts.Resolve(ctx, "secret")
	if err != nil {
		t.Fatalf("accounts.Resolve(secret) = %v, want nil", err)
	}
	if acc.ID != "acc1" {
		t.Fatalf("Resolve(secret).ID = %q, want %q", acc.ID, "acc1")
	}
	if acc.Tier != coordcore.TierFree {
		t.Fatalf("Resolve(secret).Tier = %v, want %v", acc.Tier, coordcore.TierFree)
	}

	// Test AccountStore: Resolve with unknown token
	_, err = accounts.Resolve(ctx, "bad")
	if err == nil {
		t.Fatal("accounts.Resolve(bad) = nil, want error")
	} else {
		if !errors.Is(err, coordcore.ErrUnknownToken) {
			t.Fatalf("accounts.Resolve(bad) = %v, want ErrUnknownToken", err)
		}
	}

	// Test AuditLogger: Log
	event := coordcore.AuditEvent{
		Kind:      coordcore.AuditPeerRegistered,
		AccountID: "acc1",
		NetworkID: "net1",
		PeerID:    "peer1",
		Detail:    "test event",
	}
	if err := audit.Log(ctx, event); err != nil {
		t.Fatalf("audit.Log() = %v, want nil", err)
	}

	// Test SubnetPolicy: Allow
	prefix := netip.MustParsePrefix("10.1.0.0/16")
	if err := subnet.Allow(ctx, "net1", prefix); err == nil {
		t.Fatal("subnet.Allow() = nil, want error")
	} else {
		if !errors.Is(err, coordcore.ErrSubnetNotAvailable) {
			t.Fatalf("subnet.Allow() = %v, want ErrSubnetNotAvailable", err)
		}
	}

	// Test LifecycleHooks: Call all methods without panic
	peer := coordcore.Peer{
		ID:        "peer1",
		Name:      "test-peer",
		VPNAddr:   netip.MustParseAddr("10.0.0.2"),
		NetworkID: "net1",
	}
	network := coordcore.Network{
		ID:   "net1",
		CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		Name: "test-network",
	}

	// These should not panic
	hooks.OnPeerRegistered(ctx, peer, network)
	hooks.OnPeerLeft(ctx, peer, network)
	hooks.OnNetworkCreated(ctx, network, acc)
	hooks.OnSubnetRouteAdvertised(ctx, peer, prefix)

	t.Log("All CE implementations wired and working correctly")
}
