// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: BUSL-1.1
package ce

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	coordcore "github.com/veldmesh/veld/coord/core"
)

// Verify each CE type satisfies its interface
var (
	_ coordcore.PlanEnforcer  = (*FreeEnforcer)(nil)
	_ coordcore.AccountStore  = (*TokenAccountStore)(nil)
	_ coordcore.AuditLogger   = (*NoopAuditLogger)(nil)
	_ coordcore.SubnetPolicy  = (*RejectSubnetPolicy)(nil)
	_ coordcore.LifecycleHooks = (*NoopHooks)(nil)
)

func TestFreeEnforcer_CanRegisterMachine(t *testing.T) {
	e := NewFreeEnforcer()
	ctx := context.Background()

	// Below limit
	if err := e.CanRegisterMachine(ctx, "net1", 4); err != nil {
		t.Errorf("CanRegisterMachine(4) = %v, want nil", err)
	}

	// At limit
	if err := e.CanRegisterMachine(ctx, "net1", 5); err == nil {
		t.Error("CanRegisterMachine(5) = nil, want error")
	} else {
		if !errors.Is(err, coordcore.ErrMachineLimitReached) {
			t.Errorf("CanRegisterMachine(5) = %v, want wrapped ErrMachineLimitReached", err)
		}
	}

	// Over limit
	if err := e.CanRegisterMachine(ctx, "net1", 10); err == nil {
		t.Error("CanRegisterMachine(10) = nil, want error")
	} else {
		if !errors.Is(err, coordcore.ErrMachineLimitReached) {
			t.Errorf("CanRegisterMachine(10) = %v, want wrapped ErrMachineLimitReached", err)
		}
	}
}

func TestFreeEnforcer_CanAddNetwork(t *testing.T) {
	e := NewFreeEnforcer()
	ctx := context.Background()

	// Below limit
	if err := e.CanAddNetwork(ctx, "acc1", 0); err != nil {
		t.Errorf("CanAddNetwork(0) = %v, want nil", err)
	}

	// At limit
	if err := e.CanAddNetwork(ctx, "acc1", 1); err == nil {
		t.Error("CanAddNetwork(1) = nil, want error")
	} else {
		if !errors.Is(err, coordcore.ErrNetworkLimitReached) {
			t.Errorf("CanAddNetwork(1) = %v, want wrapped ErrNetworkLimitReached", err)
		}
	}

	// Over limit
	if err := e.CanAddNetwork(ctx, "acc1", 5); err == nil {
		t.Error("CanAddNetwork(5) = nil, want error")
	} else {
		if !errors.Is(err, coordcore.ErrNetworkLimitReached) {
			t.Errorf("CanAddNetwork(5) = %v, want wrapped ErrNetworkLimitReached", err)
		}
	}
}

func TestFreeEnforcer_CanUseSubnetRouting(t *testing.T) {
	e := NewFreeEnforcer()
	ctx := context.Background()

	err := e.CanUseSubnetRouting(ctx, "net1")
	if err == nil {
		t.Error("CanUseSubnetRouting() = nil, want error")
	}
	if !errors.Is(err, coordcore.ErrSubnetNotAvailable) {
		t.Errorf("CanUseSubnetRouting() = %v, want ErrSubnetNotAvailable", err)
	}
}

func TestFreeEnforcer_MachineLimitFor(t *testing.T) {
	e := NewFreeEnforcer()
	ctx := context.Background()

	if got := e.MachineLimitFor(ctx, "net1"); got != FreeMachineLimit {
		t.Errorf("MachineLimitFor() = %d, want %d", got, FreeMachineLimit)
	}
}

func TestTokenAccountStore_Resolve(t *testing.T) {
	tokens := map[string]coordcore.Account{
		"secret": {ID: "acc1", Tier: coordcore.TierFree},
		"token2": {ID: "acc2", Tier: coordcore.TierFree},
	}
	store := NewTokenAccountStore(tokens)
	ctx := context.Background()

	// Known token
	acc, err := store.Resolve(ctx, "secret")
	if err != nil {
		t.Errorf("Resolve(secret) = %v, want nil", err)
	}
	if acc.ID != "acc1" {
		t.Errorf("Resolve(secret).ID = %q, want %q", acc.ID, "acc1")
	}
	if acc.Tier != coordcore.TierFree {
		t.Errorf("Resolve(secret).Tier = %v, want %v", acc.Tier, coordcore.TierFree)
	}

	// Unknown token
	_, err = store.Resolve(ctx, "bad")
	if err == nil {
		t.Error("Resolve(bad) = nil, want error")
	}
	if !errors.Is(err, coordcore.ErrUnknownToken) {
		t.Errorf("Resolve(bad) = %v, want ErrUnknownToken", err)
	}
}

func TestTokenAccountStore_RecordActivity(t *testing.T) {
	store := NewTokenAccountStore(map[string]coordcore.Account{
		"token": {ID: "acc1", Tier: coordcore.TierFree},
	})
	ctx := context.Background()

	err := store.RecordActivity(ctx, "acc1")
	if err != nil {
		t.Errorf("RecordActivity() = %v, want nil", err)
	}
}

func TestNoopAuditLogger_Log(t *testing.T) {
	logger := NewNoopAuditLogger()
	ctx := context.Background()

	event := coordcore.AuditEvent{
		Kind:      coordcore.AuditPeerRegistered,
		AccountID: "acc1",
		NetworkID: "net1",
		PeerID:    "peer1",
		Detail:    "test",
	}

	err := logger.Log(ctx, event)
	if err != nil {
		t.Errorf("Log() = %v, want nil", err)
	}
}

func TestRejectSubnetPolicy_Allow(t *testing.T) {
	policy := NewRejectSubnetPolicy()
	ctx := context.Background()
	prefix := netip.MustParsePrefix("10.0.0.0/8")

	err := policy.Allow(ctx, "net1", prefix)
	if err == nil {
		t.Error("Allow() = nil, want error")
	}
	if !errors.Is(err, coordcore.ErrSubnetNotAvailable) {
		t.Errorf("Allow() = %v, want ErrSubnetNotAvailable", err)
	}
}

func TestNoopHooks_AllMethods(t *testing.T) {
	hooks := NewNoopHooks()
	ctx := context.Background()
	peer := coordcore.Peer{ID: "peer1", Name: "test", VPNAddr: netip.MustParseAddr("10.0.0.1"), NetworkID: "net1"}
	network := coordcore.Network{ID: "net1", CIDR: netip.MustParsePrefix("10.0.0.0/8"), Name: "test"}
	account := coordcore.Account{ID: "acc1", Tier: coordcore.TierFree}
	prefix := netip.MustParsePrefix("10.0.0.0/24")

	// These should not panic
	hooks.OnPeerRegistered(ctx, peer, network)
	hooks.OnPeerLeft(ctx, peer, network)
	hooks.OnNetworkCreated(ctx, network, account)
	hooks.OnSubnetRouteAdvertised(ctx, peer, prefix)
}
