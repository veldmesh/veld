// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: BUSL-1.1
package coordcore

import (
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestSentinelErrors(t *testing.T) {
	// Verify all sentinel errors are non-nil
	if ErrMachineLimitReached == nil {
		t.Fatal("ErrMachineLimitReached is nil")
	}
	if ErrNetworkLimitReached == nil {
		t.Fatal("ErrNetworkLimitReached is nil")
	}
	if ErrSubnetNotAvailable == nil {
		t.Fatal("ErrSubnetNotAvailable is nil")
	}
	if ErrUnknownToken == nil {
		t.Fatal("ErrUnknownToken is nil")
	}

	// Verify they are distinct
	if ErrMachineLimitReached == ErrNetworkLimitReached {
		t.Fatal("ErrMachineLimitReached == ErrNetworkLimitReached")
	}
	if ErrMachineLimitReached == ErrSubnetNotAvailable {
		t.Fatal("ErrMachineLimitReached == ErrSubnetNotAvailable")
	}
	if ErrMachineLimitReached == ErrUnknownToken {
		t.Fatal("ErrMachineLimitReached == ErrUnknownToken")
	}
	if ErrNetworkLimitReached == ErrSubnetNotAvailable {
		t.Fatal("ErrNetworkLimitReached == ErrSubnetNotAvailable")
	}
	if ErrNetworkLimitReached == ErrUnknownToken {
		t.Fatal("ErrNetworkLimitReached == ErrUnknownToken")
	}
	if ErrSubnetNotAvailable == ErrUnknownToken {
		t.Fatal("ErrSubnetNotAvailable == ErrUnknownToken")
	}
}

func TestTierString(t *testing.T) {
	tests := []struct {
		tier Tier
		want string
	}{
		{TierFree, "free"},
		{TierPlus, "plus"},
		{TierTeams, "teams"},
		{TierBusiness, "business"},
		{Tier(255), "unknown"},
	}

	for _, tt := range tests {
		if got := tt.tier.String(); got != tt.want {
			t.Errorf("Tier(%d).String() = %q, want %q", tt.tier, got, tt.want)
		}
	}
}

func TestAuditEventStruct(t *testing.T) {
	// Verify AuditEvent fields are assignable
	now := time.Now()

	event := AuditEvent{
		Kind:      AuditPeerRegistered,
		AccountID: "account123",
		NetworkID: "network456",
		PeerID:    "peer789",
		Detail:    "test detail",
		At:        now,
	}

	if event.Kind != AuditPeerRegistered {
		t.Fatal("event.Kind assignment failed")
	}
	if event.AccountID != "account123" {
		t.Fatal("event.AccountID assignment failed")
	}
	if event.NetworkID != "network456" {
		t.Fatal("event.NetworkID assignment failed")
	}
	if event.PeerID != "peer789" {
		t.Fatal("event.PeerID assignment failed")
	}
	if event.Detail != "test detail" {
		t.Fatal("event.Detail assignment failed")
	}
	if event.At != now {
		t.Fatal("event.At assignment failed")
	}

	// Verify AuditEventKind constants are distinct
	if AuditPeerRegistered == AuditPeerLeft {
		t.Fatal("AuditPeerRegistered == AuditPeerLeft")
	}
	if AuditPeerRegistered == AuditNetworkCreated {
		t.Fatal("AuditPeerRegistered == AuditNetworkCreated")
	}
	if AuditPeerRegistered == AuditSubnetRouteAdded {
		t.Fatal("AuditPeerRegistered == AuditSubnetRouteAdded")
	}
	if AuditPeerRegistered == AuditRegistrationRejected {
		t.Fatal("AuditPeerRegistered == AuditRegistrationRejected")
	}
}

func TestTypesCompile(t *testing.T) {
	// Verify all types can be instantiated and used as expected
	_ = Account{ID: "acc1", Tier: TierFree}
	_ = Network{ID: "net1", CIDR: netip.MustParsePrefix("10.0.0.0/8"), Name: "test"}
	_ = Peer{ID: "peer1", Name: "test", VPNAddr: netip.MustParseAddr("10.0.0.1"), NetworkID: "net1"}
}

func TestErrorsIsWorks(t *testing.T) {
	// Verify errors.Is works with sentinel errors
	err := ErrMachineLimitReached
	if !errors.Is(err, ErrMachineLimitReached) {
		t.Fatal("errors.Is(ErrMachineLimitReached, ErrMachineLimitReached) failed")
	}

	err = ErrNetworkLimitReached
	if !errors.Is(err, ErrNetworkLimitReached) {
		t.Fatal("errors.Is(ErrNetworkLimitReached, ErrNetworkLimitReached) failed")
	}

	err = ErrSubnetNotAvailable
	if !errors.Is(err, ErrSubnetNotAvailable) {
		t.Fatal("errors.Is(ErrSubnetNotAvailable, ErrSubnetNotAvailable) failed")
	}

	err = ErrUnknownToken
	if !errors.Is(err, ErrUnknownToken) {
		t.Fatal("errors.Is(ErrUnknownToken, ErrUnknownToken) failed")
	}
}
