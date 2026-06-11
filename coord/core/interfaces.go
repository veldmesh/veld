// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: BUSL-1.1
package coordcore

import (
	"context"
	"net/netip"
)

// PlanEnforcer gates tier-limited actions.
// CE: FreeEnforcer (hard-coded Free limits).
// Managed: TieredEnforcer (checks account tier from DB).
type PlanEnforcer interface {
	CanRegisterMachine(ctx context.Context, networkID string, currentCount int) error
	CanAddNetwork(ctx context.Context, accountID string, currentCount int) error
	CanUseSubnetRouting(ctx context.Context, networkID string) error
	MachineLimitFor(ctx context.Context, networkID string) int
}

// AccountStore resolves a network token to an account and tier.
// CE: TokenAccountStore (static tokens, always Free).
// Managed: DBAccountStore (Postgres, billing-aware).
type AccountStore interface {
	Resolve(ctx context.Context, token string) (Account, error)
	RecordActivity(ctx context.Context, accountID string) error
}

// AuditLogger records audit events.
// CE: NoopAuditLogger. Managed: DBAuditLogger.
type AuditLogger interface {
	Log(ctx context.Context, event AuditEvent) error
}

// SubnetPolicy controls subnet route advertisement.
// CE: RejectSubnetPolicy (always ErrSubnetNotAvailable).
// Managed: TieredSubnetPolicy (checks PlanEnforcer).
type SubnetPolicy interface {
	Allow(ctx context.Context, networkID string, route netip.Prefix) error
}

// LifecycleHooks are called at key events.
// CE: NoopHooks. Managed: billing counters, webhooks, metrics.
type LifecycleHooks interface {
	OnPeerRegistered(ctx context.Context, peer Peer, network Network)
	OnPeerLeft(ctx context.Context, peer Peer, network Network)
	OnNetworkCreated(ctx context.Context, network Network, account Account)
	OnSubnetRouteAdvertised(ctx context.Context, peer Peer, route netip.Prefix)
}
