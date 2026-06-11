// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: BUSL-1.1
package coordcore

import (
	"errors"
	"net/netip"
	"time"
)

// Sentinel errors returned by PlanEnforcer and SubnetPolicy.
var (
	ErrMachineLimitReached = errors.New("machine limit reached for this plan")
	ErrNetworkLimitReached = errors.New("network limit reached for this plan")
	ErrSubnetNotAvailable  = errors.New("subnet routing requires Teams tier or above")
	ErrUnknownToken        = errors.New("unknown or expired token")
)

// Tier represents the billing/feature tier of an account.
type Tier uint8

const (
	TierFree Tier = iota
	TierPlus
	TierTeams
	TierBusiness
)

func (t Tier) String() string {
	switch t {
	case TierFree:
		return "free"
	case TierPlus:
		return "plus"
	case TierTeams:
		return "teams"
	case TierBusiness:
		return "business"
	default:
		return "unknown"
	}
}

// Account is the result of resolving a network token.
type Account struct {
	ID   string
	Tier Tier
}

// Network describes a registered VPN network.
type Network struct {
	ID   string
	CIDR netip.Prefix
	Name string
}

// Peer describes a registered peer.
type Peer struct {
	ID        string
	Name      string
	VPNAddr   netip.Addr
	NetworkID string
}

// AuditEventKind classifies an audit event.
type AuditEventKind string

const (
	AuditPeerRegistered       AuditEventKind = "peer.registered"
	AuditPeerLeft             AuditEventKind = "peer.left"
	AuditNetworkCreated       AuditEventKind = "network.created"
	AuditSubnetRouteAdded     AuditEventKind = "subnet.route.added"
	AuditRegistrationRejected AuditEventKind = "registration.rejected"
)

// AuditEvent is a single audit record.
type AuditEvent struct {
	Kind      AuditEventKind
	AccountID string
	NetworkID string
	PeerID    string
	Detail    string
	At        time.Time
}
