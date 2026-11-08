// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package ipctypes

import (
	"time"
)

// PolicyStatusResponse is returned by GET /api/policy/status.
type PolicyStatusResponse struct {
	LocalPolicy   LocalPolicyStatus   `json:"local_policy"`
	NetworkPolicy NetworkPolicyStatus `json:"network_policy"`
	DropCounters  DropCountersStatus  `json:"drop_counters"`
	RecentDrops   []DropEvent         `json:"recent_drops"`
}

type LocalPolicyStatus struct {
	Path    string `json:"path"`
	Hash    string `json:"hash"`
	Version int    `json:"version"`
	Default string `json:"default"`
	Rules   int    `json:"rules"`
}

type NetworkPolicyStatus struct {
	Version int    `json:"version"`
	Signer  string `json:"signer"`
	Age     string `json:"age"`
}

type DropCountersStatus struct {
	ByPeer         map[string]uint64 `json:"by_peer"`
	ByRule         map[int]uint64    `json:"by_rule"`
	ByOutboundOnly map[string]uint64 `json:"by_outbound_only"`
}

type DropEvent struct {
	Time    time.Time `json:"time"`
	PeerID  string    `json:"peer_id"`
	Proto   string    `json:"proto"`
	Port    uint16    `json:"port"`
	RuleIdx int       `json:"rule_idx"`
}
