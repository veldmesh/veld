// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package acl

import (
	"sync/atomic"
)

// Action represents the result of a policy decision.
type Action int

const (
	ActionAllow Action = iota
	ActionDeny
)

// Decision is the result of evaluating a packet against the policy.
type Decision struct {
	Action       Action
	RuleIndex    int  // -1 if default action
	OutboundOnly bool // true if the destination peer is outbound-only
}

// CompiledPolicy is an immutable, compiled policy optimized for fast Decide calls.
// It is safe for concurrent use.
type CompiledPolicy struct {
	// For each destination peer, a list of rules that apply to it.
	// Key: destination peer ID (32-byte Ed25519 public key)
	// Value: list of rules sorted by priority (first match wins)
	dstRules map[[32]byte][]compiledRule

	// Rules with wildcard destination (to="*") - consulted for every destination
	dstAnyRules []compiledRule

	// Default action for packets that don't match any rule
	defaultAction Action

	// Set of outbound-only peer IDs
	outboundOnly map[[32]byte]struct{}

	// Set of all known peer IDs (for quick membership check)
	knownPeers map[[32]byte]struct{}
}

// compiledRule is a rule compiled for fast matching.
type compiledRule struct {
	srcPeers  map[[32]byte]struct{} // source peers this rule applies to (empty means srcAny=true)
	srcAny    bool                  // true if rule applies to any source peer (from="*")
	ports     []PortRange           // allowed protocols/ports
	ruleIndex int                   // original rule index
}

// Compile compiles the Policy into a CompiledPolicy for fast Decide lookups.
// The returned CompiledPolicy is immutable and safe for concurrent use.
func (p *Policy) Compile() *CompiledPolicy {
	// Build set of all known peer IDs
	knownPeers := make(map[[32]byte]struct{}, len(p.Peers))
	for _, key := range p.Peers {
		knownPeers[key] = struct{}{}
	}

	// Build outbound-only set
	outboundOnly := make(map[[32]byte]struct{}, len(p.OutboundOnly))
	for _, name := range p.OutboundOnly {
		if key, ok := p.Peers[name]; ok {
			outboundOnly[key] = struct{}{}
		}
	}

	// Resolve all rules to concrete (srcPeerID, dstPeerID) pairs
	// For each destination peer, collect all rules that apply to it
	dstRules := make(map[[32]byte][]compiledRule)
	var dstAnyRules []compiledRule

	for ruleIdx, rule := range p.Rules {
		srcSet := resolveSubjectToPeers(rule.From, p.Peers, p.Tags)
		dstSet := resolveSubjectToPeers(rule.To, p.Peers, p.Tags)

		srcAny := rule.From == "*"
		dstAny := rule.To == "*"

		cr := compiledRule{
			srcPeers:  srcSet,
			srcAny:    srcAny,
			ports:     rule.Ports,
			ruleIndex: ruleIdx,
		}

		if dstAny {
			// Rule applies to any destination - add to wildcard list
			dstAnyRules = append(dstAnyRules, cr)
		} else {
			// Rule applies to specific destinations
			for dstID := range dstSet {
				dstRules[dstID] = append(dstRules[dstID], cr)
			}
		}
	}

	return &CompiledPolicy{
		dstRules:      dstRules,
		dstAnyRules:   dstAnyRules,
		defaultAction: Action(p.Default),
		outboundOnly:  outboundOnly,
		knownPeers:    knownPeers,
	}
}

// resolveSubjectToPeers resolves a subject (peer name, tag, or "*") to a set of peer IDs.
// Returns empty set for "*" (wildcard), which is handled separately via srcAny/dstAny flags.
func resolveSubjectToPeers(subject string, peers map[string]PeerKey, tags map[string][]string) map[[32]byte]struct{} {
	result := make(map[[32]byte]struct{})
	if subject == "*" {
		// Wildcard - caller should use srcAny/dstAny flag instead
		return result
	}
	if len(subject) >= 4 && subject[:4] == "tag:" {
		tagName := subject[4:]
		for _, pn := range tags[tagName] {
			if key, ok := peers[pn]; ok {
				result[key] = struct{}{}
			}
		}
		return result
	}
	if key, ok := peers[subject]; ok {
		result[key] = struct{}{}
	}
	return result
}

// Decide evaluates a packet against the compiled policy.
// src, dst are Ed25519 public keys (32 bytes).
// proto is the IP protocol (TCP=6, UDP=17, ICMP=1, ICMPv6=58).
// port is the destination port (ignored for ICMP).
func (cp *CompiledPolicy) Decide(src, dst [32]byte, proto Proto, port uint16) Decision {
	// Check destination-specific rules first
	if rules, ok := cp.dstRules[dst]; ok {
		for _, rule := range rules {
			// Check if source peer matches (srcAny means any authenticated peer)
			if !rule.srcAny {
				if _, ok := rule.srcPeers[src]; !ok {
					continue
				}
			}

			// Check if protocol/port matches
			for _, pr := range rule.ports {
				if pr.MatchesProto(proto) {
					if pr.ContainsPort(port) {
						// Check outbound-only for known peers
						if _, ok := cp.outboundOnly[dst]; ok {
							return Decision{Action: ActionDeny, RuleIndex: -1, OutboundOnly: true}
						}
						return Decision{Action: ActionAllow, RuleIndex: rule.ruleIndex}
					}
				}
			}
		}
	}

	// Then check wildcard destination rules (to="*")
	for _, rule := range cp.dstAnyRules {
		// Check if source peer matches (srcAny means any authenticated peer)
		if !rule.srcAny {
			if _, ok := rule.srcPeers[src]; !ok {
				continue
			}
		}

		// Check if protocol/port matches
		for _, pr := range rule.ports {
			if pr.MatchesProto(proto) {
				if pr.ContainsPort(port) {
					// Check outbound-only for known peers
					if _, ok := cp.outboundOnly[dst]; ok {
						return Decision{Action: ActionDeny, RuleIndex: -1, OutboundOnly: true}
					}
					return Decision{Action: ActionAllow, RuleIndex: rule.ruleIndex}
				}
			}
		}
	}

	// No rule matched - check if destination is a known peer
	if _, ok := cp.knownPeers[dst]; !ok {
		return Decision{Action: cp.defaultAction, RuleIndex: -1}
	}

	// Known peer but no rule matched - check outbound-only
	if _, ok := cp.outboundOnly[dst]; ok {
		return Decision{Action: ActionDeny, RuleIndex: -1, OutboundOnly: true}
	}

	return Decision{Action: cp.defaultAction, RuleIndex: -1}
}

// PolicyDecider is an interface for policy decision making.
// Both CompiledPolicy and combinedPolicy implement this.
type PolicyDecider interface {
	Decide(src, dst [32]byte, proto Proto, port uint16) Decision
}

// Combine combines a local policy and a network policy into a single PolicyDecider.
// A packet passes only if BOTH policies allow it.
// If local is nil, it defers to network policy (missing local = defer to network).
// If network is nil, it defers to local policy.
func Combine(local, network PolicyDecider) PolicyDecider {
	// If one is nil, return the other
	if local == nil {
		return network
	}
	if network == nil {
		return local
	}

	return &combinedPolicy{
		local:   local,
		network: network,
	}
}

// combinedPolicy wraps two PolicyDeciders and requires both to allow.
type combinedPolicy struct {
	local   PolicyDecider
	network PolicyDecider
}

func (c *combinedPolicy) Decide(src, dst [32]byte, proto Proto, port uint16) Decision {
	localDec := c.local.Decide(src, dst, proto, port)
	if localDec.Action == ActionDeny {
		return localDec
	}
	netDec := c.network.Decide(src, dst, proto, port)
	if netDec.Action == ActionDeny {
		return netDec
	}
	// Both allow - return the more specific decision (local takes precedence for rule index)
	if localDec.RuleIndex >= 0 {
		return localDec
	}
	return netDec
}

// PolicySwap is an atomic pointer to a CompiledPolicy for hot-swapping policies.
// This allows a later story to swap the policy and re-check flows.
type PolicySwap struct {
	ptr atomic.Pointer[CompiledPolicy]
}

// Store atomically stores a new compiled policy.
func (ps *PolicySwap) Store(cp *CompiledPolicy) {
	ps.ptr.Store(cp)
}

// Load atomically loads the current compiled policy.
func (ps *PolicySwap) Load() *CompiledPolicy {
	return ps.ptr.Load()
}

// Decide evaluates a packet against the current policy.
// Returns a zero Decision (deny) if no policy is loaded.
func (ps *PolicySwap) Decide(src, dst [32]byte, proto Proto, port uint16) Decision {
	cp := ps.Load()
	if cp == nil {
		return Decision{Action: ActionDeny, RuleIndex: -1}
	}
	return cp.Decide(src, dst, proto, port)
}
