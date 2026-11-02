// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package acl

import (
	"testing"
)

func makeTestPolicy(defaultAct DefaultAction, rules []Rule, peers map[string]PeerKey, tags map[string][]string, outboundOnly []string) *CompiledPolicy {
	p := &Policy{
		Version:      1,
		Default:      defaultAct,
		Peers:        peers,
		Tags:         tags,
		Rules:        rules,
		OutboundOnly: outboundOnly,
	}
	return p.Compile()
}

func TestCombine_LocalAllowNetworkAllow(t *testing.T) {
	peers := map[string]PeerKey{
		"a": {2},
		"b": {1},
	}
	rules := []Rule{
		{From: "a", To: "b", Ports: []PortRange{{Proto: ProtoTCP, Start: 22, End: 22}}},
	}
	local := makeTestPolicy(DefaultAllow, rules, peers, nil, nil)
	network := makeTestPolicy(DefaultAllow, rules, peers, nil, nil)

	dec := Combine(local, network).Decide(peers["a"], peers["b"], ProtoTCP, 22)
	if dec.Action != ActionAllow {
		t.Errorf("got %v, want allow", dec.Action)
	}
}

func TestCombine_LocalDenyNetworkAllow(t *testing.T) {
	peers := map[string]PeerKey{
		"a": {2},
		"b": {1},
	}
	rules := []Rule{
		{From: "a", To: "b", Ports: []PortRange{{Proto: ProtoTCP, Start: 22, End: 22}}},
	}
	local := makeTestPolicy(DefaultDeny, nil, peers, nil, nil)
	network := makeTestPolicy(DefaultAllow, rules, peers, nil, nil)

	dec := Combine(local, network).Decide(peers["a"], peers["b"], ProtoTCP, 22)
	if dec.Action != ActionDeny {
		t.Errorf("got %v, want deny (local denies)", dec.Action)
	}
}

func TestCombine_LocalAllowNetworkDeny(t *testing.T) {
	peers := map[string]PeerKey{
		"a": {2},
		"b": {1},
	}
	rules := []Rule{
		{From: "a", To: "b", Ports: []PortRange{{Proto: ProtoTCP, Start: 22, End: 22}}},
	}
	local := makeTestPolicy(DefaultAllow, rules, peers, nil, nil)
	network := makeTestPolicy(DefaultDeny, nil, peers, nil, nil)

	dec := Combine(local, network).Decide(peers["a"], peers["b"], ProtoTCP, 22)
	if dec.Action != ActionDeny {
		t.Errorf("got %v, want deny (network denies)", dec.Action)
	}
}

func TestCombine_LocalMissingNetworkAllow(t *testing.T) {
	peers := map[string]PeerKey{
		"a": {2},
		"b": {1},
	}
	rules := []Rule{
		{From: "a", To: "b", Ports: []PortRange{{Proto: ProtoTCP, Start: 22, End: 22}}},
	}
	var local PolicyDecider = nil
	network := makeTestPolicy(DefaultAllow, rules, peers, nil, nil)

	dec := Combine(local, network).Decide(peers["a"], peers["b"], ProtoTCP, 22)
	if dec.Action != ActionAllow {
		t.Errorf("got %v, want allow (network allows, no local)", dec.Action)
	}
}

func TestCombine_LocalMissingNetworkDeny(t *testing.T) {
	peers := map[string]PeerKey{
		"a": {2},
		"b": {1},
	}
	var local PolicyDecider = nil
	network := makeTestPolicy(DefaultDeny, nil, peers, nil, nil)

	dec := Combine(local, network).Decide(peers["a"], peers["b"], ProtoTCP, 22)
	if dec.Action != ActionDeny {
		t.Errorf("got %v, want deny (network denies, no local)", dec.Action)
	}
}

func TestCombine_OutboundOnly(t *testing.T) {
	peers := map[string]PeerKey{
		"a": {1},
		"b": {2},
	}
	rules := []Rule{
		{From: "a", To: "b", Ports: []PortRange{{Proto: ProtoTCP, Start: 22, End: 22}}},
		{From: "b", To: "a", Ports: []PortRange{{Proto: ProtoTCP, Start: 22, End: 22}}},
	}
	local := makeTestPolicy(DefaultAllow, rules, peers, nil, []string{"b"}) // b is outbound-only
	network := makeTestPolicy(DefaultAllow, rules, peers, nil, nil)

	// a -> b: b is outbound-only, so inbound to b should be denied
	dec := Combine(local, network).Decide(peers["a"], peers["b"], ProtoTCP, 22)
	if dec.Action != ActionDeny {
		t.Errorf("got %v, want deny (peer b is outbound-only)", dec.Action)
	}
	if !dec.OutboundOnly {
		t.Error("OutboundOnly flag not set")
	}

	// b -> a: should be allowed
	dec = Combine(local, network).Decide(peers["b"], peers["a"], ProtoTCP, 22)
	if dec.Action != ActionAllow {
		t.Errorf("got %v, want allow (peer b starting connection)", dec.Action)
	}
}

func TestPolicySwap_StoreAndLoad(t *testing.T) {
	ps := &PolicySwap{}
	peers := map[string]PeerKey{
		"a": {2},
		"b": {1},
	}
	rules := []Rule{
		{From: "a", To: "b", Ports: []PortRange{{Proto: ProtoTCP, Start: 22, End: 22}}},
	}
	cp := makeTestPolicy(DefaultAllow, rules, peers, nil, nil)

	ps.Store(cp)
	loaded := ps.Load()
	if loaded != cp {
		t.Error("loaded policy doesn't match stored")
	}
}

func TestPolicySwap_Decide(t *testing.T) {
	ps := &PolicySwap{}
	peers := map[string]PeerKey{
		"a": {2},
		"b": {1},
	}
	rules := []Rule{
		{From: "a", To: "b", Ports: []PortRange{{Proto: ProtoTCP, Start: 22, End: 22}}},
	}
	cp := makeTestPolicy(DefaultDeny, rules, peers, nil, nil)

	ps.Store(cp)

	dec := ps.Decide(peers["a"], peers["b"], ProtoTCP, 22)
	if dec.Action != ActionAllow {
		t.Errorf("got %v, want allow", dec.Action)
	}
	if dec.RuleIndex != 0 {
		t.Errorf("rule index: got %d, want 0", dec.RuleIndex)
	}

	// Unknown peer
	dec = ps.Decide([32]byte{99}, peers["b"], ProtoTCP, 22)
	if dec.Action != ActionDeny {
		t.Errorf("unknown peer: got %v, want deny", dec.Action)
	}
}

func TestPolicySwap_NilPolicy(t *testing.T) {
	ps := &PolicySwap{}
	dec := ps.Decide([32]byte{1}, [32]byte{2}, ProtoTCP, 22)
	if dec.Action != ActionDeny {
		t.Errorf("nil policy: got %v, want deny", dec.Action)
	}
}

func TestPolicySwap_HotSwap(t *testing.T) {
	ps := &PolicySwap{}
	peers := map[string]PeerKey{
		"a": {1},
		"b": {2},
	}

	// Initial policy: deny all
	cp1 := makeTestPolicy(DefaultDeny, nil, peers, nil, nil)
	ps.Store(cp1)

	dec := ps.Decide(peers["a"], peers["b"], ProtoTCP, 22)
	if dec.Action != ActionDeny {
		t.Errorf("initial: got %v, want deny", dec.Action)
	}

	// Swap to allow policy
	cp2 := makeTestPolicy(DefaultAllow, nil, peers, nil, nil)
	ps.Store(cp2)

	dec = ps.Decide(peers["a"], peers["b"], ProtoTCP, 22)
	if dec.Action != ActionAllow {
		t.Errorf("after swap: got %v, want allow", dec.Action)
	}
}
