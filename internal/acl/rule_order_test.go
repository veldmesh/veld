// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package acl

import (
	"testing"
)

// TestDecide_RuleOrder_StarBeforeSpecific tests that to="*" rules before specific
// destination rules are evaluated first (file order semantics).
func TestDecide_RuleOrder_StarBeforeSpecific(t *testing.T) {
	p := &Policy{
		Version: 1,
		Default: DefaultDeny,
		Peers: map[string]PeerKey{
			"alice": {1},
			"bob":   {2},
			"carol": {3},
		},
		Rules: []Rule{
			// Rule 0: wildcard destination - alice can talk to ANYONE on tcp/22
			{From: "alice", To: "*", Ports: []PortRange{{Proto: ProtoTCP, Start: 22, End: 22}}},
			// Rule 1: specific destination - alice CANNOT talk to bob on tcp/22 (deny by ordering)
			// Since rule 0 is first and matches, this rule should never be reached for alice->bob:22
			{From: "alice", To: "bob", Ports: []PortRange{{Proto: ProtoTCP, Start: 22, End: 22}}},
		},
	}

	compiled := p.Compile()

	// alice -> bob on tcp/22 should match rule 0 (wildcard) and be allowed
	dec := compiled.Decide([32]byte{1}, [32]byte{2}, ProtoTCP, 22)
	if dec.Action != ActionAllow {
		t.Errorf("alice->bob tcp/22: got %v, want allow", dec.Action)
	}
	if dec.RuleIndex != 0 {
		t.Errorf("rule index: got %d, want 0 (wildcard rule evaluated first)", dec.RuleIndex)
	}

	// alice -> carol on tcp/22 should also match rule 0
	dec = compiled.Decide([32]byte{1}, [32]byte{3}, ProtoTCP, 22)
	if dec.Action != ActionAllow {
		t.Errorf("alice->carol tcp/22: got %v, want allow", dec.Action)
	}
	if dec.RuleIndex != 0 {
		t.Errorf("rule index: got %d, want 0", dec.RuleIndex)
	}
}

// TestDecide_RuleOrder_SpecificBeforeStar tests that specific destination rules before
// wildcard rules are evaluated first.
func TestDecide_RuleOrder_SpecificBeforeStar(t *testing.T) {
	p := &Policy{
		Version: 1,
		Default: DefaultDeny,
		Peers: map[string]PeerKey{
			"alice": {1},
			"bob":   {2},
			"carol": {3},
		},
		Rules: []Rule{
			// Rule 0: specific destination - alice can talk to bob on tcp/22
			{From: "alice", To: "bob", Ports: []PortRange{{Proto: ProtoTCP, Start: 22, End: 22}}},
			// Rule 1: wildcard destination - alice can talk to ANYONE on tcp/80
			{From: "alice", To: "*", Ports: []PortRange{{Proto: ProtoTCP, Start: 80, End: 80}}},
		},
	}

	compiled := p.Compile()

	// alice -> bob on tcp/22 should match rule 0
	dec := compiled.Decide([32]byte{1}, [32]byte{2}, ProtoTCP, 22)
	if dec.Action != ActionAllow {
		t.Errorf("alice->bob tcp/22: got %v, want allow", dec.Action)
	}
	if dec.RuleIndex != 0 {
		t.Errorf("rule index: got %d, want 0", dec.RuleIndex)
	}

	// alice -> bob on tcp/80 should match rule 1 (wildcard)
	dec = compiled.Decide([32]byte{1}, [32]byte{2}, ProtoTCP, 80)
	if dec.Action != ActionAllow {
		t.Errorf("alice->bob tcp/80: got %v, want allow", dec.Action)
	}
	if dec.RuleIndex != 1 {
		t.Errorf("rule index: got %d, want 1", dec.RuleIndex)
	}

	// alice -> carol on tcp/80 should match rule 1
	dec = compiled.Decide([32]byte{1}, [32]byte{3}, ProtoTCP, 80)
	if dec.Action != ActionAllow {
		t.Errorf("alice->carol tcp/80: got %v, want allow", dec.Action)
	}
	if dec.RuleIndex != 1 {
		t.Errorf("rule index: got %d, want 1", dec.RuleIndex)
	}
}

// TestDecide_RuleOrder_StarSource tests file order with wildcard source.
func TestDecide_RuleOrder_StarSource(t *testing.T) {
	p := &Policy{
		Version: 1,
		Default: DefaultDeny,
		Peers: map[string]PeerKey{
			"alice": {1},
			"bob":   {2},
			"carol": {3},
		},
		Rules: []Rule{
			// Rule 0: wildcard source - ANYONE can talk to bob on tcp/22
			{From: "*", To: "bob", Ports: []PortRange{{Proto: ProtoTCP, Start: 22, End: 22}}},
			// Rule 1: specific source - carol CANNOT talk to bob on tcp/22 (but rule 0 allows it)
			{From: "carol", To: "bob", Ports: []PortRange{{Proto: ProtoTCP, Start: 22, End: 22}}},
		},
	}

	compiled := p.Compile()

	// carol -> bob on tcp/22 should match rule 0 (wildcard source) and be allowed
	dec := compiled.Decide([32]byte{3}, [32]byte{2}, ProtoTCP, 22)
	if dec.Action != ActionAllow {
		t.Errorf("carol->bob tcp/22: got %v, want allow", dec.Action)
	}
	if dec.RuleIndex != 0 {
		t.Errorf("rule index: got %d, want 0 (wildcard source rule evaluated first)", dec.RuleIndex)
	}

	// alice -> bob on tcp/22 should also match rule 0
	dec = compiled.Decide([32]byte{1}, [32]byte{2}, ProtoTCP, 22)
	if dec.Action != ActionAllow {
		t.Errorf("alice->bob tcp/22: got %v, want allow", dec.Action)
	}
	if dec.RuleIndex != 0 {
		t.Errorf("rule index: got %d, want 0", dec.RuleIndex)
	}
}

// TestDecide_RuleOrder_DifferentPorts tests that file order works across different ports.
func TestDecide_RuleOrder_DifferentPorts(t *testing.T) {
	p := &Policy{
		Version: 1,
		Default: DefaultDeny,
		Peers: map[string]PeerKey{
			"alice": {1},
			"bob":   {2},
		},
		Rules: []Rule{
			// Rule 0: alice -> bob on tcp/22
			{From: "alice", To: "bob", Ports: []PortRange{{Proto: ProtoTCP, Start: 22, End: 22}}},
			// Rule 1: alice -> bob on tcp/80
			{From: "alice", To: "bob", Ports: []PortRange{{Proto: ProtoTCP, Start: 80, End: 80}}},
			// Rule 2: wildcard - alice -> anyone on any port
			{From: "alice", To: "*", Ports: []PortRange{{Proto: ProtoAny, Start: 0, End: 65535}}},
		},
	}

	compiled := p.Compile()

	// alice -> bob on tcp/22 matches rule 0
	dec := compiled.Decide([32]byte{1}, [32]byte{2}, ProtoTCP, 22)
	if dec.RuleIndex != 0 {
		t.Errorf("tcp/22: rule index got %d, want 0", dec.RuleIndex)
	}

	// alice -> bob on tcp/80 matches rule 1
	dec = compiled.Decide([32]byte{1}, [32]byte{2}, ProtoTCP, 80)
	if dec.RuleIndex != 1 {
		t.Errorf("tcp/80: rule index got %d, want 1", dec.RuleIndex)
	}

	// alice -> bob on tcp/443 matches rule 2 (wildcard)
	dec = compiled.Decide([32]byte{1}, [32]byte{2}, ProtoTCP, 443)
	if dec.RuleIndex != 2 {
		t.Errorf("tcp/443: rule index got %d, want 2", dec.RuleIndex)
	}
}
