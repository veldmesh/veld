// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package acl

import (
	"testing"
)

func TestDecide_BasicAllow(t *testing.T) {
	p := &Policy{
		Version: 1,
		Default: DefaultDeny,
		Peers: map[string]PeerKey{
			"alice": {1},
			"bob":   {2},
		},
		Rules: []Rule{
			{From: "alice", To: "bob", Ports: []PortRange{{Proto: ProtoTCP, Start: 22, End: 22}}},
		},
	}

	compiled := p.Compile()

	// alice -> bob on tcp/22 should be allowed
	dec := compiled.Decide([32]byte{1}, [32]byte{2}, ProtoTCP, 22)
	if dec.Action != ActionAllow {
		t.Errorf("alice->bob tcp/22: got %v, want allow", dec.Action)
	}
	if dec.RuleIndex != 0 {
		t.Errorf("rule index: got %d, want 0", dec.RuleIndex)
	}

	// bob -> alice on tcp/22 should be denied (one-way rule)
	dec = compiled.Decide([32]byte{2}, [32]byte{1}, ProtoTCP, 22)
	if dec.Action != ActionDeny {
		t.Errorf("bob->alice tcp/22: got %v, want deny", dec.Action)
	}
	if dec.RuleIndex != -1 {
		t.Errorf("rule index: got %d, want -1 (default)", dec.RuleIndex)
	}
}

func TestDecide_DefaultAllow(t *testing.T) {
	p := &Policy{
		Version: 1,
		Default: DefaultAllow,
		Peers: map[string]PeerKey{
			"alice": {1},
			"bob":   {2},
		},
		Rules: []Rule{
			{From: "alice", To: "bob", Ports: []PortRange{{Proto: ProtoTCP, Start: 22, End: 22}}},
		},
	}

	compiled := p.Compile()

	// bob -> alice should be allowed by default
	dec := compiled.Decide([32]byte{2}, [32]byte{1}, ProtoTCP, 22)
	if dec.Action != ActionAllow {
		t.Errorf("bob->alice tcp/22: got %v, want allow (default)", dec.Action)
	}
	if dec.RuleIndex != -1 {
		t.Errorf("rule index: got %d, want -1 (default)", dec.RuleIndex)
	}
}

func TestDecide_TagExpansion(t *testing.T) {
	p := &Policy{
		Version: 1,
		Default: DefaultDeny,
		Peers: map[string]PeerKey{
			"alice": {1},
			"bob":   {2},
			"carol": {3},
		},
		Tags: map[string][]string{
			"admins":  {"alice", "bob"},
			"servers": {"carol"},
		},
		Rules: []Rule{
			{From: "tag:admins", To: "tag:servers", Ports: []PortRange{{Proto: ProtoTCP, Start: 443, End: 443}}},
		},
	}

	compiled := p.Compile()

	// alice -> carol on tcp/443 should be allowed
	dec := compiled.Decide([32]byte{1}, [32]byte{3}, ProtoTCP, 443)
	if dec.Action != ActionAllow {
		t.Errorf("alice->carol tcp/443: got %v, want allow", dec.Action)
	}

	// bob -> carol on tcp/443 should be allowed
	dec = compiled.Decide([32]byte{2}, [32]byte{3}, ProtoTCP, 443)
	if dec.Action != ActionAllow {
		t.Errorf("bob->carol tcp/443: got %v, want allow", dec.Action)
	}

	// carol -> alice on tcp/443 should be denied (one-way)
	dec = compiled.Decide([32]byte{3}, [32]byte{1}, ProtoTCP, 443)
	if dec.Action != ActionDeny {
		t.Errorf("carol->alice tcp/443: got %v, want deny", dec.Action)
	}
}

func TestDecide_StarSubject(t *testing.T) {
	p := &Policy{
		Version: 1,
		Default: DefaultDeny,
		Peers: map[string]PeerKey{
			"alice": {1},
			"bob":   {2},
		},
		Rules: []Rule{
			{From: "*", To: "bob", Ports: []PortRange{{Proto: ProtoTCP, Start: 22, End: 22}}},
		},
	}

	compiled := p.Compile()

	// alice -> bob on tcp/22 should be allowed
	dec := compiled.Decide([32]byte{1}, [32]byte{2}, ProtoTCP, 22)
	if dec.Action != ActionAllow {
		t.Errorf("alice->bob tcp/22: got %v, want allow", dec.Action)
	}

	// bob -> bob on tcp/22 should be allowed (from * includes bob)
	dec = compiled.Decide([32]byte{2}, [32]byte{2}, ProtoTCP, 22)
	if dec.Action != ActionAllow {
		t.Errorf("bob->bob tcp/22: got %v, want allow", dec.Action)
	}
}

func TestDecide_PortRange(t *testing.T) {
	p := &Policy{
		Version: 1,
		Default: DefaultDeny,
		Peers: map[string]PeerKey{
			"alice": {1},
			"bob":   {2},
		},
		Rules: []Rule{
			{From: "alice", To: "bob", Ports: []PortRange{{Proto: ProtoTCP, Start: 8000, End: 8099}}},
		},
	}

	compiled := p.Compile()

	// alice -> bob on tcp/8000 should be allowed
	dec := compiled.Decide([32]byte{1}, [32]byte{2}, ProtoTCP, 8000)
	if dec.Action != ActionAllow {
		t.Errorf("tcp/8000: got %v, want allow", dec.Action)
	}

	// alice -> bob on tcp/8099 should be allowed
	dec = compiled.Decide([32]byte{1}, [32]byte{2}, ProtoTCP, 8099)
	if dec.Action != ActionAllow {
		t.Errorf("tcp/8099: got %v, want allow", dec.Action)
	}

	// alice -> bob on tcp/7999 should be denied
	dec = compiled.Decide([32]byte{1}, [32]byte{2}, ProtoTCP, 7999)
	if dec.Action != ActionDeny {
		t.Errorf("tcp/7999: got %v, want deny", dec.Action)
	}

	// alice -> bob on tcp/8100 should be denied
	dec = compiled.Decide([32]byte{1}, [32]byte{2}, ProtoTCP, 8100)
	if dec.Action != ActionDeny {
		t.Errorf("tcp/8100: got %v, want deny", dec.Action)
	}
}

func TestDecide_StarPorts(t *testing.T) {
	p := &Policy{
		Version: 1,
		Default: DefaultDeny,
		Peers: map[string]PeerKey{
			"alice": {1},
			"bob":   {2},
		},
		Rules: []Rule{
			{From: "alice", To: "bob", Ports: []PortRange{{Proto: ProtoAny, Start: 0, End: 65535}}},
		},
	}

	compiled := p.Compile()

	// alice -> bob on any protocol/port should be allowed
	for _, proto := range []Proto{ProtoTCP, ProtoUDP, ProtoICMP, ProtoICMPv6} {
		for _, port := range []uint16{0, 22, 53, 80, 443, 65535} {
			dec := compiled.Decide([32]byte{1}, [32]byte{2}, proto, port)
			if dec.Action != ActionAllow {
				t.Errorf("proto=%d port=%d: got %v, want allow", proto, port, dec.Action)
			}
		}
	}
}

func TestDecide_ICMP(t *testing.T) {
	p := &Policy{
		Version: 1,
		Default: DefaultDeny,
		Peers: map[string]PeerKey{
			"alice": {1},
			"bob":   {2},
		},
		Rules: []Rule{
			{From: "alice", To: "bob", Ports: []PortRange{{Proto: ProtoICMP, Start: 0, End: 65535}}},
		},
	}

	compiled := p.Compile()

	// alice -> bob ICMP should be allowed (port ignored for ICMP)
	dec := compiled.Decide([32]byte{1}, [32]byte{2}, ProtoICMP, 0)
	if dec.Action != ActionAllow {
		t.Errorf("ICMP: got %v, want allow", dec.Action)
	}

	// alice -> bob TCP should be denied
	dec = compiled.Decide([32]byte{1}, [32]byte{2}, ProtoTCP, 22)
	if dec.Action != ActionDeny {
		t.Errorf("TCP: got %v, want deny", dec.Action)
	}
}

func TestDecide_ICMPKeywordMatchesICMPv6(t *testing.T) {
	// Test that "icmp" keyword in TOML matches both ICMPv4 and ICMPv6
	p := &Policy{
		Version: 1,
		Default: DefaultDeny,
		Peers: map[string]PeerKey{
			"alice": {1},
			"bob":   {2},
		},
		Rules: []Rule{
			{From: "alice", To: "bob", Ports: []PortRange{{Proto: ProtoICMP, Start: 0, End: 65535, matchICMPv6: true}}},
		},
	}

	compiled := p.Compile()

	// alice -> bob ICMPv4 should be allowed
	dec := compiled.Decide([32]byte{1}, [32]byte{2}, ProtoICMP, 0)
	if dec.Action != ActionAllow {
		t.Errorf("ICMPv4: got %v, want allow", dec.Action)
	}

	// alice -> bob ICMPv6 should also be allowed (this is the fix)
	dec = compiled.Decide([32]byte{1}, [32]byte{2}, ProtoICMPv6, 0)
	if dec.Action != ActionAllow {
		t.Errorf("ICMPv6: got %v, want allow (icmp keyword should match both)", dec.Action)
	}

	// alice -> bob TCP should be denied
	dec = compiled.Decide([32]byte{1}, [32]byte{2}, ProtoTCP, 22)
	if dec.Action != ActionDeny {
		t.Errorf("TCP: got %v, want deny", dec.Action)
	}
}

func TestDecide_ICMPKeywordParsedFromTOML(t *testing.T) {
	// Test that "icmp" keyword parsed from TOML matches both ICMPv4 and ICMPv6
	src := `
version = 1
default = "deny"
[peers]
alice = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
bob   = "ed25519:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
[[rule]]
from = "alice"
to   = "bob"
ports = ["icmp"]
`
	p, _, err := ParsePolicy(src)
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}

	compiled := p.Compile()

	// Use the actual parsed peer keys
	aliceKey := p.Peers["alice"]
	bobKey := p.Peers["bob"]

	// alice -> bob ICMPv4 should be allowed
	dec := compiled.Decide(aliceKey, bobKey, ProtoICMP, 0)
	if dec.Action != ActionAllow {
		t.Errorf("ICMPv4: got %v, want allow", dec.Action)
	}

	// alice -> bob ICMPv6 should also be allowed (this is the fix)
	dec = compiled.Decide(aliceKey, bobKey, ProtoICMPv6, 0)
	if dec.Action != ActionAllow {
		t.Errorf("ICMPv6: got %v, want allow (icmp keyword should match both)", dec.Action)
	}

	// alice -> bob TCP should be denied
	dec = compiled.Decide(aliceKey, bobKey, ProtoTCP, 22)
	if dec.Action != ActionDeny {
		t.Errorf("TCP: got %v, want deny", dec.Action)
	}
}

func TestDecide_OutboundOnly(t *testing.T) {
	p := &Policy{
		Version: 1,
		Default: DefaultDeny,
		Peers: map[string]PeerKey{
			"alice": {1},
			"bob":   {2},
		},
		Rules: []Rule{
			{From: "*", To: "bob", Ports: []PortRange{{Proto: ProtoTCP, Start: 22, End: 22}}},
		},
		OutboundOnly: []string{"bob"},
	}

	compiled := p.Compile()

	// alice -> bob on tcp/22 should be DENIED (bob is outbound-only, cannot receive inbound)
	dec := compiled.Decide([32]byte{1}, [32]byte{2}, ProtoTCP, 22)
	if dec.Action != ActionDeny {
		t.Errorf("alice->bob tcp/22: got %v, want deny (outbound_only)", dec.Action)
	}
	if !dec.OutboundOnly {
		t.Errorf("alice->bob: OutboundOnly flag not set")
	}

	// bob -> alice on tcp/22 should be allowed (bob is starting the connection)
	// Note: this requires a rule that allows bob -> alice
	p2 := &Policy{
		Version: 1,
		Default: DefaultDeny,
		Peers: map[string]PeerKey{
			"alice": {1},
			"bob":   {2},
		},
		Rules: []Rule{
			{From: "bob", To: "alice", Ports: []PortRange{{Proto: ProtoTCP, Start: 22, End: 22}}},
		},
		OutboundOnly: []string{"bob"},
	}
	compiled2 := p2.Compile()
	dec = compiled2.Decide([32]byte{2}, [32]byte{1}, ProtoTCP, 22)
	if dec.Action != ActionAllow {
		t.Errorf("bob->alice tcp/22: got %v, want allow (bob starts connection)", dec.Action)
	}
}

func TestDecide_RuleIndex(t *testing.T) {
	p := &Policy{
		Version: 1,
		Default: DefaultDeny,
		Peers: map[string]PeerKey{
			"alice": {1},
			"bob":   {2},
		},
		Rules: []Rule{
			{From: "alice", To: "bob", Ports: []PortRange{{Proto: ProtoTCP, Start: 22, End: 22}}},
			{From: "alice", To: "bob", Ports: []PortRange{{Proto: ProtoTCP, Start: 80, End: 80}}},
		},
	}

	compiled := p.Compile()

	// First rule should match tcp/22
	dec := compiled.Decide([32]byte{1}, [32]byte{2}, ProtoTCP, 22)
	if dec.RuleIndex != 0 {
		t.Errorf("tcp/22: rule index got %d, want 0", dec.RuleIndex)
	}

	// Second rule should match tcp/80
	dec = compiled.Decide([32]byte{1}, [32]byte{2}, ProtoTCP, 80)
	if dec.RuleIndex != 1 {
		t.Errorf("tcp/80: rule index got %d, want 1", dec.RuleIndex)
	}
}

func TestDecide_UnknownPeer(t *testing.T) {
	p := &Policy{
		Version: 1,
		Default: DefaultDeny,
		Peers: map[string]PeerKey{
			"alice": {1},
		},
		Rules: []Rule{
			{From: "alice", To: "alice", Ports: []PortRange{{Proto: ProtoTCP, Start: 22, End: 22}}},
		},
	}

	compiled := p.Compile()

	// Unknown peer ID should fall back to default
	dec := compiled.Decide([32]byte{99}, [32]byte{1}, ProtoTCP, 22)
	if dec.Action != ActionDeny {
		t.Errorf("unknown src: got %v, want deny", dec.Action)
	}

	dec = compiled.Decide([32]byte{1}, [32]byte{99}, ProtoTCP, 22)
	if dec.Action != ActionDeny {
		t.Errorf("unknown dst: got %v, want deny", dec.Action)
	}
}

func TestDecide_FirstMatchWins(t *testing.T) {
	p := &Policy{
		Version: 1,
		Default: DefaultDeny,
		Peers: map[string]PeerKey{
			"alice": {1},
			"bob":   {2},
		},
		Rules: []Rule{
			{From: "alice", To: "bob", Ports: []PortRange{{Proto: ProtoTCP, Start: 22, End: 22}}},
			{From: "alice", To: "bob", Ports: []PortRange{{Proto: ProtoTCP, Start: 80, End: 80}}},
		},
	}

	compiled := p.Compile()

	// Both rules match tcp/22 and tcp/80 respectively, first match wins
	dec := compiled.Decide([32]byte{1}, [32]byte{2}, ProtoTCP, 22)
	if dec.RuleIndex != 0 {
		t.Errorf("tcp/22: rule index got %d, want 0 (first match)", dec.RuleIndex)
	}
}

func TestDecide_DisjointTagsWarning(t *testing.T) {
	// Test that disjoint tags produce a warning
	src := `
version = 1
default = "deny"
[peers]
alice = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
bob   = "ed25519:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
carol = "ed25519:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC="
[tags]
admins = ["alice"]
servers = ["bob"]
[[rule]]
from = "tag:admins"
to   = "tag:servers"
ports = ["tcp/22"]
`
	p, warnings, err := ParsePolicy(src)
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	if len(warnings) == 0 {
		t.Fatal("expected warning for disjoint tags")
	}
	_ = p
}
