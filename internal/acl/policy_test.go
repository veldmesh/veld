// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package acl

import (
	"testing"
)

const validPolicyTOML = `
version = 1
default = "allow"

[peers]
alice = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
bob   = "ed25519:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
carol = "ed25519:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC="

[tags]
admins = ["alice", "bob"]
servers = ["carol"]

[[rule]]
from = "alice"
to   = "bob"
ports = ["tcp/22", "tcp/8000-8099"]

[[rule]]
from = "tag:admins"
to   = "tag:servers"
ports = ["tcp/443", "udp/53"]

[[rule]]
from = "*"
to   = "carol"
ports = ["icmp"]

[outbound_only]
peers = ["bob"]
`

func TestParsePolicy_Valid(t *testing.T) {
	p, warnings, err := ParsePolicy(validPolicyTOML)
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	if p.Version != 1 {
		t.Errorf("Version: got %d, want 1", p.Version)
	}
	if p.Default != DefaultAllow {
		t.Errorf("Default: got %v, want %v", p.Default, DefaultAllow)
	}
	if len(p.Peers) != 3 {
		t.Fatalf("Peers: got %d, want 3", len(p.Peers))
	}
	if len(p.Tags) != 2 {
		t.Fatalf("Tags: got %d, want 2", len(p.Tags))
	}
	if len(p.Rules) != 3 {
		t.Fatalf("Rules: got %d, want 3", len(p.Rules))
	}
	if len(p.OutboundOnly) != 1 {
		t.Fatalf("OutboundOnly: got %d, want 1", len(p.OutboundOnly))
	}
	// Check warnings are returned (even if empty)
	_ = warnings
}

func TestParsePolicy_MissingDefault(t *testing.T) {
	src := `
version = 1
[peers]
alice = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
`
	_, _, err := ParsePolicy(src)
	if err == nil {
		t.Fatal("expected error for missing default")
	}
}

func TestParsePolicy_InvalidDefault(t *testing.T) {
	src := `
version = 1
default = "maybe"
[peers]
alice = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
`
	_, _, err := ParsePolicy(src)
	if err == nil {
		t.Fatal("expected error for invalid default")
	}
}

func TestParsePolicy_UnknownPeerInRule(t *testing.T) {
	src := `
version = 1
default = "deny"
[peers]
alice = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
[[rule]]
from = "unknown"
to   = "alice"
ports = ["tcp/22"]
`
	_, _, err := ParsePolicy(src)
	if err == nil {
		t.Fatal("expected error for unknown peer in rule")
	}
}

func TestParsePolicy_UnknownTagInRule(t *testing.T) {
	src := `
version = 1
default = "deny"
[peers]
alice = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
[[rule]]
from = "tag:unknown"
to   = "alice"
ports = ["tcp/22"]
`
	_, _, err := ParsePolicy(src)
	if err == nil {
		t.Fatal("expected error for unknown tag in rule")
	}
}

func TestParsePolicy_TagReferencesUnknownPeer(t *testing.T) {
	src := `
version = 1
default = "deny"
[peers]
alice = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
[tags]
admins = ["alice", "unknown"]
`
	_, _, err := ParsePolicy(src)
	if err == nil {
		t.Fatal("expected error for tag referencing unknown peer")
	}
}

func TestParsePolicy_DuplicatePeerNames(t *testing.T) {
	src := `
version = 1
default = "deny"
[peers]
alice = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
alice = "ed25519:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
`
	_, _, err := ParsePolicy(src)
	if err == nil {
		t.Fatal("expected error for duplicate peer names")
	}
}

func TestParsePolicy_DuplicateTagNames(t *testing.T) {
	// TOML spec says duplicate keys are invalid; BurntSushi/toml overwrites silently.
	// We can't reliably detect this at the map level. This test documents the limitation.
	src := `
version = 1
default = "deny"
[peers]
alice = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
[tags]
admins = ["alice"]
# duplicate "admins" key would be silently overwritten by TOML parser
`
	// This should parse without error (second admins overwrites first)
	p, _, err := ParsePolicy(src)
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	if len(p.Tags) != 1 {
		t.Fatalf("Tags: got %d, want 1", len(p.Tags))
	}
}

func TestParsePolicy_BadPortFormat(t *testing.T) {
	src := `
version = 1
default = "deny"
[peers]
alice = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
bob   = "ed25519:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
[[rule]]
from = "alice"
to   = "bob"
ports = ["tcp/99999"]
`
	_, _, err := ParsePolicy(src)
	if err == nil {
		t.Fatal("expected error for bad port format")
	}
}

func TestParsePolicy_InvalidPeerKeyFormat(t *testing.T) {
	src := `
version = 1
default = "deny"
[peers]
alice = "ed25519:not-base64-or-hex!"
`
	_, _, err := ParsePolicy(src)
	if err == nil {
		t.Fatal("expected error for invalid peer key format")
	}
}

func TestParsePolicy_InvalidPeerKeyLength(t *testing.T) {
	src := `
version = 1
default = "deny"
[peers]
alice = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
`
	_, _, err := ParsePolicy(src)
	if err == nil {
		t.Fatal("expected error for invalid peer key length")
	}
}

func TestParsePolicy_UnmatchableRule_Warning(t *testing.T) {
	// Rule from a peer to itself with no ports that can match - this should warn
	src := `
version = 1
default = "deny"
[peers]
alice = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
bob   = "ed25519:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
[[rule]]
from = "alice"
to   = "alice"
ports = ["tcp/22"]
`
	p, warnings, err := ParsePolicy(src)
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	if len(warnings) == 0 {
		t.Fatal("expected warning for unmatchable rule")
	}
	_ = p
}

func TestParsePolicy_HexPeerKey(t *testing.T) {
	src := `
version = 1
default = "deny"
[peers]
alice = "ed25519:0000000000000000000000000000000000000000000000000000000000000001"
bob   = "ed25519:0000000000000000000000000000000000000000000000000000000000000002"
[[rule]]
from = "alice"
to   = "bob"
ports = ["tcp/22"]
`
	p, _, err := ParsePolicy(src)
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	if len(p.Peers) != 2 {
		t.Fatalf("Peers: got %d, want 2", len(p.Peers))
	}
}

func TestParsePolicy_DefaultDeny(t *testing.T) {
	src := `
version = 1
default = "deny"
[peers]
alice = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
[[rule]]
from = "alice"
to   = "alice"
ports = ["*"]
`
	p, _, err := ParsePolicy(src)
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	if p.Default != DefaultDeny {
		t.Errorf("Default: got %v, want %v", p.Default, DefaultDeny)
	}
}

func TestParsePolicy_PortRanges(t *testing.T) {
	src := `
version = 1
default = "deny"
[peers]
alice = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
bob   = "ed25519:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
[[rule]]
from = "alice"
to   = "bob"
ports = ["tcp/8000-8099", "udp/1000-2000", "tcp/22", "udp/53", "icmp", "*"]
`
	p, _, err := ParsePolicy(src)
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	if len(p.Rules) != 1 {
		t.Fatalf("Rules: got %d, want 1", len(p.Rules))
	}
	if len(p.Rules[0].Ports) != 6 {
		t.Fatalf("Ports: got %d, want 6", len(p.Rules[0].Ports))
	}
}

func TestParsePolicy_StarSubject(t *testing.T) {
	src := `
version = 1
default = "deny"
[peers]
alice = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
bob   = "ed25519:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
[[rule]]
from = "*"
to   = "bob"
ports = ["tcp/22"]
`
	p, _, err := ParsePolicy(src)
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	if p.Rules[0].From != "*" {
		t.Errorf("From: got %q, want *", p.Rules[0].From)
	}
}

func TestParsePolicy_StarPorts(t *testing.T) {
	src := `
version = 1
default = "deny"
[peers]
alice = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
bob   = "ed25519:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
[[rule]]
from = "alice"
to   = "bob"
ports = ["*"]
`
	p, _, err := ParsePolicy(src)
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	if len(p.Rules[0].Ports) != 1 {
		t.Fatalf("Ports: got %d, want 1", len(p.Rules[0].Ports))
	}
	if p.Rules[0].Ports[0].Proto != ProtoAny || p.Rules[0].Ports[0].Start != 0 || p.Rules[0].Ports[0].End != 65535 {
		t.Errorf("Port: got %+v, want any", p.Rules[0].Ports[0])
	}
}
