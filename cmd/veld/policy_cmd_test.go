// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestPolicyCheck_Golden(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir := t.TempDir()

	// Copy the test policy file
	policySrc := filepath.Join("testdata", "policy_valid.toml")
	policyDst := filepath.Join(tmpDir, "policy_valid.toml")
	data, err := os.ReadFile(policySrc)
	if err != nil {
		t.Fatalf("read test policy: %v", err)
	}
	if err := os.WriteFile(policyDst, data, 0o600); err != nil {
		t.Fatalf("write test policy: %v", err)
	}

	// Run the check command
	cmd := newPolicyCheckCmd()
	cmd.SetArgs([]string{policyDst})
	cmd.SetOut(&strings.Builder{})
	cmd.SetErr(&strings.Builder{})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("policy check failed: %v", err)
	}

	stdout := cmd.OutOrStdout().(*strings.Builder).String()
	stderr := cmd.ErrOrStderr().(*strings.Builder).String()

	// Verify key output elements
	if !strings.Contains(stdout, "Policy OK (version 1)") {
		t.Errorf("stdout missing 'Policy OK (version 1)': %s", stdout)
	}
	if !strings.Contains(stdout, "Default: deny") {
		t.Errorf("stdout missing 'Default: deny': %s", stdout)
	}
	if !strings.Contains(stdout, "Peers (3):") {
		t.Errorf("stdout missing 'Peers (3):': %s", stdout)
	}
	if !strings.Contains(stdout, "alice: ed25519:") {
		t.Errorf("stdout missing alice peer: %s", stdout)
	}
	if !strings.Contains(stdout, "bob: ed25519:") {
		t.Errorf("stdout missing bob peer: %s", stdout)
	}
	if !strings.Contains(stdout, "carol: ed25519:") {
		t.Errorf("stdout missing carol peer: %s", stdout)
	}
	if !strings.Contains(stdout, "Tags (2):") {
		t.Errorf("stdout missing 'Tags (2):': %s", stdout)
	}
	if !strings.Contains(stdout, "admins: alice, bob") {
		t.Errorf("stdout missing admins tag: %s", stdout)
	}
	if !strings.Contains(stdout, "servers: carol") {
		t.Errorf("stdout missing servers tag: %s", stdout)
	}
	if !strings.Contains(stdout, "Rules (3):") {
		t.Errorf("stdout missing 'Rules (3):': %s", stdout)
	}
	if !strings.Contains(stdout, "[0] from=alice to=bob") {
		t.Errorf("stdout missing rule 0: %s", stdout)
	}
	if !strings.Contains(stdout, "[1] from=tag:admins to=tag:servers") {
		t.Errorf("stdout missing rule 1: %s", stdout)
	}
	if !strings.Contains(stdout, "[2] from=* to=bob") {
		t.Errorf("stdout missing rule 2: %s", stdout)
	}
	if !strings.Contains(stdout, "Outbound-only peers: carol") {
		t.Errorf("stdout missing outbound-only: %s", stdout)
	}

	// Warnings should go to stderr (none expected for valid policy)
	if stderr != "" {
		t.Logf("stderr: %s", stderr)
	}
}

func TestPolicyCheck_InvalidPolicy(t *testing.T) {
	tmpDir := t.TempDir()

	// Create an invalid policy file (missing default)
	invalidPolicy := `
version = 1
[peers]
alice = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
`
	policyPath := filepath.Join(tmpDir, "invalid.toml")
	if err := os.WriteFile(policyPath, []byte(invalidPolicy), 0o600); err != nil {
		t.Fatalf("write invalid policy: %v", err)
	}

	cmd := newPolicyCheckCmd()
	cmd.SetArgs([]string{policyPath})
	cmd.SetOut(&strings.Builder{})
	cmd.SetErr(&strings.Builder{})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for invalid policy")
	}

	stderr := cmd.ErrOrStderr().(*strings.Builder).String()
	if !strings.Contains(stderr, "default is required") {
		t.Errorf("stderr missing 'default is required': %s", stderr)
	}
}

func TestPolicyCheck_UnknownPeer(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a policy with unknown peer in rule
	invalidPolicy := `
version = 1
default = "deny"
[peers]
alice = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
[[rule]]
from = "alice"
to   = "unknown"
ports = ["tcp/22"]
`
	policyPath := filepath.Join(tmpDir, "unknown_peer.toml")
	if err := os.WriteFile(policyPath, []byte(invalidPolicy), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	cmd := newPolicyCheckCmd()
	cmd.SetArgs([]string{policyPath})
	cmd.SetOut(&strings.Builder{})
	cmd.SetErr(&strings.Builder{})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for unknown peer")
	}

	stderr := cmd.ErrOrStderr().(*strings.Builder).String()
	if !strings.Contains(stderr, "unknown peer") {
		t.Errorf("stderr missing 'unknown peer': %s", stderr)
	}
}

func TestPolicyCheck_UnmatchableRuleWarning(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a policy with unmatchable rule (from and to are the same peer)
	policy := `
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
	policyPath := filepath.Join(tmpDir, "unmatchable.toml")
	if err := os.WriteFile(policyPath, []byte(policy), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	cmd := newPolicyCheckCmd()
	cmd.SetArgs([]string{policyPath})
	cmd.SetOut(&strings.Builder{})
	cmd.SetErr(&strings.Builder{})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("policy check failed: %v", err)
	}

	stderr := cmd.ErrOrStderr().(*strings.Builder).String()
	if !strings.Contains(stderr, "can never match") {
		t.Errorf("stderr missing 'can never match' warning: %s", stderr)
	}
}

func TestPolicyTest_Golden(t *testing.T) {
	tmpDir := t.TempDir()

	policySrc := filepath.Join("testdata", "policy_valid.toml")
	policyDst := filepath.Join(tmpDir, "policy_valid.toml")
	data, err := os.ReadFile(policySrc)
	if err != nil {
		t.Fatalf("read test policy: %v", err)
	}
	if err := os.WriteFile(policyDst, data, 0o600); err != nil {
		t.Fatalf("write test policy: %v", err)
	}

	tests := []struct {
		name       string
		args       []string
		wantStdout string
		wantStderr string
		wantCode   int
	}{
		{
			name:       "allow - alice to bob tcp/22 matches rule 0",
			args:       []string{policyDst, "alice", "bob", "tcp/22"},
			wantStdout: "ALLOW\n  Matched rule 0: from=alice to=bob",
			wantCode:   0,
		},
		{
			name:       "deny - bob to alice tcp/22 (no reverse rule)",
			args:       []string{policyDst, "bob", "alice", "tcp/22"},
			wantStdout: "DENY\n  Default action: deny",
			wantCode:   0,
		},
		{
			name:       "deny - alice to bob tcp/80 (port not in range)",
			args:       []string{policyDst, "alice", "bob", "tcp/80"},
			wantStdout: "DENY\n  Default action: deny",
			wantCode:   0,
		},
		{
			name:       "allow - alice to bob icmp matches rule 2",
			args:       []string{policyDst, "alice", "bob", "icmp"},
			wantStdout: "ALLOW\n  Matched rule 2: from=* to=bob ports=icmp",
			wantCode:   0,
		},
		{
			name:       "deny - alice to carol tcp/22 (outbound-only carol)",
			args:       []string{policyDst, "alice", "carol", "tcp/22"},
			wantStdout: "DENY\n  (outbound-only denial)",
			wantCode:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newPolicyTestCmd()
			cmd.SetArgs(tt.args)
			cmd.SetOut(&strings.Builder{})
			cmd.SetErr(&strings.Builder{})

			err := cmd.Execute()
			stdout := cmd.OutOrStdout().(*strings.Builder).String()
			stderr := cmd.ErrOrStderr().(*strings.Builder).String()

			if (err != nil) != (tt.wantCode != 0) {
				t.Errorf("execute error mismatch: got err=%v, wantCode=%d", err, tt.wantCode)
			}

			if !strings.Contains(stdout, tt.wantStdout) {
				t.Errorf("stdout mismatch:\ngot:  %s\nexpected to contain: %s", stdout, tt.wantStdout)
			}

			// Warnings should go to stderr
			if tt.wantStderr != "" && !strings.Contains(stderr, tt.wantStderr) {
				t.Errorf("stderr missing %q: %s", tt.wantStderr, stderr)
			}
		})
	}
}

func TestPolicyTest_Ed25519Prefix(t *testing.T) {
	tmpDir := t.TempDir()

	policySrc := filepath.Join("testdata", "policy_valid.toml")
	policyDst := filepath.Join(tmpDir, "policy_valid.toml")
	data, err := os.ReadFile(policySrc)
	if err != nil {
		t.Fatalf("read test policy: %v", err)
	}
	if err := os.WriteFile(policyDst, data, 0o600); err != nil {
		t.Fatalf("write test policy: %v", err)
	}

	// alice's key in base64 with ed25519: prefix
	aliceB64 := "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	bobB64 := "ed25519:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="

	cmd := newPolicyTestCmd()
	cmd.SetArgs([]string{policyDst, aliceB64, bobB64, "tcp/22"})
	cmd.SetOut(&strings.Builder{})
	cmd.SetErr(&strings.Builder{})

	err = cmd.Execute()
	if err != nil {
		t.Fatalf("policy test failed: %v", err)
	}

	stdout := cmd.OutOrStdout().(*strings.Builder).String()
	if !strings.Contains(stdout, "ALLOW") {
		t.Errorf("expected ALLOW for ed25519: prefix: %s", stdout)
	}
}

func TestPolicyTest_RejectsWildcard(t *testing.T) {
	tmpDir := t.TempDir()

	policySrc := filepath.Join("testdata", "policy_valid.toml")
	policyDst := filepath.Join(tmpDir, "policy_valid.toml")
	data, err := os.ReadFile(policySrc)
	if err != nil {
		t.Fatalf("read test policy: %v", err)
	}
	if err := os.WriteFile(policyDst, data, 0o600); err != nil {
		t.Fatalf("write test policy: %v", err)
	}

	cmd := newPolicyTestCmd()
	cmd.SetArgs([]string{policyDst, "*", "bob", "tcp/22"})
	cmd.SetOut(&strings.Builder{})
	cmd.SetErr(&strings.Builder{})

	err = cmd.Execute()
	if err == nil {
		t.Fatal("expected error for wildcard from")
	}

	stderr := cmd.ErrOrStderr().(*strings.Builder).String()
	if !strings.Contains(stderr, "wildcard") {
		t.Errorf("stderr missing wildcard error: %s", stderr)
	}
}

func TestPolicyTest_RejectsTag(t *testing.T) {
	tmpDir := t.TempDir()

	policySrc := filepath.Join("testdata", "policy_valid.toml")
	policyDst := filepath.Join(tmpDir, "policy_valid.toml")
	data, err := os.ReadFile(policySrc)
	if err != nil {
		t.Fatalf("read test policy: %v", err)
	}
	if err := os.WriteFile(policyDst, data, 0o600); err != nil {
		t.Fatalf("write test policy: %v", err)
	}

	cmd := newPolicyTestCmd()
	cmd.SetArgs([]string{policyDst, "tag:admins", "bob", "tcp/22"})
	cmd.SetOut(&strings.Builder{})
	cmd.SetErr(&strings.Builder{})

	err = cmd.Execute()
	if err == nil {
		t.Fatal("expected error for tag from")
	}

	stderr := cmd.ErrOrStderr().(*strings.Builder).String()
	if !strings.Contains(stderr, "tag") {
		t.Errorf("stderr missing tag error: %s", stderr)
	}
}

func TestPolicyTest_PortRangeUsesFirstPort(t *testing.T) {
	tmpDir := t.TempDir()

	policySrc := filepath.Join("testdata", "policy_valid.toml")
	policyDst := filepath.Join(tmpDir, "policy_valid.toml")
	data, err := os.ReadFile(policySrc)
	if err != nil {
		t.Fatalf("read test policy: %v", err)
	}
	if err := os.WriteFile(policyDst, data, 0o600); err != nil {
		t.Fatalf("write test policy: %v", err)
	}

	// Rule 0 allows tcp/22 and tcp/8000-8099
	// Test with tcp/8000-8099 - should use first port (8000) and match rule 0
	cmd := newPolicyTestCmd()
	cmd.SetArgs([]string{policyDst, "alice", "bob", "tcp/8000-8099"})
	cmd.SetOut(&strings.Builder{})
	cmd.SetErr(&strings.Builder{})

	err = cmd.Execute()
	if err != nil {
		t.Fatalf("policy test failed: %v", err)
	}

	stdout := cmd.OutOrStdout().(*strings.Builder).String()
	if !strings.Contains(stdout, "ALLOW") {
		t.Errorf("expected ALLOW for port range (first port 8000): %s", stdout)
	}
	if !strings.Contains(stdout, "Matched rule 0") {
		t.Errorf("expected rule 0 match: %s", stdout)
	}
}

func TestPolicyTest_AllTCPPorts(t *testing.T) {
	tmpDir := t.TempDir()

	policySrc := filepath.Join("testdata", "policy_valid.toml")
	policyDst := filepath.Join(tmpDir, "policy_valid.toml")
	data, err := os.ReadFile(policySrc)
	if err != nil {
		t.Fatalf("read test policy: %v", err)
	}
	if err := os.WriteFile(policyDst, data, 0o600); err != nil {
		t.Fatalf("write test policy: %v", err)
	}

	// Test with tcp/22 (all TCP ports) - should match rule 0 since it allows tcp/22 and tcp/8000-8099
	cmd := newPolicyTestCmd()
	cmd.SetArgs([]string{policyDst, "alice", "bob", "tcp/22"})
	cmd.SetOut(&strings.Builder{})
	cmd.SetErr(&strings.Builder{})

	err = cmd.Execute()
	if err != nil {
		t.Fatalf("policy test failed: %v", err)
	}

	stdout := cmd.OutOrStdout().(*strings.Builder).String()
	if !strings.Contains(stdout, "ALLOW") {
		t.Errorf("expected ALLOW for tcp/22: %s", stdout)
	}
	if !strings.Contains(stdout, "Matched rule 0") {
		t.Errorf("expected rule 0 match: %s", stdout)
	}
}

func TestPolicyTest_UnknownPeer(t *testing.T) {
	tmpDir := t.TempDir()

	policySrc := filepath.Join("testdata", "policy_valid.toml")
	policyDst := filepath.Join(tmpDir, "policy_valid.toml")
	data, err := os.ReadFile(policySrc)
	if err != nil {
		t.Fatalf("read test policy: %v", err)
	}
	if err := os.WriteFile(policyDst, data, 0o600); err != nil {
		t.Fatalf("write test policy: %v", err)
	}

	cmd := newPolicyTestCmd()
	cmd.SetArgs([]string{policyDst, "unknown", "bob", "tcp/22"})
	cmd.SetOut(&strings.Builder{})
	cmd.SetErr(&strings.Builder{})

	err = cmd.Execute()
	if err == nil {
		t.Fatal("expected error for unknown peer")
	}

	stderr := cmd.ErrOrStderr().(*strings.Builder).String()
	if !strings.Contains(stderr, "unknown peer or ID") {
		t.Errorf("stderr missing unknown peer error: %s", stderr)
	}
}

// newPolicyCheckCmd creates a new policy check command for testing.
func newPolicyCheckCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "check <policy.toml>",
		Short: "Validate a policy file",
		Args:  cobra.ExactArgs(1),
		RunE:  runPolicyCheck,
	}
}

// newPolicyTestCmd creates a new policy test command for testing.
func newPolicyTestCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "test <policy.toml> <from> <to> <proto/port>",
		Short: "Test a policy decision",
		Args:  cobra.ExactArgs(4),
		RunE:  runPolicyTest,
	}
}
