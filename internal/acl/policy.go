// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package acl

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/BurntSushi/toml"
)

// DefaultAction represents the default policy action.
type DefaultAction int

const (
	DefaultAllow DefaultAction = iota
	DefaultDeny
)

// String returns the string representation of the default action.
func (d DefaultAction) String() string {
	if d == DefaultDeny {
		return "deny"
	}
	return "allow"
}

// ParseDefaultAction parses a string into a DefaultAction.
func ParseDefaultAction(s string) (DefaultAction, error) {
	switch strings.ToLower(s) {
	case "allow":
		return DefaultAllow, nil
	case "deny":
		return DefaultDeny, nil
	default:
		return DefaultAllow, fmt.Errorf("invalid default action: %q", s)
	}
}

// Proto represents the IP protocol.
type Proto uint8

const (
	ProtoTCP    Proto = 6
	ProtoUDP    Proto = 17
	ProtoICMP   Proto = 1
	ProtoICMPv6 Proto = 58
	ProtoAny    Proto = 255
)

// PortRange represents a port or port range for a specific protocol.
type PortRange struct {
	Proto Proto
	Start uint16
	End   uint16
}

// ContainsPort returns true if the port range contains the given port.
func (pr PortRange) ContainsPort(port uint16) bool {
	if pr.Proto != ProtoAny && pr.Proto != ProtoICMP && pr.Proto != ProtoICMPv6 {
		return port >= pr.Start && port <= pr.End
	}
	// For ICMP and "any", port is ignored (always matches)
	return true
}

// Rule represents a single ACL rule.
type Rule struct {
	From  string      // peer name, "tag:<name>", or "*"
	To    string      // peer name, "tag:<name>", or "*"
	Ports []PortRange // allowed protocols/ports
}

// PeerKey represents an Ed25519 public key.
type PeerKey [32]byte

// Policy represents a parsed and validated ACL policy.
type Policy struct {
	Version      int
	Default      DefaultAction
	Peers        map[string]PeerKey  // name -> Ed25519 public key
	Tags         map[string][]string // tag name -> list of peer names
	Rules        []Rule
	OutboundOnly []string // peer names that are outbound-only
	Warnings     []string // non-fatal warnings (e.g., unmatchable rules)
}

// ParsePolicy parses a TOML policy string and returns a validated Policy.
func ParsePolicy(src string) (*Policy, []string, error) {
	var raw rawPolicy
	md, err := toml.Decode(src, &raw)
	if err != nil {
		return nil, nil, fmt.Errorf("parse policy: %w", err)
	}

	// Check for undecoded keys (unknown fields)
	if len(md.Undecoded()) > 0 {
		var unknown []string
		for _, k := range md.Undecoded() {
			unknown = append(unknown, strings.Join(k, "."))
		}
		return nil, nil, fmt.Errorf("unknown policy fields: %s", strings.Join(unknown, ", "))
	}

	p, warnings, err := raw.validateAndCompile()
	if err != nil {
		return nil, warnings, err
	}
	return p, warnings, nil
}

// rawPolicy is the intermediate representation for TOML decoding.
type rawPolicy struct {
	Version      int                 `toml:"version"`
	Default      string              `toml:"default"`
	Peers        map[string]string   `toml:"peers"`
	Tags         map[string][]string `toml:"tags"`
	Rules        []rawRule           `toml:"rule"`
	OutboundOnly rawOutboundOnly     `toml:"outbound_only"`
}

type rawRule struct {
	From  string   `toml:"from"`
	To    string   `toml:"to"`
	Ports []string `toml:"ports"`
}

type rawOutboundOnly struct {
	Peers []string `toml:"peers"`
}

func (r *rawPolicy) validateAndCompile() (*Policy, []string, error) {
	var warnings []string

	// Validate version
	if r.Version <= 0 {
		return nil, warnings, errors.New("policy: version must be a positive integer")
	}

	// Validate default
	if r.Default == "" {
		return nil, warnings, errors.New("policy: default is required (allow or deny)")
	}
	defaultAction, err := ParseDefaultAction(r.Default)
	if err != nil {
		return nil, warnings, fmt.Errorf("policy: %w", err)
	}

	// Validate peers
	if len(r.Peers) == 0 {
		return nil, warnings, errors.New("policy: at least one peer is required")
	}
	peers := make(map[string]PeerKey, len(r.Peers))
	for name, keyStr := range r.Peers {
		if name == "" {
			return nil, warnings, errors.New("policy: peer name cannot be empty")
		}
		if _, exists := peers[name]; exists {
			return nil, warnings, fmt.Errorf("policy: duplicate peer name: %q", name)
		}
		key, err := parsePeerKey(keyStr)
		if err != nil {
			return nil, warnings, fmt.Errorf("policy: peer %q: %w", name, err)
		}
		peers[name] = key
	}

	// Validate tags
	tags := make(map[string][]string, len(r.Tags))
	for tagName, peerNames := range r.Tags {
		if tagName == "" {
			return nil, warnings, errors.New("policy: tag name cannot be empty")
		}
		if _, exists := tags[tagName]; exists {
			return nil, warnings, fmt.Errorf("policy: duplicate tag name: %q", tagName)
		}
		if len(peerNames) == 0 {
			return nil, warnings, fmt.Errorf("policy: tag %q must reference at least one peer", tagName)
		}
		for _, pn := range peerNames {
			if _, ok := peers[pn]; !ok {
				return nil, warnings, fmt.Errorf("policy: tag %q references unknown peer %q", tagName, pn)
			}
		}
		tags[tagName] = peerNames
	}

	// Validate rules
	rules := make([]Rule, 0, len(r.Rules))
	for i, rr := range r.Rules {
		if rr.From == "" || rr.To == "" {
			return nil, warnings, fmt.Errorf("policy: rule %d: from and to are required", i)
		}
		if len(rr.Ports) == 0 {
			return nil, warnings, fmt.Errorf("policy: rule %d: at least one port is required", i)
		}

		// Validate from/to subjects
		if err := validateSubject(rr.From, peers, tags); err != nil {
			return nil, warnings, fmt.Errorf("policy: rule %d: from: %w", i, err)
		}
		if err := validateSubject(rr.To, peers, tags); err != nil {
			return nil, warnings, fmt.Errorf("policy: rule %d: to: %w", i, err)
		}

		// Parse ports
		ports := make([]PortRange, 0, len(rr.Ports))
		for _, portStr := range rr.Ports {
			pr, err := parsePortRange(portStr)
			if err != nil {
				return nil, warnings, fmt.Errorf("policy: rule %d: port %q: %w", i, portStr, err)
			}
			ports = append(ports, pr)
		}

		rules = append(rules, Rule{
			From:  rr.From,
			To:    rr.To,
			Ports: ports,
		})
	}

	// Validate outbound_only peers
	outboundOnly := make([]string, 0, len(r.OutboundOnly.Peers))
	for _, name := range r.OutboundOnly.Peers {
		if _, ok := peers[name]; !ok {
			return nil, warnings, fmt.Errorf("policy: outbound_only.peers: unknown peer %q", name)
		}
		outboundOnly = append(outboundOnly, name)
	}

	// Check for unmatchable rules (warnings)
	for i, rule := range rules {
		if isUnmatchable(rule, peers, tags) {
			warnings = append(warnings, fmt.Sprintf("policy: rule %d: can never match (from=%q to=%q)", i, rule.From, rule.To))
		}
	}

	return &Policy{
		Version:      r.Version,
		Default:      defaultAction,
		Peers:        peers,
		Tags:         tags,
		Rules:        rules,
		OutboundOnly: outboundOnly,
		Warnings:     warnings,
	}, warnings, nil
}

func validateSubject(subject string, peers map[string]PeerKey, tags map[string][]string) error {
	if subject == "*" {
		return nil
	}
	if strings.HasPrefix(subject, "tag:") {
		tagName := subject[4:]
		if tagName == "" {
			return errors.New("empty tag name")
		}
		if _, ok := tags[tagName]; !ok {
			return fmt.Errorf("unknown tag: %q", tagName)
		}
		return nil
	}
	// Peer name
	if _, ok := peers[subject]; !ok {
		return fmt.Errorf("unknown peer: %q", subject)
	}
	return nil
}

func parsePeerKey(s string) (PeerKey, error) {
	var key PeerKey
	const prefix = "ed25519:"
	if !strings.HasPrefix(s, prefix) {
		return key, errors.New("peer key must start with \"ed25519:\"")
	}
	encoded := s[len(prefix):]

	// Try hex first (hex strings are also valid base64, so check hex first)
	if decoded, err := hex.DecodeString(encoded); err == nil {
		if len(decoded) != 32 {
			return key, fmt.Errorf("ed25519 key must be 32 bytes, got %d", len(decoded))
		}
		copy(key[:], decoded)
		return key, nil
	}

	// Try base64
	if decoded, err := base64.StdEncoding.DecodeString(encoded); err == nil {
		if len(decoded) != 32 {
			return key, fmt.Errorf("ed25519 key must be 32 bytes, got %d", len(decoded))
		}
		copy(key[:], decoded)
		return key, nil
	}

	return key, errors.New("peer key must be base64 or hex encoded 32-byte ed25519 public key")
}

func parsePortRange(s string) (PortRange, error) {
	var pr PortRange

	if s == "*" {
		return PortRange{Proto: ProtoAny, Start: 0, End: 65535}, nil
	}
	if strings.EqualFold(s, "icmp") {
		return PortRange{Proto: ProtoICMP, Start: 0, End: 65535}, nil
	}

	// Format: proto/port or proto/start-end
	parts := strings.Split(s, "/")
	if len(parts) != 2 {
		return pr, fmt.Errorf("invalid port format: %q (expected proto/port or proto/start-end)", s)
	}

	protoStr := strings.ToLower(parts[0])
	portStr := parts[1]

	switch protoStr {
	case "tcp":
		pr.Proto = ProtoTCP
	case "udp":
		pr.Proto = ProtoUDP
	case "icmp":
		pr.Proto = ProtoICMP
		return PortRange{Proto: ProtoICMP, Start: 0, End: 65535}, nil
	default:
		return pr, fmt.Errorf("unknown protocol: %q", protoStr)
	}

	// Parse port or range
	if strings.Contains(portStr, "-") {
		rangeParts := strings.Split(portStr, "-")
		if len(rangeParts) != 2 {
			return pr, fmt.Errorf("invalid port range: %q", portStr)
		}
		start, err := parsePort(rangeParts[0])
		if err != nil {
			return pr, fmt.Errorf("invalid start port: %w", err)
		}
		end, err := parsePort(rangeParts[1])
		if err != nil {
			return pr, fmt.Errorf("invalid end port: %w", err)
		}
		if start > end {
			return pr, fmt.Errorf("start port %d > end port %d", start, end)
		}
		pr.Start = start
		pr.End = end
	} else {
		port, err := parsePort(portStr)
		if err != nil {
			return pr, err
		}
		pr.Start = port
		pr.End = port
	}

	return pr, nil
}

func parsePort(s string) (uint16, error) {
	var port uint64
	_, err := fmt.Sscanf(s, "%d", &port)
	if err != nil {
		return 0, fmt.Errorf("invalid port number: %q", s)
	}
	if port > 65535 {
		return 0, fmt.Errorf("port %d exceeds maximum 65535", port)
	}
	return uint16(port), nil
}

func isUnmatchable(rule Rule, peers map[string]PeerKey, tags map[string][]string) bool {
	fromSet := resolveSubject(rule.From, peers, tags)
	toSet := resolveSubject(rule.To, peers, tags)

	if len(fromSet) == 1 && len(toSet) == 1 {
		for k := range fromSet {
			if _, ok := toSet[k]; ok {
				return true
			}
		}
	}
	return false
}

func resolveSubject(subject string, peers map[string]PeerKey, tags map[string][]string) map[[32]byte]struct{} {
	result := make(map[[32]byte]struct{})
	if subject == "*" {
		for _, k := range peers {
			result[k] = struct{}{}
		}
		return result
	}
	if strings.HasPrefix(subject, "tag:") {
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
