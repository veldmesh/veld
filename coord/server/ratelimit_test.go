// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"net/netip"
	"testing"
	"time"
)

func TestNormalizeIP_IPv4(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"1.2.3.4", "1.2.3.4"},
		{"192.168.1.1", "192.168.1.1"},
		{"10.0.0.1", "10.0.0.1"},
	}
	for _, tc := range tests {
		result := normalizeIP(tc.input)
		if result != tc.expected {
			t.Errorf("normalizeIP(%q) = %q, want %q", tc.input, result, tc.expected)
		}
	}
}

func TestNormalizeIP_IPv6(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"2001:db8::1", "2001:db8::/64"},
		{"2001:db8::ffff:ffff:ffff:ffff", "2001:db8::/64"},
		{"2001:db8:1::1", "2001:db8:1::/64"},
		{"fe80::1", "fe80::/64"},
	}
	for _, tc := range tests {
		result := normalizeIP(tc.input)
		if result != tc.expected {
			t.Errorf("normalizeIP(%q) = %q, want %q", tc.input, result, tc.expected)
		}
	}
}

func TestNormalizeIP_Invalid(t *testing.T) {
	result := normalizeIP("not-an-ip")
	if result != "not-an-ip" {
		t.Errorf("normalizeIP(%q) = %q, want %q", "not-an-ip", result, "not-an-ip")
	}
}

func TestIPRateLimiter_Basic(t *testing.T) {
	rl := NewIPRateLimiter(10, 5)

	for i := 0; i < 5; i++ {
		if !rl.Allow("1.2.3.4") {
			t.Errorf("request %d should be allowed (burst)", i+1)
		}
	}

	if rl.Allow("1.2.3.4") {
		t.Error("request 6 should be denied (burst exhausted)")
	}
}

func TestIPRateLimiter_Refill(t *testing.T) {
	rl := NewIPRateLimiter(100, 2)

	if !rl.Allow("1.2.3.4") {
		t.Fatal("first request should be allowed")
	}
	if !rl.Allow("1.2.3.4") {
		t.Fatal("second request should be allowed")
	}
	if rl.Allow("1.2.3.4") {
		t.Fatal("third request should be denied")
	}

	time.Sleep(15 * time.Millisecond)

	if !rl.Allow("1.2.3.4") {
		t.Error("request after refill should be allowed")
	}
}

func TestIPRateLimiter_IPv6Aggregation(t *testing.T) {
	rl := NewIPRateLimiter(10, 2)

	if !rl.Allow("2001:db8::1") {
		t.Fatal("first IPv6 request should be allowed")
	}
	if !rl.Allow("2001:db8::2") {
		t.Fatal("second IPv6 request in same /64 should be allowed (same bucket)")
	}
	if rl.Allow("2001:db8::3") {
		t.Error("third IPv6 request in same /64 should be denied (shared bucket)")
	}

	if !rl.Allow("2001:db8:1::1") {
		t.Error("IPv6 in different /64 should have separate bucket")
	}
}

func TestIPRateLimiter_EvictOldest(t *testing.T) {
	rl := &IPRateLimiter{
		entries: make(map[string]*ipBucket),
		rate:    1,
		burst:   10,
	}
	now := time.Now()

	rl.entries["1.2.3.1"] = &ipBucket{tokens: 5, lastFill: now.Add(-10 * time.Second)}
	rl.entries["1.2.3.2"] = &ipBucket{tokens: 5, lastFill: now.Add(-5 * time.Second)}
	rl.entries["1.2.3.3"] = &ipBucket{tokens: 5, lastFill: now}

	rl.evictOldest(now)

	if _, ok := rl.entries["1.2.3.1"]; ok {
		t.Error("oldest entry should have been evicted")
	}
	if _, ok := rl.entries["1.2.3.2"]; !ok {
		t.Error("1.2.3.2 should not have been evicted")
	}
	if _, ok := rl.entries["1.2.3.3"]; !ok {
		t.Error("1.2.3.3 should not have been evicted")
	}
}

func TestIPRateLimiter_CapRespected(t *testing.T) {
	rl := &IPRateLimiter{
		entries: make(map[string]*ipBucket),
		rate:    1000,
		burst:   1,
	}

	const smallCap = 10
	now := time.Now()

	for i := 0; i < smallCap; i++ {
		key := netip.AddrFrom4([4]byte{192, 168, byte(i >> 8), byte(i)}).String()
		rl.entries[key] = &ipBucket{tokens: 0, lastFill: now}
	}

	if len(rl.entries) >= smallCap {
		rl.evictOldest(now)
	}
	rl.entries["192.168.255.255"] = &ipBucket{tokens: 0, lastFill: now}

	if len(rl.entries) > smallCap {
		t.Errorf("map size %d exceeds cap %d", len(rl.entries), smallCap)
	}
}
