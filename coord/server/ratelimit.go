// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

const (
	// maxRateLimiterEntries caps the number of tracked IPs to prevent unbounded growth.
	maxRateLimiterEntries = 10000
)

// IPRateLimiter limits requests per source IP using a token-bucket algorithm.
// IPv6 addresses are aggregated by /64 prefix. Stale entries are pruned every
// 10 minutes and the map size is capped at maxRateLimiterEntries.
type IPRateLimiter struct {
	mu      sync.Mutex
	entries map[string]*ipBucket
	rate    float64 // tokens added per second
	burst   float64 // bucket capacity
}

type ipBucket struct {
	tokens   float64
	lastFill time.Time
}

// NewIPRateLimiter creates a limiter allowing burst requests immediately and
// then ratePerSec requests per second, tracked per source IP (with IPv6 /64 aggregation).
func NewIPRateLimiter(ratePerSec, burst float64) *IPRateLimiter {
	rl := &IPRateLimiter{
		entries: make(map[string]*ipBucket),
		rate:    ratePerSec,
		burst:   burst,
	}
	go rl.gc()
	return rl
}

// normalizeIP aggregates IPv6 addresses to their /64 prefix.
// IPv4 addresses are used as-is.
func normalizeIP(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ip // fallback: use as-is
	}
	if addr.Is6() {
		// Mask to /64 by creating a /64 prefix and getting its address.
		prefix := netip.PrefixFrom(addr, 64)
		return prefix.Masked().String()
	}
	return addr.String()
}

// Allow returns true when the IP is within its rate limit.
func (rl *IPRateLimiter) Allow(ip string) bool {
	normIP := normalizeIP(ip)
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	b, ok := rl.entries[normIP]
	if !ok {
		// Cap the map size: if at capacity, evict a random stale entry.
		// We use a simple strategy: if at capacity, clear 10% of oldest entries.
		if len(rl.entries) >= maxRateLimiterEntries {
			rl.evictOldest(now, maxRateLimiterEntries/10)
		}
		rl.entries[normIP] = &ipBucket{tokens: rl.burst - 1, lastFill: now}
		return true
	}
	b.tokens += now.Sub(b.lastFill).Seconds() * rl.rate
	b.lastFill = now
	if b.tokens > rl.burst {
		b.tokens = rl.burst
	}
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// evictOldest removes up to n oldest entries (called with lock held).
func (rl *IPRateLimiter) evictOldest(now time.Time, n int) {
	if n <= 0 || len(rl.entries) == 0 {
		return
	}
	// Find the n oldest entries by lastFill time.
	type entry struct {
		key string
		t   time.Time
	}
	oldest := make([]entry, 0, len(rl.entries))
	for k, b := range rl.entries {
		oldest = append(oldest, entry{key: k, t: b.lastFill})
	}
	// Sort by time (oldest first)
	sort.Slice(oldest, func(i, j int) bool {
		return oldest[i].t.Before(oldest[j].t)
	})
	// Remove up to n oldest
	for i := 0; i < n && i < len(oldest); i++ {
		delete(rl.entries, oldest[i].key)
	}
}

func (rl *IPRateLimiter) gc() {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for range t.C {
		cutoff := time.Now().Add(-15 * time.Minute)
		rl.mu.Lock()
		for ip, b := range rl.entries {
			if b.lastFill.Before(cutoff) {
				delete(rl.entries, ip)
			}
		}
		// Hard cap: if still over limit after GC, evict oldest.
		if len(rl.entries) > maxRateLimiterEntries {
			rl.evictOldest(time.Now(), len(rl.entries)-maxRateLimiterEntries)
		}
		rl.mu.Unlock()
	}
}

func peerIP(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(p.Addr.String())
	if err != nil {
		return p.Addr.String()
	}
	return host
}

// UnaryRateLimitInterceptor rejects unary RPCs from IPs that exceed rl's rate.
func UnaryRateLimitInterceptor(rl *IPRateLimiter) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if !rl.Allow(peerIP(ctx)) {
			return nil, status.Errorf(codes.ResourceExhausted, "rate limit exceeded")
		}
		return handler(ctx, req)
	}
}

// StreamRateLimitInterceptor rejects new streams from IPs that exceed rl's rate.
func StreamRateLimitInterceptor(rl *IPRateLimiter) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if !rl.Allow(peerIP(ss.Context())) {
			return status.Errorf(codes.ResourceExhausted, "rate limit exceeded")
		}
		return handler(srv, ss)
	}
}