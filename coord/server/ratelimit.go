// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"net"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// IPRateLimiter limits requests per source IP using a token-bucket algorithm.
// Stale entries are pruned every 10 minutes so the map stays bounded.
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
// then ratePerSec requests per second, tracked per source IP.
func NewIPRateLimiter(ratePerSec, burst float64) *IPRateLimiter {
	rl := &IPRateLimiter{
		entries: make(map[string]*ipBucket),
		rate:    ratePerSec,
		burst:   burst,
	}
	go rl.gc()
	return rl
}

// Allow returns true when the IP is within its rate limit.
func (rl *IPRateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	b, ok := rl.entries[ip]
	if !ok {
		rl.entries[ip] = &ipBucket{tokens: rl.burst - 1, lastFill: now}
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
