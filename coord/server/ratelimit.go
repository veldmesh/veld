// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

const (
	maxRateLimiterEntries = 10000
)

type IPRateLimiter struct {
	mu      sync.Mutex
	entries map[string]*ipBucket
	rate    float64
	burst   float64
	gcStop  chan struct{}
}

type ipBucket struct {
	tokens   float64
	lastFill time.Time
}

func NewIPRateLimiter(ratePerSec, burst float64) *IPRateLimiter {
	rl := &IPRateLimiter{
		entries: make(map[string]*ipBucket),
		rate:    ratePerSec,
		burst:   burst,
		gcStop:  make(chan struct{}),
	}
	go rl.gc()
	return rl
}

func (rl *IPRateLimiter) Stop() {
	close(rl.gcStop)
}

func normalizeIP(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	if addr.Is6() {
		prefix := netip.PrefixFrom(addr, 64)
		return prefix.Masked().String()
	}
	return addr.String()
}

func (rl *IPRateLimiter) Allow(ip string) bool {
	normIP := normalizeIP(ip)
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	b, ok := rl.entries[normIP]
	if !ok {
		if len(rl.entries) >= maxRateLimiterEntries {
			rl.evictOldest(now)
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

func (rl *IPRateLimiter) evictOldest(now time.Time) {
	if len(rl.entries) == 0 {
		return
	}
	var oldestKey string
	var oldestTime time.Time
	first := true
	for k, b := range rl.entries {
		if first || b.lastFill.Before(oldestTime) {
			oldestKey = k
			oldestTime = b.lastFill
			first = false
		}
	}
	if oldestKey != "" {
		delete(rl.entries, oldestKey)
	}
}

func (rl *IPRateLimiter) gc() {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			cutoff := time.Now().Add(-15 * time.Minute)
			rl.mu.Lock()
			for ip, b := range rl.entries {
				if b.lastFill.Before(cutoff) {
					delete(rl.entries, ip)
				}
			}
			for len(rl.entries) > maxRateLimiterEntries {
				rl.evictOldest(time.Now())
			}
			rl.mu.Unlock()
		case <-rl.gcStop:
			return
		}
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

func UnaryRateLimitInterceptor(rl *IPRateLimiter) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if !rl.Allow(peerIP(ctx)) {
			return nil, status.Errorf(codes.ResourceExhausted, "rate limit exceeded")
		}
		return handler(ctx, req)
	}
}

func StreamRateLimitInterceptor(rl *IPRateLimiter) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if !rl.Allow(peerIP(ss.Context())) {
			return status.Errorf(codes.ResourceExhausted, "rate limit exceeded")
		}
		return handler(srv, ss)
	}
}
