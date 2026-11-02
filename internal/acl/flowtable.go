// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package acl

import (
	"hash/maphash"
	"sync"
	"sync/atomic"
	"time"
)

// FlowEntry represents an entry in the flow table.
type FlowEntry struct {
	Flow
	Created    time.Time
	LastSeen   time.Time
	State      FlowState
	IsReplyDir bool // true if this entry represents the reply direction

	// Eviction list pointers (used by FlowTable)
	next *FlowEntry
	prev *FlowEntry
}

// FlowState represents the state of a flow.
type FlowState uint8

const (
	FlowStateNew FlowState = iota
	FlowStateEstablished
	FlowStateClosing
	FlowStateClosed
)

// FlowTableConfig holds configuration for the flow table.
type FlowTableConfig struct {
	MaxFlows        int           // maximum number of flows (default 16384)
	TCPIdleTimeout  time.Duration // TCP idle timeout (default 5 min)
	UDPIdleTimeout  time.Duration // UDP idle timeout (default 60 s)
	ICMPIdleTimeout time.Duration // ICMP idle timeout (default 30 s)
}

// DefaultFlowTableConfig returns the default flow table configuration.
func DefaultFlowTableConfig() FlowTableConfig {
	return FlowTableConfig{
		MaxFlows:        16384,
		TCPIdleTimeout:  5 * time.Minute,
		UDPIdleTimeout:  60 * time.Second,
		ICMPIdleTimeout: 30 * time.Second,
	}
}

// FlowTable is a thread-safe flow table for connection tracking.
// It uses a sharded map for scalability and a time-ordered list for LRU eviction.
type FlowTable struct {
	shards    []*flowShard
	shardMask int
	config    FlowTableConfig
	evictList *evictList   // doubly-linked list for LRU eviction
	evictMu   sync.Mutex   // protects evictList
	flowCount atomic.Int64 // atomic counter for total flows
	hashSeed  maphash.Seed // random seed for hashFlowKey to prevent adversarial shard targeting
}

// flowShard is a single shard of the flow table.
type flowShard struct {
	mu    sync.Mutex
	flows map[FlowKey]*FlowEntry
}

// evictList is a doubly-linked list for LRU eviction.
type evictList struct {
	head, tail *FlowEntry
}

// FlowKey is the normalized flow key (bidirectional).
type FlowKey struct {
	SrcIP   [16]byte
	DstIP   [16]byte
	SrcPort uint16
	DstPort uint16
	Proto   Proto
	IPv6    bool
}

// NewFlowTable creates a new flow table with the given configuration.
func NewFlowTable(config FlowTableConfig) *FlowTable {
	if config.MaxFlows <= 0 {
		config.MaxFlows = 16384
	}
	if config.TCPIdleTimeout <= 0 {
		config.TCPIdleTimeout = 5 * time.Minute
	}
	if config.UDPIdleTimeout <= 0 {
		config.UDPIdleTimeout = 60 * time.Second
	}
	if config.ICMPIdleTimeout <= 0 {
		config.ICMPIdleTimeout = 30 * time.Second
	}

	// Use power of 2 shards for fast masking
	numShards := 64
	ft := &FlowTable{
		shards:    make([]*flowShard, numShards),
		shardMask: numShards - 1,
		config:    config,
		evictList: &evictList{},
		hashSeed:  maphash.MakeSeed(),
	}
	for i := range ft.shards {
		ft.shards[i] = &flowShard{
			flows: make(map[FlowKey]*FlowEntry),
		}
	}
	return ft
}

// NormalizeFlowKey normalizes a flow key so that both directions of a connection
// map to the same key. The "forward" direction is the one with the lower IP address,
// or if equal, the lower port.
func NormalizeFlowKey(f Flow) (FlowKey, bool) {
	var key FlowKey
	key.Proto = f.Proto
	key.IPv6 = f.IPv6

	// Compare IPs to determine canonical direction
	cmp := compareIPs(f.SrcIP, f.DstIP, f.IPv6)
	if cmp < 0 || (cmp == 0 && f.SrcPort <= f.DstPort) {
		// Forward direction
		key.SrcIP = f.SrcIP
		key.DstIP = f.DstIP
		key.SrcPort = f.SrcPort
		key.DstPort = f.DstPort
		return key, false
	} else {
		// Reverse direction
		key.SrcIP = f.DstIP
		key.DstIP = f.SrcIP
		key.SrcPort = f.DstPort
		key.DstPort = f.SrcPort
		return key, true
	}
}

// compareIPs compares two IP addresses. Returns -1 if a < b, 0 if equal, 1 if a > b.
func compareIPs(a, b [16]byte, ipv6 bool) int {
	if ipv6 {
		for i := 0; i < 16; i++ {
			if a[i] < b[i] {
				return -1
			}
			if a[i] > b[i] {
				return 1
			}
		}
		return 0
	}
	// IPv4: compare last 4 bytes
	for i := 12; i < 16; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

// hashFlowKey computes a hash for a flow key using maphash.
// This ensures all key fields (IPs, ports, proto) affect the low bits used for shard selection.
func (ft *FlowTable) hashFlowKey(key FlowKey) uint64 {
	var h maphash.Hash
	h.SetSeed(ft.hashSeed)
	// Write all key fields - maphash handles the mixing
	h.Write(key.SrcIP[:])
	h.Write(key.DstIP[:])
	h.Write([]byte{byte(key.Proto)})
	h.Write([]byte{byte(key.SrcPort >> 8), byte(key.SrcPort)})
	h.Write([]byte{byte(key.DstPort >> 8), byte(key.DstPort)})
	if key.IPv6 {
		h.Write([]byte{1})
	} else {
		h.Write([]byte{0})
	}
	return h.Sum64()
}

// isEntryExpired checks if a flow entry has exceeded its idle timeout.
// Caller must hold the shard lock.
func (ft *FlowTable) isEntryExpired(entry *FlowEntry, now time.Time) bool {
	timeout := ft.GetTimeout(entry.Proto)
	return now.Sub(entry.LastSeen) > timeout
}

// unlinkEntry removes an entry from the eviction list.
// Caller must hold ft.evictMu.
func (ft *FlowTable) unlinkEntry(entry *FlowEntry) {
	if entry.prev != nil {
		entry.prev.next = entry.next
	} else {
		ft.evictList.head = entry.next
	}
	if entry.next != nil {
		entry.next.prev = entry.prev
	} else {
		ft.evictList.tail = entry.prev
	}
	entry.prev = nil
	entry.next = nil
}

// linkEntryFront adds an entry to the front of the eviction list.
// Caller must hold ft.evictMu.
func (ft *FlowTable) linkEntryFront(entry *FlowEntry) {
	entry.next = ft.evictList.head
	entry.prev = nil
	if ft.evictList.head != nil {
		ft.evictList.head.prev = entry
	}
	ft.evictList.head = entry
	if ft.evictList.tail == nil {
		ft.evictList.tail = entry
	}
}

// linkEntryBack adds an entry to the back of the eviction list.
// Caller must hold ft.evictMu.
func (ft *FlowTable) linkEntryBack(entry *FlowEntry) {
	entry.prev = ft.evictList.tail
	entry.next = nil
	if ft.evictList.tail != nil {
		ft.evictList.tail.next = entry
	}
	ft.evictList.tail = entry
	if ft.evictList.head == nil {
		ft.evictList.head = entry
	}
}

// moveToFrontLocked moves an entry to the front of the eviction list.
// Caller must hold ft.evictMu.
func (ft *FlowTable) moveToFrontLocked(entry *FlowEntry) {
	ft.unlinkEntry(entry)
	ft.linkEntryFront(entry)
}

// popOldestEntry removes and returns the oldest entry from the eviction list.
// Caller must hold ft.evictMu.
// Returns nil if list is empty.
func (ft *FlowTable) popOldestEntry() *FlowEntry {
	e := ft.evictList.tail
	if e == nil {
		return nil
	}
	ft.unlinkEntry(e)
	return e
}

// Lookup looks up a flow by its key. Returns the entry and whether it was the reply direction.
// If createIfMissing is true, creates a new entry with the given state.
// Expired entries are treated as missing (deleted and nil returned).
func (ft *FlowTable) Lookup(f Flow, createIfMissing bool, initialState FlowState) (*FlowEntry, bool, bool) {
	key, isReply := NormalizeFlowKey(f)
	shardIdx := ft.hashFlowKey(key) & uint64(ft.shardMask)
	shard := ft.shards[shardIdx]

	shard.mu.Lock()
	defer shard.mu.Unlock()

	entry, ok := shard.flows[key]
	now := time.Now()
	if ok {
		// Check if entry is expired
		if ft.isEntryExpired(entry, now) {
			// Treat expired entry as missing - delete it
			delete(shard.flows, key)
			// Remove from eviction list
			ft.evictMu.Lock()
			ft.unlinkEntry(entry)
			ft.evictMu.Unlock()
			ft.flowCount.Add(-1)
		} else {
			entry.LastSeen = now
			if entry.State == FlowStateNew && initialState == FlowStateEstablished {
				entry.State = FlowStateEstablished
			}
			// Move to front of LRU list
			ft.evictMu.Lock()
			ft.moveToFrontLocked(entry)
			ft.evictMu.Unlock()
			return entry, isReply, false
		}
	}

	if !createIfMissing {
		return nil, isReply, false
	}

	// Check if we need to evict (global limit)
	for ft.flowCount.Load() >= int64(ft.config.MaxFlows) {
		ft.evictOneLocked(int(shardIdx))
	}

	entry = &FlowEntry{
		Flow:       f,
		Created:    now,
		LastSeen:   now,
		State:      initialState,
		IsReplyDir: isReply,
	}
	shard.flows[key] = entry
	// Add to front of LRU list
	ft.evictMu.Lock()
	ft.linkEntryFront(entry)
	ft.evictMu.Unlock()
	ft.flowCount.Add(1)
	return entry, isReply, true
}

// evictOneLocked evicts a single oldest flow.
// Called with shard lock held for callerShardIdx.
func (ft *FlowTable) evictOneLocked(callerShardIdx int) {
	const maxAttempts = 8
	for attempts := 0; attempts < maxAttempts; attempts++ {
		// Pop the oldest entry from the eviction list
		ft.evictMu.Lock()
		e := ft.popOldestEntry()
		ft.evictMu.Unlock()

		if e == nil {
			return
		}

		// Try to remove the entry from its shard
		key, _ := NormalizeFlowKey(e.Flow)
		shardIdx := ft.hashFlowKey(key) & uint64(ft.shardMask)
		targetShard := ft.shards[shardIdx]

		// If victim is in the same shard as caller, we already hold the lock
		if int(shardIdx) == callerShardIdx {
			if _, ok := targetShard.flows[key]; ok {
				delete(targetShard.flows, key)
				ft.flowCount.Add(-1)
			}
			return // Successfully evicted one entry
		}

		// TryLock for other shards
		if targetShard.mu.TryLock() {
			if _, ok := targetShard.flows[key]; ok {
				delete(targetShard.flows, key)
				ft.flowCount.Add(-1)
			}
			targetShard.mu.Unlock()
			return // Successfully evicted one entry
		}

		// Could not lock target shard (contended), put victim back at TAIL to preserve LRU order
		ft.evictMu.Lock()
		ft.linkEntryBack(e)
		ft.evictMu.Unlock()
	}
	// After maxAttempts, give up and allow temporary overshoot of at most one entry per concurrent inserter
}

// UpdateState updates the state of a flow entry.
func (ft *FlowTable) UpdateState(f Flow, state FlowState) bool {
	key, _ := NormalizeFlowKey(f)
	shardIdx := ft.hashFlowKey(key) & uint64(ft.shardMask)
	shard := ft.shards[shardIdx]

	shard.mu.Lock()
	defer shard.mu.Unlock()

	entry, ok := shard.flows[key]
	if !ok {
		return false
	}
	// Check if entry is expired
	now := time.Now()
	if ft.isEntryExpired(entry, now) {
		delete(shard.flows, key)
		ft.evictMu.Lock()
		ft.unlinkEntry(entry)
		ft.evictMu.Unlock()
		ft.flowCount.Add(-1)
		return false
	}
	entry.State = state
	entry.LastSeen = now
	// Move to front of LRU list
	ft.evictMu.Lock()
	ft.moveToFrontLocked(entry)
	ft.evictMu.Unlock()
	return true
}

// RemoveFlow removes a flow entry by its normalized key.
// Returns true if the flow was found and removed.
func (ft *FlowTable) RemoveFlow(key FlowKey) bool {
	shardIdx := ft.hashFlowKey(key) & uint64(ft.shardMask)
	shard := ft.shards[shardIdx]

	shard.mu.Lock()
	defer shard.mu.Unlock()

	entry, ok := shard.flows[key]
	if !ok {
		return false
	}
	delete(shard.flows, key)
	ft.evictMu.Lock()
	ft.unlinkEntry(entry)
	ft.evictMu.Unlock()
	ft.flowCount.Add(-1)
	return true
}

// GetTimeout returns the idle timeout for a flow based on its protocol.
func (ft *FlowTable) GetTimeout(proto Proto) time.Duration {
	switch proto {
	case ProtoTCP:
		return ft.config.TCPIdleTimeout
	case ProtoUDP:
		return ft.config.UDPIdleTimeout
	case ProtoICMP, ProtoICMPv6:
		return ft.config.ICMPIdleTimeout
	default:
		return ft.config.UDPIdleTimeout
	}
}

// ExpireOldFlows removes flows that have been idle longer than their timeout,
// and also removes flows in closed state (TCP FIN/RST).
// Returns the number of expired/removed flows.
func (ft *FlowTable) ExpireOldFlows() int {
	now := time.Now()
	count := 0
	for _, shard := range ft.shards {
		shard.mu.Lock()
		for key, entry := range shard.flows {
			timeout := ft.GetTimeout(entry.Proto)
			expired := now.Sub(entry.LastSeen) > timeout
			closed := entry.State == FlowStateClosed
			if expired || closed {
				delete(shard.flows, key)
				ft.evictMu.Lock()
				ft.unlinkEntry(entry)
				ft.evictMu.Unlock()
				ft.flowCount.Add(-1)
				count++
			}
		}
		shard.mu.Unlock()
	}
	return count
}

// Len returns the total number of flows in the table.
func (ft *FlowTable) Len() int {
	return int(ft.flowCount.Load())
}

// Stats returns statistics about the flow table.
func (ft *FlowTable) Stats() FlowTableStats {
	stats := FlowTableStats{}
	now := time.Now()
	for _, shard := range ft.shards {
		shard.mu.Lock()
		stats.TotalFlows += len(shard.flows)
		for _, entry := range shard.flows {
			if entry.State == FlowStateEstablished {
				stats.EstablishedFlows++
			}
			timeout := ft.GetTimeout(entry.Proto)
			if now.Sub(entry.LastSeen) > timeout {
				stats.ExpiredFlows++
			}
		}
		shard.mu.Unlock()
	}
	stats.MaxFlows = ft.config.MaxFlows
	return stats
}

// FlowTableStats holds statistics about the flow table.
type FlowTableStats struct {
	TotalFlows       int
	EstablishedFlows int
	ExpiredFlows     int
	MaxFlows         int
}
