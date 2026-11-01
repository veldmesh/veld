// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package acl

import (
	"sync"
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
	evictList *evictList // doubly-linked list for LRU eviction
	evictMu   sync.Mutex // protects evictList
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

// hashFlowKey computes a hash for a flow key.
func hashFlowKey(key FlowKey) uint64 {
	h := uint64(key.Proto) << 48
	h |= uint64(key.SrcPort) << 32
	h |= uint64(key.DstPort) << 16
	if key.IPv6 {
		h |= 1
	}
	// Mix in IP addresses (simplified hash)
	for i := 0; i < 16; i += 4 {
		h ^= uint64(binaryBigEndian(key.SrcIP[i:i+4])) * 0x9e3779b97f4a7c15
		h ^= uint64(binaryBigEndian(key.DstIP[i:i+4])) * 0x9e3779b97f4a7c15
	}
	return h
}

func binaryBigEndian(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// Lookup looks up a flow by its key. Returns the entry and whether it was the reply direction.
// If createIfMissing is true, creates a new entry with the given state.
func (ft *FlowTable) Lookup(f Flow, createIfMissing bool, initialState FlowState) (*FlowEntry, bool, bool) {
	key, isReply := NormalizeFlowKey(f)
	shardIdx := hashFlowKey(key) & uint64(ft.shardMask)
	shard := ft.shards[shardIdx]

	shard.mu.Lock()
	defer shard.mu.Unlock()

	entry, ok := shard.flows[key]
	if ok {
		entry.LastSeen = time.Now()
		if entry.State == FlowStateNew && initialState == FlowStateEstablished {
			entry.State = FlowStateEstablished
		}
		ft.moveToFront(entry)
		return entry, isReply, false
	}

	if !createIfMissing {
		return nil, isReply, false
	}

	// Check if we need to evict (global limit)
	if ft.totalFlowsLocked() >= ft.config.MaxFlows {
		ft.evictGlobalOldestLocked()
	}

	now := time.Now()
	entry = &FlowEntry{
		Flow:       f,
		Created:    now,
		LastSeen:   now,
		State:      initialState,
		IsReplyDir: isReply,
	}
	shard.flows[key] = entry
	ft.addToFront(entry)
	return entry, isReply, true
}

// totalFlowsLocked returns the total number of flows across all shards.
// Caller must hold at least one shard lock (to avoid deadlock, we use a simple approach).
func (ft *FlowTable) totalFlowsLocked() int {
	count := 0
	for _, shard := range ft.shards {
		// Try to lock, skip if busy (approximate count is fine for eviction decision)
		if shard.mu.TryLock() {
			count += len(shard.flows)
			shard.mu.Unlock()
		}
	}
	return count
}

// evictGlobalOldestLocked evicts the globally oldest flow from the eviction list.
// Caller must hold a shard lock.
func (ft *FlowTable) evictGlobalOldestLocked() {
	// Walk the eviction list from tail (oldest) to find an entry we can evict
	ft.evictMu.Lock()
	defer ft.evictMu.Unlock()

	for e := ft.evictList.tail; e != nil; e = e.prev {
		key, _ := NormalizeFlowKey(e.Flow)
		shardIdx := hashFlowKey(key) & uint64(ft.shardMask)
		targetShard := ft.shards[shardIdx]

		// Try to lock the target shard
		if targetShard.mu.TryLock() {
			// Double-check the entry still exists
			if _, ok := targetShard.flows[key]; ok {
				delete(targetShard.flows, key)
				ft.removeFromListLocked(e)
			}
			targetShard.mu.Unlock()
			return
		}
	}
}

// moveToFront moves an entry to the front of the eviction list (most recently used).
func (ft *FlowTable) moveToFront(entry *FlowEntry) {
	ft.removeFromList(entry)
	ft.addToFront(entry)
}

// addToFront adds an entry to the front of the eviction list.
func (ft *FlowTable) addToFront(entry *FlowEntry) {
	ft.evictMu.Lock()
	defer ft.evictMu.Unlock()
	ft.addToFrontLocked(entry)
}

// addToFrontLocked adds an entry to the front of the eviction list.
// Caller must hold ft.evictMu.
func (ft *FlowTable) addToFrontLocked(entry *FlowEntry) {
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

// removeFromList removes an entry from the eviction list.
func (ft *FlowTable) removeFromList(entry *FlowEntry) {
	ft.evictMu.Lock()
	defer ft.evictMu.Unlock()
	ft.removeFromListLocked(entry)
}

// removeFromListLocked removes an entry from the eviction list.
// Caller must hold ft.evictMu.
func (ft *FlowTable) removeFromListLocked(entry *FlowEntry) {
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

// UpdateState updates the state of a flow entry.
func (ft *FlowTable) UpdateState(f Flow, state FlowState) bool {
	key, _ := NormalizeFlowKey(f)
	shardIdx := hashFlowKey(key) & uint64(ft.shardMask)
	shard := ft.shards[shardIdx]

	shard.mu.Lock()
	defer shard.mu.Unlock()

	entry, ok := shard.flows[key]
	if !ok {
		return false
	}
	entry.State = state
	entry.LastSeen = time.Now()
	ft.moveToFront(entry)
	return true
}

// RemoveFlow removes a flow entry by its normalized key.
// Returns true if the flow was found and removed.
func (ft *FlowTable) RemoveFlow(key FlowKey) bool {
	shardIdx := hashFlowKey(key) & uint64(ft.shardMask)
	shard := ft.shards[shardIdx]

	shard.mu.Lock()
	defer shard.mu.Unlock()

	entry, ok := shard.flows[key]
	if !ok {
		return false
	}
	delete(shard.flows, key)
	ft.removeFromList(entry)
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
				ft.removeFromList(entry)
				count++
			}
		}
		shard.mu.Unlock()
	}
	return count
}

// Len returns the total number of flows in the table.
func (ft *FlowTable) Len() int {
	count := 0
	for _, shard := range ft.shards {
		shard.mu.Lock()
		count += len(shard.flows)
		shard.mu.Unlock()
	}
	return count
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
