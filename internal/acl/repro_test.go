// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package acl

import (
	"fmt"
	"sync"
	"testing"
)

// TestFlowTable_SameShardFlood reproduces the bug where evictOneLocked loops forever
// when all flows hash to the same shard as the caller.
func TestFlowTable_SameShardFlood(t *testing.T) {
	config := DefaultFlowTableConfig()
	config.MaxFlows = 64
	ft := NewFlowTable(config)

	// Find flows that hash to shard 0
	targetShard := 0
	flows := make([]Flow, 0)

	for i := 0; i < 10000 && len(flows) < 200; i++ {
		f := Flow{
			SrcIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: byte(i)},
			DstIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: 100},
			SrcPort: uint16(10000 + i),
			DstPort: 22,
			Proto:   ProtoTCP,
			IPv6:    false,
		}
		key, _ := NormalizeFlowKey(f)
		shardIdx := ft.hashFlowKey(key) & uint64(ft.shardMask)
		if int(shardIdx) == targetShard {
			flows = append(flows, f)
		}
	}

	fmt.Printf("Found %d flows for shard %d\n", len(flows), targetShard)

	if len(flows) < 65 {
		t.Skip("Could not find enough flows for same shard")
	}

	// Now insert them all - this should trigger eviction after 64
	for i, f := range flows {
		ft.Lookup(f, true, FlowStateNew)
		if i%50 == 0 {
			fmt.Printf("Inserted %d flows, table size: %d\n", i+1, ft.Len())
		}
	}
	fmt.Printf("Final table size: %d\n", ft.Len())

	// Should have evicted to stay within bound
	if ft.Len() > config.MaxFlows {
		t.Errorf("flow table exceeded max flows: got %d, max %d", ft.Len(), config.MaxFlows)
	}
}

// TestFlowTable_MillionDistinctFlows tests 1M distinct flows from one goroutine
func TestFlowTable_MillionDistinctFlows(t *testing.T) {
	config := DefaultFlowTableConfig()
	config.MaxFlows = 16384
	ft := NewFlowTable(config)

	// Add 1,000,000 distinct flows - encode i into 4 bytes of SrcIP
	for i := 0; i < 1_000_000; i++ {
		f := Flow{
			SrcIP:   [16]byte{12: byte(i >> 24), 13: byte(i >> 16), 14: byte(i >> 8), 15: byte(i)},
			DstIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: 100},
			SrcPort: uint16(i),
			DstPort: 22,
			Proto:   ProtoTCP,
			IPv6:    false,
		}
		ft.Lookup(f, true, FlowStateNew)
	}

	// Should have evicted to stay within bound
	if ft.Len() > config.MaxFlows {
		t.Errorf("flow table exceeded max flows: got %d, max %d", ft.Len(), config.MaxFlows)
	}
	if ft.Len() < config.MaxFlows/2 {
		t.Errorf("flow table too empty: got %d, max %d", ft.Len(), config.MaxFlows)
	}
}

// TestFlowTable_ConcurrentMillionFlows tests 8 goroutines x 125,000 distinct flows
func TestFlowTable_ConcurrentMillionFlows(t *testing.T) {
	config := DefaultFlowTableConfig()
	config.MaxFlows = 100000
	ft := NewFlowTable(config)

	var wg sync.WaitGroup
	numGoroutines := 8
	perGoroutine := 125000 // 8 * 125000 = 1,000,000 > 100,000

	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				f := Flow{
					SrcIP:   [16]byte{12: byte(gid), 13: byte(i >> 16), 14: byte(i >> 8), 15: byte(i)},
					DstIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: 100},
					SrcPort: uint16(i),
					DstPort: 22,
					Proto:   ProtoTCP,
					IPv6:    false,
				}
				ft.Lookup(f, true, FlowStateNew)
			}
		}(g)
	}

	wg.Wait()

	// Should have evicted to stay within bound
	if ft.Len() > config.MaxFlows {
		t.Errorf("flow table exceeded max flows under concurrency: got %d, max %d", ft.Len(), config.MaxFlows)
	}
	if ft.Len() < config.MaxFlows/2 {
		t.Errorf("flow table too empty under concurrency: got %d, max %d", ft.Len(), config.MaxFlows)
	}
}

// TestFlowTable_LRUListConsistency verifies LRU list length equals map size
func TestFlowTable_LRUListConsistency(t *testing.T) {
	config := DefaultFlowTableConfig()
	config.MaxFlows = 100
	ft := NewFlowTable(config)

	// Add 200 flows
	for i := 0; i < 200; i++ {
		f := Flow{
			SrcIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: byte(i)},
			DstIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: 100},
			SrcPort: uint16(10000 + i),
			DstPort: 22,
			Proto:   ProtoTCP,
			IPv6:    false,
		}
		ft.Lookup(f, true, FlowStateNew)
	}

	// Count entries in LRU list
	count := 0
	e := ft.evictList.head
	for e != nil {
		count++
		e = e.next
	}

	if count != ft.Len() {
		t.Errorf("LRU list length (%d) != map size (%d)", count, ft.Len())
	}
}
