// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package acl

import (
	"sync"
	"testing"
	"time"
)

func TestFlowTable_BasicLookup(t *testing.T) {
	ft := NewFlowTable(DefaultFlowTableConfig())

	f := Flow{
		SrcIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: 1}, // 10.0.0.1
		DstIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: 2}, // 10.0.0.2
		SrcPort: 12345,
		DstPort: 22,
		Proto:   ProtoTCP,
		IPv6:    false,
	}

	entry, isReply, created := ft.Lookup(f, true, FlowStateNew)
	if !created {
		t.Fatal("expected new entry to be created")
	}
	if entry == nil {
		t.Fatal("entry is nil")
	}
	if isReply {
		t.Error("expected forward direction, got reply")
	}
	if entry.State != FlowStateNew {
		t.Errorf("state: got %v, want %v", entry.State, FlowStateNew)
	}

	// Lookup again - should get same entry
	entry2, isReply2, created2 := ft.Lookup(f, true, FlowStateNew)
	if created2 {
		t.Error("expected existing entry, not created")
	}
	if entry != entry2 {
		t.Error("expected same entry")
	}
	if isReply2 {
		t.Error("expected forward direction")
	}
}

func TestFlowTable_BidirectionalNormalization(t *testing.T) {
	ft := NewFlowTable(DefaultFlowTableConfig())

	// Forward direction
	f1 := Flow{
		SrcIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: 1},
		DstIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: 2},
		SrcPort: 12345,
		DstPort: 22,
		Proto:   ProtoTCP,
		IPv6:    false,
	}

	// Reply direction (swapped)
	f2 := Flow{
		SrcIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: 2},
		DstIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: 1},
		SrcPort: 22,
		DstPort: 12345,
		Proto:   ProtoTCP,
		IPv6:    false,
	}

	entry1, isReply1, _ := ft.Lookup(f1, true, FlowStateNew)
	entry2, isReply2, _ := ft.Lookup(f2, true, FlowStateNew)

	if entry1 != entry2 {
		t.Fatal("forward and reply should map to same entry")
	}
	if isReply1 {
		t.Error("f1 should be forward direction")
	}
	if !isReply2 {
		t.Error("f2 should be reply direction")
	}
	if entry1.IsReplyDir {
		t.Error("entry should be marked as forward direction")
	}
}

func TestFlowTable_IPv6Normalization(t *testing.T) {
	ft := NewFlowTable(DefaultFlowTableConfig())

	f1 := Flow{
		SrcIP:   [16]byte{0: 0x20, 1: 0x01, 15: 1}, // 2001::1
		DstIP:   [16]byte{0: 0x20, 1: 0x01, 15: 2}, // 2001::2
		SrcPort: 12345,
		DstPort: 22,
		Proto:   ProtoTCP,
		IPv6:    true,
	}

	f2 := Flow{
		SrcIP:   [16]byte{0: 0x20, 1: 0x01, 15: 2},
		DstIP:   [16]byte{0: 0x20, 1: 0x01, 15: 1},
		SrcPort: 22,
		DstPort: 12345,
		Proto:   ProtoTCP,
		IPv6:    true,
	}

	entry1, isReply1, _ := ft.Lookup(f1, true, FlowStateNew)
	entry2, isReply2, _ := ft.Lookup(f2, true, FlowStateNew)

	if entry1 != entry2 {
		t.Fatal("IPv6 forward and reply should map to same entry")
	}
	if isReply1 {
		t.Error("f1 should be forward direction")
	}
	if !isReply2 {
		t.Error("f2 should be reply direction")
	}
}

func TestFlowTable_UDPFlow(t *testing.T) {
	ft := NewFlowTable(DefaultFlowTableConfig())

	f := Flow{
		SrcIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: 1},
		DstIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: 2},
		SrcPort: 12345,
		DstPort: 53,
		Proto:   ProtoUDP,
		IPv6:    false,
	}

	entry, _, created := ft.Lookup(f, true, FlowStateNew)
	if !created {
		t.Fatal("expected new entry")
	}
	if entry.Proto != ProtoUDP {
		t.Errorf("proto: got %v, want %v", entry.Proto, ProtoUDP)
	}
}

func TestFlowTable_ICMPFlow(t *testing.T) {
	ft := NewFlowTable(DefaultFlowTableConfig())

	f := Flow{
		SrcIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: 1},
		DstIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: 2},
		SrcPort: 0,
		DstPort: 0,
		Proto:   ProtoICMP,
		IPv6:    false,
	}

	entry, _, created := ft.Lookup(f, true, FlowStateNew)
	if !created {
		t.Fatal("expected new entry")
	}
	if entry.Proto != ProtoICMP {
		t.Errorf("proto: got %v, want %v", entry.Proto, ProtoICMP)
	}
}

func TestFlowTable_UpdateState(t *testing.T) {
	ft := NewFlowTable(DefaultFlowTableConfig())

	f := Flow{
		SrcIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: 1},
		DstIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: 2},
		SrcPort: 12345,
		DstPort: 22,
		Proto:   ProtoTCP,
		IPv6:    false,
	}

	ft.Lookup(f, true, FlowStateNew)
	ok := ft.UpdateState(f, FlowStateEstablished)
	if !ok {
		t.Fatal("UpdateState failed")
	}

	entry, _, _ := ft.Lookup(f, false, FlowStateNew)
	if entry.State != FlowStateEstablished {
		t.Errorf("state: got %v, want %v", entry.State, FlowStateEstablished)
	}
}

func TestFlowTable_ExpireOldFlows(t *testing.T) {
	config := DefaultFlowTableConfig()
	config.TCPIdleTimeout = 10 * time.Millisecond
	config.UDPIdleTimeout = 10 * time.Millisecond
	config.ICMPIdleTimeout = 10 * time.Millisecond
	ft := NewFlowTable(config)

	f := Flow{
		SrcIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: 1},
		DstIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: 2},
		SrcPort: 12345,
		DstPort: 22,
		Proto:   ProtoTCP,
		IPv6:    false,
	}

	ft.Lookup(f, true, FlowStateNew)
	if ft.Len() != 1 {
		t.Fatalf("expected 1 flow, got %d", ft.Len())
	}

	// Wait for expiration
	time.Sleep(20 * time.Millisecond)

	expired := ft.ExpireOldFlows()
	if expired != 1 {
		t.Errorf("expected 1 expired flow, got %d", expired)
	}
	if ft.Len() != 0 {
		t.Errorf("expected 0 flows after expiration, got %d", ft.Len())
	}
}

func TestFlowTable_ExpireOldFlows_ClosedState(t *testing.T) {
	config := DefaultFlowTableConfig()
	config.TCPIdleTimeout = 1 * time.Hour // Long timeout, we test closed state reaping
	ft := NewFlowTable(config)

	f := Flow{
		SrcIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: 1},
		DstIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: 2},
		SrcPort: 12345,
		DstPort: 22,
		Proto:   ProtoTCP,
		IPv6:    false,
	}

	ft.Lookup(f, true, FlowStateNew)
	if ft.Len() != 1 {
		t.Fatalf("expected 1 flow, got %d", ft.Len())
	}

	// Set flow state to closed (simulating FIN/RST detection)
	ok := ft.UpdateState(f, FlowStateClosed)
	if !ok {
		t.Fatal("UpdateState to FlowStateClosed failed")
	}

	// ExpireOldFlows should immediately reap closed flows
	expired := ft.ExpireOldFlows()
	if expired != 1 {
		t.Errorf("expected 1 closed flow reaped, got %d", expired)
	}
	if ft.Len() != 0 {
		t.Errorf("expected 0 flows after reaping closed flow, got %d", ft.Len())
	}
}

func TestFlowTable_RemoveFlow(t *testing.T) {
	ft := NewFlowTable(DefaultFlowTableConfig())

	f := Flow{
		SrcIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: 1},
		DstIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: 2},
		SrcPort: 12345,
		DstPort: 22,
		Proto:   ProtoTCP,
		IPv6:    false,
	}

	// Create a flow
	_, _, created := ft.Lookup(f, true, FlowStateNew)
	if !created {
		t.Fatal("expected new entry to be created")
	}

	// Get the normalized key
	key, _ := NormalizeFlowKey(f)

	// RemoveFlow should return true and remove the entry
	removed := ft.RemoveFlow(key)
	if !removed {
		t.Fatal("RemoveFlow should return true for existing flow")
	}
	if ft.Len() != 0 {
		t.Errorf("expected 0 flows after removal, got %d", ft.Len())
	}

	// RemoveFlow on non-existent key should return false
	removed = ft.RemoveFlow(key)
	if removed {
		t.Error("RemoveFlow should return false for non-existent flow")
	}
}

func TestFlowTable_RemoveFlow_UpdatesEvictionList(t *testing.T) {
	ft := NewFlowTable(DefaultFlowTableConfig())

	// Add two flows
	f1 := Flow{
		SrcIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: 1},
		DstIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: 2},
		SrcPort: 12345,
		DstPort: 22,
		Proto:   ProtoTCP,
		IPv6:    false,
	}

	f2 := Flow{
		SrcIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: 3},
		DstIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: 4},
		SrcPort: 12346,
		DstPort: 80,
		Proto:   ProtoTCP,
		IPv6:    false,
	}

	ft.Lookup(f1, true, FlowStateNew)
	ft.Lookup(f2, true, FlowStateNew)

	if ft.Len() != 2 {
		t.Fatalf("expected 2 flows, got %d", ft.Len())
	}

	// Remove the first flow
	key1, _ := NormalizeFlowKey(f1)
	removed := ft.RemoveFlow(key1)
	if !removed {
		t.Fatal("RemoveFlow should return true for existing flow")
	}

	// The second flow should still exist
	if ft.Len() != 1 {
		t.Errorf("expected 1 flow after removal, got %d", ft.Len())
	}

	_, _, _ = ft.Lookup(f2, false, FlowStateNew)
	if ft.Len() != 1 {
		t.Error("f2 should still exist after f1 removal")
	}

	// Remove the second flow
	key2, _ := NormalizeFlowKey(f2)
	removed = ft.RemoveFlow(key2)
	if !removed {
		t.Error("RemoveFlow should return true for f2")
	}
	if ft.Len() != 0 {
		t.Errorf("expected 0 flows after removing both, got %d", ft.Len())
	}
}

func TestFlowTable_Eviction(t *testing.T) {
	config := DefaultFlowTableConfig()
	config.MaxFlows = 10 // Very small for testing
	ft := NewFlowTable(config)

	// Add more flows than max
	for i := 0; i < 20; i++ {
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

	// Should have evicted some flows
	if ft.Len() > config.MaxFlows {
		t.Errorf("flow table exceeded max flows: got %d, max %d", ft.Len(), config.MaxFlows)
	}
}

func TestFlowTable_EvictionIsLRU(t *testing.T) {
	config := DefaultFlowTableConfig()
	config.MaxFlows = 5
	ft := NewFlowTable(config)

	// Add 5 flows
	for i := 0; i < 5; i++ {
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

	// Access the first flow to make it recently used
	f0 := Flow{
		SrcIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: 0},
		DstIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: 100},
		SrcPort: 10000,
		DstPort: 22,
		Proto:   ProtoTCP,
		IPv6:    false,
	}
	e0, _, _ := ft.Lookup(f0, false, FlowStateNew)
	if e0 == nil {
		t.Fatal("flow 0 should exist")
	}

	// Add one more flow - should evict the oldest (flow 1, not flow 0)
	f5 := Flow{
		SrcIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: 5},
		DstIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: 100},
		SrcPort: 10005,
		DstPort: 22,
		Proto:   ProtoTCP,
		IPv6:    false,
	}
	ft.Lookup(f5, true, FlowStateNew)

	// Flow 0 should still exist (was recently accessed)
	e0, _, _ = ft.Lookup(f0, false, FlowStateNew)
	if e0 == nil {
		t.Error("flow 0 should not have been evicted (recently accessed)")
	}

	// Flow 1 should have been evicted
	f1 := Flow{
		SrcIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: 1},
		DstIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: 100},
		SrcPort: 10001,
		DstPort: 22,
		Proto:   ProtoTCP,
		IPv6:    false,
	}
	e1, _, _ := ft.Lookup(f1, false, FlowStateNew)
	if e1 != nil {
		t.Error("flow 1 should have been evicted (oldest idle)")
	}
}

func TestFlowTable_ConcurrentAccess(t *testing.T) {
	ft := NewFlowTable(DefaultFlowTableConfig())

	done := make(chan bool, 100)
	for i := 0; i < 100; i++ {
		go func(id int) {
			f := Flow{
				SrcIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: byte(id)},
				DstIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: 100},
				SrcPort: uint16(10000 + id),
				DstPort: 22,
				Proto:   ProtoTCP,
				IPv6:    false,
			}
			for j := 0; j < 100; j++ {
				ft.Lookup(f, true, FlowStateNew)
				ft.UpdateState(f, FlowStateEstablished)
			}
			done <- true
		}(i)
	}

	for i := 0; i < 100; i++ {
		<-done
	}

	// Just verify no panic and table is consistent
	if ft.Len() == 0 {
		t.Error("flow table should not be empty")
	}
}

func TestFlowTable_Stats(t *testing.T) {
	ft := NewFlowTable(DefaultFlowTableConfig())

	f1 := Flow{
		SrcIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: 1},
		DstIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: 2},
		SrcPort: 12345,
		DstPort: 22,
		Proto:   ProtoTCP,
		IPv6:    false,
	}

	f2 := Flow{
		SrcIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: 3},
		DstIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: 4},
		SrcPort: 12346,
		DstPort: 80,
		Proto:   ProtoUDP,
		IPv6:    false,
	}

	ft.Lookup(f1, true, FlowStateNew)
	ft.Lookup(f2, true, FlowStateEstablished)

	stats := ft.Stats()
	if stats.TotalFlows != 2 {
		t.Errorf("TotalFlows: got %d, want 2", stats.TotalFlows)
	}
	if stats.EstablishedFlows != 1 {
		t.Errorf("EstablishedFlows: got %d, want 1", stats.EstablishedFlows)
	}
	if stats.MaxFlows != 16384 {
		t.Errorf("MaxFlows: got %d, want 16384", stats.MaxFlows)
	}
}

func TestFlowTable_GetTimeout(t *testing.T) {
	ft := NewFlowTable(DefaultFlowTableConfig())

	if ft.GetTimeout(ProtoTCP) != 5*time.Minute {
		t.Errorf("TCP timeout: got %v, want 5m", ft.GetTimeout(ProtoTCP))
	}
	if ft.GetTimeout(ProtoUDP) != 60*time.Second {
		t.Errorf("UDP timeout: got %v, want 60s", ft.GetTimeout(ProtoUDP))
	}
	if ft.GetTimeout(ProtoICMP) != 30*time.Second {
		t.Errorf("ICMP timeout: got %v, want 30s", ft.GetTimeout(ProtoICMP))
	}
	if ft.GetTimeout(ProtoICMPv6) != 30*time.Second {
		t.Errorf("ICMPv6 timeout: got %v, want 30s", ft.GetTimeout(ProtoICMPv6))
	}
}

// Gate tests for flow table bounds and expiration

func TestFlowTable_BoundEnforcement_SingleGoroutine(t *testing.T) {
	config := DefaultFlowTableConfig()
	config.MaxFlows = 10000
	ft := NewFlowTable(config)

	// Add 100000 connection starts (10x the limit)
	for i := 0; i < 100000; i++ {
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

	// Should have evicted to stay within bound
	if ft.Len() > config.MaxFlows {
		t.Errorf("flow table exceeded max flows: got %d, max %d", ft.Len(), config.MaxFlows)
	}
	// Should be close to max (allowing for some races in eviction)
	if ft.Len() < config.MaxFlows/2 {
		t.Errorf("flow table too empty: got %d, max %d", ft.Len(), config.MaxFlows)
	}
}

func TestFlowTable_BoundEnforcement_Concurrent(t *testing.T) {
	config := DefaultFlowTableConfig()
	config.MaxFlows = 50000
	ft := NewFlowTable(config)

	var wg sync.WaitGroup
	numGoroutines := 4
	perGoroutine := 25000 // 4 * 25000 = 100,000 > 50,000

	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				f := Flow{
					SrcIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: byte(gid)},
					DstIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: byte(i)},
					SrcPort: uint16(10000 + gid*1000 + i),
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
	// Should be close to max
	if ft.Len() < config.MaxFlows/2 {
		t.Errorf("flow table too empty under concurrency: got %d, max %d", ft.Len(), config.MaxFlows)
	}
}

func TestFlowTable_ExpiredFlowsTreatedAsMissing(t *testing.T) {
	config := DefaultFlowTableConfig()
	config.TCPIdleTimeout = 10 * time.Millisecond
	ft := NewFlowTable(config)

	f := Flow{
		SrcIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: 1},
		DstIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: 2},
		SrcPort: 12345,
		DstPort: 22,
		Proto:   ProtoTCP,
		IPv6:    false,
	}

	// Create flow
	entry, _, _ := ft.Lookup(f, true, FlowStateNew)
	if entry == nil {
		t.Fatal("entry should be created")
	}

	// Wait for expiration
	time.Sleep(20 * time.Millisecond)

	// Lookup without createIfMissing - should return nil because flow is expired
	entry, _, created := ft.Lookup(f, false, FlowStateNew)
	if entry != nil {
		t.Errorf("expired flow should be treated as missing, got entry with state %v", entry.State)
	}
	if created {
		t.Error("should not create new entry on lookup without createIfMissing")
	}

	// Lookup with createIfMissing should create a new entry
	entry, _, created = ft.Lookup(f, true, FlowStateNew)
	if entry == nil {
		t.Fatal("new entry should be created")
	}
	if !created {
		t.Error("should create new entry on lookup with createIfMissing")
	}
}

func TestFlowTable_UpdateState_ExpiredEntry(t *testing.T) {
	config := DefaultFlowTableConfig()
	config.TCPIdleTimeout = 10 * time.Millisecond
	ft := NewFlowTable(config)

	f := Flow{
		SrcIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: 1},
		DstIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: 2},
		SrcPort: 12345,
		DstPort: 22,
		Proto:   ProtoTCP,
		IPv6:    false,
	}

	// Create flow
	ft.Lookup(f, true, FlowStateNew)
	if ft.Len() != 1 {
		t.Fatalf("expected 1 flow, got %d", ft.Len())
	}

	// Wait for expiration
	time.Sleep(20 * time.Millisecond)

	// UpdateState on expired flow should return false
	ok := ft.UpdateState(f, FlowStateEstablished)
	if ok {
		t.Error("UpdateState on expired flow should return false")
	}
	if ft.Len() != 0 {
		t.Errorf("expired flow should be removed, got %d flows", ft.Len())
	}
}

func TestFlowTable_EvictionPicksOldestIdle(t *testing.T) {
	config := DefaultFlowTableConfig()
	config.MaxFlows = 5
	ft := NewFlowTable(config)

	// Add 5 flows
	for i := 0; i < 5; i++ {
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

	// Access the first flow to make it recently used
	f0 := Flow{
		SrcIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: 0},
		DstIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: 100},
		SrcPort: 10000,
		DstPort: 22,
		Proto:   ProtoTCP,
		IPv6:    false,
	}
	e0, _, _ := ft.Lookup(f0, false, FlowStateNew)
	if e0 == nil {
		t.Fatal("flow 0 should exist")
	}

	// Add one more flow - should evict the oldest (flow 1, not flow 0)
	f5 := Flow{
		SrcIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: 5},
		DstIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: 100},
		SrcPort: 10005,
		DstPort: 22,
		Proto:   ProtoTCP,
		IPv6:    false,
	}
	ft.Lookup(f5, true, FlowStateNew)

	// Flow 0 should still exist (was recently accessed)
	e0, _, _ = ft.Lookup(f0, false, FlowStateNew)
	if e0 == nil {
		t.Error("flow 0 should not have been evicted (recently accessed)")
	}

	// Flow 1 should have been evicted
	f1 := Flow{
		SrcIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: 1},
		DstIP:   [16]byte{12: 10, 13: 0, 14: 0, 15: 100},
		SrcPort: 10001,
		DstPort: 22,
		Proto:   ProtoTCP,
		IPv6:    false,
	}
	e1, _, _ := ft.Lookup(f1, false, FlowStateNew)
	if e1 != nil {
		t.Error("flow 1 should have been evicted (oldest idle)")
	}
}
