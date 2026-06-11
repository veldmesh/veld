// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"testing"
	"time"

	coordv1 "github.com/veldmesh/veld/gen/veld/coord/v1"
)

func TestBus_PublishReceive(t *testing.T) {
	bus := NewBus()
	ch := bus.Subscribe("net1")
	defer bus.Unsubscribe("net1", ch)

	event := &coordv1.PeerEvent{
		Type: coordv1.EventType_JOIN,
		Peer: &coordv1.Peer{Id: "peer1", Name: "Test Peer"},
	}

	bus.Publish("net1", event)

	select {
	case received := <-ch:
		if received.Type != event.Type || received.Peer.Id != event.Peer.Id {
			t.Errorf("received event mismatch: got %+v, want %+v", received, event)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timeout waiting for event")
	}
}

func TestBus_Unsubscribe_ClosesChan(t *testing.T) {
	bus := NewBus()
	ch := bus.Subscribe("net1")

	bus.Unsubscribe("net1", ch)

	// Channel should be closed
	select {
	case _, ok := <-ch:
		if ok {
			t.Error("channel should be closed after unsubscribe")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timeout waiting for channel close")
	}
}

func TestBus_MultipleSubscribers(t *testing.T) {
	bus := NewBus()
	ch1 := bus.Subscribe("net1")
	ch2 := bus.Subscribe("net1")
	defer bus.Unsubscribe("net1", ch1)
	defer bus.Unsubscribe("net1", ch2)

	event := &coordv1.PeerEvent{
		Type: coordv1.EventType_JOIN,
		Peer: &coordv1.Peer{Id: "peer1", Name: "Test Peer"},
	}

	bus.Publish("net1", event)

	for _, ch := range []<-chan *coordv1.PeerEvent{ch1, ch2} {
		select {
		case received := <-ch:
			if received.Type != event.Type {
				t.Errorf("received event type mismatch: got %v, want %v", received.Type, event.Type)
			}
		case <-time.After(100 * time.Millisecond):
			t.Fatal("timeout waiting for event on channel")
		}
	}
}

func TestBus_NonblockingDrop(t *testing.T) {
	bus := NewBus()
	ch := bus.Subscribe("net1")
	defer bus.Unsubscribe("net1", ch)

	// Fill the channel (buffer size 64)
	for i := 0; i < 64; i++ {
		event := &coordv1.PeerEvent{
			Type: coordv1.EventType_JOIN,
			Peer: &coordv1.Peer{Id: string(rune('0' + i))},
		}
		bus.Publish("net1", event)
	}

	// Next publish should not block (drop silently)
	done := make(chan bool)
	go func() {
		event := &coordv1.PeerEvent{Type: coordv1.EventType_LEAVE}
		bus.Publish("net1", event)
		done <- true
	}()

	select {
	case <-done:
		// Success: publish did not block
	case <-time.After(500 * time.Millisecond):
		t.Fatal("publish blocked when channel was full")
	}
}

func TestBus_SignalDelivery(t *testing.T) {
	bus := NewBus()
	ch := bus.SubscribeSignals("peer1")
	defer bus.UnsubscribeSignals("peer1", ch)

	payload := []byte("test signal")
	bus.SendSignal("peer2", "peer1", payload)

	select {
	case msg := <-ch:
		if msg.FromPeerID != "peer2" || msg.ToPeerID != "peer1" {
			t.Errorf("signal routing wrong: from=%s, to=%s", msg.FromPeerID, msg.ToPeerID)
		}
		if string(msg.Payload) != "test signal" {
			t.Errorf("signal payload mismatch: got %s, want test signal", msg.Payload)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timeout waiting for signal")
	}
}

func TestBus_SignalUnsubscribe(t *testing.T) {
	bus := NewBus()
	ch := bus.SubscribeSignals("peer1")

	bus.UnsubscribeSignals("peer1", ch)

	// Channel should be closed
	select {
	case _, ok := <-ch:
		if ok {
			t.Error("channel should be closed after unsubscribe")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timeout waiting for channel close")
	}
}
