// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package peer

import (
	"net/netip"
	"testing"
	"time"
)

func TestEntry_HoldQueue_Enqueue_Drain(t *testing.T) {
	e := &Entry{}

	pkt1 := []byte{0x45, 0x00, 0x01}
	pkt2 := []byte{0x45, 0x00, 0x02}

	if !e.Enqueue(pkt1) {
		t.Fatal("Enqueue pkt1 should succeed")
	}
	if !e.Enqueue(pkt2) {
		t.Fatal("Enqueue pkt2 should succeed")
	}

	q := e.DrainQueue()
	if len(q) != 2 {
		t.Fatalf("DrainQueue: got %d packets, want 2", len(q))
	}
	if string(q[0]) != string(pkt1) {
		t.Errorf("q[0]: got %x, want %x", q[0], pkt1)
	}
	if string(q[1]) != string(pkt2) {
		t.Errorf("q[1]: got %x, want %x", q[1], pkt2)
	}
}

func TestEntry_HoldQueue_DrainEmpty(t *testing.T) {
	e := &Entry{}
	q := e.DrainQueue()
	if q != nil {
		t.Errorf("DrainQueue on empty queue: got %v, want nil", q)
	}
}

func TestEntry_HoldQueue_MaxCapacity(t *testing.T) {
	e := &Entry{}

	pkt := []byte{0x45, 0x00}
	for i := 0; i < HoldQueueMax; i++ {
		if !e.Enqueue(pkt) {
			t.Fatalf("Enqueue %d should succeed (below max)", i)
		}
	}

	if e.Enqueue(pkt) {
		t.Error("Enqueue beyond HoldQueueMax should return false")
	}

	q := e.DrainQueue()
	if len(q) != HoldQueueMax {
		t.Errorf("DrainQueue: got %d, want %d", len(q), HoldQueueMax)
	}
}

func TestEntry_HoldQueue_Isolation(t *testing.T) {
	e := &Entry{}
	pkt := []byte{0x45, 0x00, 0x03}
	e.Enqueue(pkt)
	pkt[2] = 0xFF

	q := e.DrainQueue()
	if q[0][2] == 0xFF {
		t.Error("Enqueue should copy the packet, not store a reference")
	}
}

func TestEntry_DrainQueue_ClearsQueue(t *testing.T) {
	e := &Entry{}
	e.Enqueue([]byte{1})
	e.DrainQueue()

	if q := e.DrainQueue(); q != nil {
		t.Error("second DrainQueue should return nil")
	}
}

func TestEntry_SetGet_Session(t *testing.T) {
	e := &Entry{}
	if e.GetSession() != nil {
		t.Error("initial session should be nil")
	}
	if e.GetState() != StatePending {
		t.Errorf("initial state: got %d, want StatePending", e.GetState())
	}

	e.SetSession(nil)
	if e.GetState() != StateConnected {
		t.Errorf("state after SetSession: got %d, want StateConnected", e.GetState())
	}
}

func TestEntry_SetState(t *testing.T) {
	e := &Entry{}
	e.SetState(StateHandshaking)
	if e.GetState() != StateHandshaking {
		t.Errorf("got %d, want StateHandshaking", e.GetState())
	}
}

func TestEntry_Touch_LastSeen(t *testing.T) {
	e := &Entry{}
	before := time.Now()
	e.Touch()
	after := time.Now()

	ls := e.LastSeen()
	if ls.Before(before) || ls.After(after) {
		t.Errorf("LastSeen %v not in range [%v, %v]", ls, before, after)
	}
}

func TestEntry_Endpoint(t *testing.T) {
	e := &Entry{}
	ep, _ := netip.ParseAddrPort("1.2.3.4:5000")
	e.SetEndpoint(ep)
	if e.GetEndpoint() != ep {
		t.Errorf("GetEndpoint: got %v, want %v", e.GetEndpoint(), ep)
	}
}
