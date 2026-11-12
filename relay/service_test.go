// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: BUSL-1.1
package relay

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/veldmesh/veld/internal/crypto"
	relayc "github.com/veldmesh/veld/internal/relay"
)

// testMaxMessage mirrors the client's (unexported) maxMessage: the largest
// plaintext payload a single relay frame can carry.
const testMaxMessage = 0xFFFF - 16

func mustIdentity(t *testing.T) *crypto.Identity {
	t.Helper()
	id, err := crypto.Generate()
	if err != nil {
		t.Fatalf("crypto.Generate: %v", err)
	}
	return id
}

// startService launches a relay service on a loopback TCP listener.
func startService(t *testing.T, id *crypto.Identity) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	svc := NewService(id, ln)
	go svc.Serve(context.Background()) //nolint:errcheck
	t.Cleanup(func() { _ = svc.Close() })
	return svc.Addr()
}

// readWithTimeout reads one message, failing the test if it blocks longer
// than d. Used where a test expects the relay to have closed a connection.
func readWithTimeout(t *testing.T, c *relayc.Conn, d time.Duration) ([]byte, error) {
	t.Helper()
	type res struct {
		b   []byte
		err error
	}
	ch := make(chan res, 1)
	go func() {
		b, err := c.ReadMessage()
		ch <- res{b, err}
	}()
	select {
	case r := <-ch:
		return r.b, r.err
	case <-time.After(d):
		t.Fatal("ReadMessage blocked past deadline")
		return nil, nil
	}
}

// dialPair connects two clients, each naming the other as its remote peer,
// and returns both Conns.
func dialPair(t *testing.T, relayAddr string, relayKey [32]byte, idA, idB *crypto.Identity) (*relayc.Conn, *relayc.Conn) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	type res struct {
		c   *relayc.Conn
		err error
	}
	ch := make(chan res, 2)
	// Dial both concurrently: the first waits for pairing.
	go func() {
		c, err := relayc.Dial(ctx, relayAddr, relayKey, idA, idB.X25519Public)
		ch <- res{c, err}
	}()
	go func() {
		c, err := relayc.Dial(ctx, relayAddr, relayKey, idB, idA.X25519Public)
		ch <- res{c, err}
	}()

	var conns []*relayc.Conn
	for i := 0; i < 2; i++ {
		r := <-ch
		if r.err != nil {
			t.Fatalf("Dial: %v", r.err)
		}
		conns = append(conns, r.c)
	}
	t.Cleanup(func() {
		_ = conns[0].Close()
		_ = conns[1].Close()
	})
	return conns[0], conns[1]
}

func TestDialExchange(t *testing.T) {
	relayID := mustIdentity(t)
	addr := startService(t, relayID)
	idA, idB := mustIdentity(t), mustIdentity(t)

	cA, cB := dialPair(t, addr, relayID.X25519Public, idA, idB)

	t.Run("A to B", func(t *testing.T) {
		payload := []byte("hello over relay")
		if err := cA.WriteMessage(payload); err != nil {
			t.Fatalf("WriteMessage: %v", err)
		}
		got, err := cB.ReadMessage()
		if err != nil {
			t.Fatalf("ReadMessage: %v", err)
		}
		if !bytes.Equal(got, payload) {
			t.Errorf("got %q, want %q", got, payload)
		}
	})

	t.Run("B to A", func(t *testing.T) {
		payload := []byte("reply over relay")
		if err := cB.WriteMessage(payload); err != nil {
			t.Fatalf("WriteMessage: %v", err)
		}
		got, err := cA.ReadMessage()
		if err != nil {
			t.Fatalf("ReadMessage: %v", err)
		}
		if !bytes.Equal(got, payload) {
			t.Errorf("got %q, want %q", got, payload)
		}
	})

	t.Run("multiple messages preserve order", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			if err := cA.WriteMessage([]byte{byte(i)}); err != nil {
				t.Fatalf("WriteMessage %d: %v", i, err)
			}
		}
		for i := 0; i < 10; i++ {
			got, err := cB.ReadMessage()
			if err != nil {
				t.Fatalf("ReadMessage %d: %v", i, err)
			}
			if len(got) != 1 || got[0] != byte(i) {
				t.Errorf("message %d: got %v", i, got)
			}
		}
	})

	t.Run("oversized message rejected locally", func(t *testing.T) {
		if err := cA.WriteMessage(make([]byte, testMaxMessage+1)); err == nil {
			t.Error("WriteMessage above maxMessage must fail")
		}
		// A max-size message still works.
		if err := cA.WriteMessage(make([]byte, testMaxMessage)); err != nil {
			t.Errorf("WriteMessage at maxMessage: %v", err)
		}
		got, err := cB.ReadMessage()
		if err != nil {
			t.Fatalf("ReadMessage max-size: %v", err)
		}
		if len(got) != testMaxMessage {
			t.Errorf("got %d bytes, want %d", len(got), testMaxMessage)
		}
	})
}

// TestDialImpostorCannotHijack verifies that a third party naming B's key
// does NOT get paired with A's waiting connection: the channel is derived
// from the authenticated initiator key, so the impostor lands on a different
// channel and A's connection does not receive the impostor's frames.
func TestDialImpostorCannotHijack(t *testing.T) {
	relayID := mustIdentity(t)
	addr := startService(t, relayID)
	idA, idB, idE := mustIdentity(t), mustIdentity(t), mustIdentity(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// A waits for B.
	cA, err := relayc.Dial(ctx, addr, relayID.X25519Public, idA, idB.X25519Public)
	if err != nil {
		t.Fatalf("Dial A: %v", err)
	}
	t.Cleanup(func() { _ = cA.Close() })

	// Impostor E also names B; it must land on a different channel.
	cE, err := relayc.Dial(ctx, addr, relayID.X25519Public, idE, idB.X25519Public)
	if err != nil {
		t.Fatalf("Dial E: %v", err)
	}
	t.Cleanup(func() { _ = cE.Close() })

	// E sends a frame; A must not receive it (A is unpaired with E).
	if err := cE.WriteMessage([]byte("hijack attempt")); err != nil {
		t.Fatalf("WriteMessage E: %v", err)
	}

	// Now the real B connects and pairs with A.
	cB, err := relayc.Dial(ctx, addr, relayID.X25519Public, idB, idA.X25519Public)
	if err != nil {
		t.Fatalf("Dial B: %v", err)
	}
	t.Cleanup(func() { _ = cB.Close() })

	want := []byte("real message for A")
	if err := cB.WriteMessage(want); err != nil {
		t.Fatalf("WriteMessage B: %v", err)
	}
	got, err := cA.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage A: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("A got %q (hijacked?), want %q", got, want)
	}
}

// TestReconnectReplacesWaiting verifies that if A reconnects before B
// arrives, the relay replaces the stale waiting connection instead of
// splicing A's two connections to each other, and B still pairs with A.
func TestReconnectReplacesWaiting(t *testing.T) {
	relayID := mustIdentity(t)
	addr := startService(t, relayID)
	idA, idB := mustIdentity(t), mustIdentity(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cA1, err := relayc.Dial(ctx, addr, relayID.X25519Public, idA, idB.X25519Public)
	if err != nil {
		t.Fatalf("Dial A1: %v", err)
	}
	cA2, err := relayc.Dial(ctx, addr, relayID.X25519Public, idA, idB.X25519Public)
	if err != nil {
		t.Fatalf("Dial A2: %v", err)
	}

	// The stale connection must have been closed by the relay.
	if _, err := readWithTimeout(t, cA1, 3*time.Second); err == nil {
		t.Error("replaced connection A1 must be closed, got no error")
	}

	// B pairs with the fresh A2.
	cB, err := relayc.Dial(ctx, addr, relayID.X25519Public, idB, idA.X25519Public)
	if err != nil {
		t.Fatalf("Dial B: %v", err)
	}
	t.Cleanup(func() { _ = cA2.Close(); _ = cB.Close() })

	want := []byte("B reaches the new A")
	if err := cB.WriteMessage(want); err != nil {
		t.Fatalf("WriteMessage B: %v", err)
	}
	got, err := cA2.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage A2: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("A2 got %q, want %q", got, want)
	}
}

// TestReconnectReplacesWaitingDeterministic is a deterministic regression
// test for the reconnect ordering race. It uses a test hook to force A2's
// registration to happen before A1's, verifying that the newer connection
// (A2) wins and the stale connection (A1) is closed. On the buggy code
// (without sequence numbers), this test would fail because A1 would evict A2.
func TestReconnectReplacesWaitingDeterministic(t *testing.T) {
	relayID := mustIdentity(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	svc := NewService(relayID, ln)
	go svc.Serve(context.Background()) //nolint:errcheck
	t.Cleanup(func() { _ = svc.Close() })

	idA, idB := mustIdentity(t), mustIdentity(t)
	channel := relayc.ChannelID(idA.X25519Public, idB.X25519Public)

	// Synchronization: A1 signals when it reaches the test hook (after
	// handshake, before registration). The test waits for A1 ready, dials A2,
	// then polls until A2 is registered in svc.waiting. A1 then proceeds and
	// should find A2 already registered and close itself (since A1 is older).
	a1Ready := make(chan struct{})
	a1Done := make(chan struct{})

	var hookCount int32
	svc.afterHandshake = func(sc *serverConn) {
		count := atomic.AddInt32(&hookCount, 1)
		switch count {
		case 1:
			// First connection (A1): signal ready, wait for test to signal done
			close(a1Ready)
			<-a1Done
		case 2:
			// Second connection (A2): return immediately so it can register
			return
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Dial A1 first (it will reach the hook first)
	cA1, err := relayc.Dial(ctx, svc.Addr(), relayID.X25519Public, idA, idB.X25519Public)
	if err != nil {
		t.Fatalf("Dial A1: %v", err)
	}

	// Give A1 time to reach the hook
	select {
	case <-a1Ready:
	case <-time.After(2 * time.Second):
		t.Fatal("A1 did not reach test hook in time")
	}

	// Now dial A2 (it will register before A1 proceeds)
	cA2, err := relayc.Dial(ctx, svc.Addr(), relayID.X25519Public, idA, idB.X25519Public)
	if err != nil {
		t.Fatalf("Dial A2: %v", err)
	}

	// Wait for A2 to actually register in svc.waiting
	deadline := time.Now().Add(2 * time.Second)
	for {
		svc.mu.Lock()
		registered := svc.waiting[channel] != nil
		svc.mu.Unlock()
		if registered {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("A2 did not register in svc.waiting before deadline")
		}
		time.Sleep(time.Millisecond)
	}

	// Now let A1 proceed (it will see A2 registered and close itself)
	close(a1Done)

	// Wait for A1's handler to finish
	select {
	case <-a1Done:
	case <-time.After(2 * time.Second):
		t.Fatal("A1 handler did not complete in time")
	}

	// A1 must be closed by the relay (newer A2 won)
	if _, err := readWithTimeout(t, cA1, 3*time.Second); err == nil {
		t.Error("stale connection A1 must be closed, got no error")
	}

	// B pairs with the fresh A2
	cB, err := relayc.Dial(ctx, svc.Addr(), relayID.X25519Public, idB, idA.X25519Public)
	if err != nil {
		t.Fatalf("Dial B: %v", err)
	}
	t.Cleanup(func() { _ = cA2.Close(); _ = cB.Close() })

	want := []byte("B reaches the new A")
	if err := cB.WriteMessage(want); err != nil {
		t.Fatalf("WriteMessage B: %v", err)
	}
	got, err := cA2.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage A2: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("A2 got %q, want %q", got, want)
	}
}

// TestReconnectOlderStalledAfterNewerPaired verifies that if a newer
// connection (A2) pairs with B and leaves waiting, an older stalled
// connection (A1) cannot re-register itself in waiting. This is the
// adversarial case where A1's handler was stalled between msg2 and
// registration while A2 registered, paired, and left waiting.
func TestReconnectOlderStalledAfterNewerPaired(t *testing.T) {
	relayID := mustIdentity(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	svc := NewService(relayID, ln)
	go svc.Serve(context.Background()) //nolint:errcheck
	t.Cleanup(func() { _ = svc.Close() })

	idA, idB := mustIdentity(t), mustIdentity(t)
	channel := relayc.ChannelID(idA.X25519Public, idB.X25519Public)

	// Synchronization:
	// - A1 signals when it reaches the hook (after handshake, before registration)
	// - A2 waits for A1 ready, then proceeds to registration
	// - B dials and pairs with A2 (A2 leaves waiting)
	// - A1 then proceeds and should be rejected because maxSeq for
	//   (channel, clientKey) is A2's seq (which is higher than A1's)
	a1Ready := make(chan struct{})
	a2Paired := make(chan struct{})
	a1Done := make(chan struct{})

	var hookCount int32
	svc.afterHandshake = func(sc *serverConn) {
		count := atomic.AddInt32(&hookCount, 1)
		switch count {
		case 1:
			// A1: signal ready, wait for A2 to pair
			close(a1Ready)
			<-a2Paired
			close(a1Done)
		case 2:
			// A2: wait for A1 ready, then return immediately to register
			<-a1Ready
			return
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Dial A1 first (it will reach the hook first)
	cA1, err := relayc.Dial(ctx, svc.Addr(), relayID.X25519Public, idA, idB.X25519Public)
	if err != nil {
		t.Fatalf("Dial A1: %v", err)
	}

	// Give A1 time to reach the hook
	select {
	case <-a1Ready:
	case <-time.After(2 * time.Second):
		t.Fatal("A1 did not reach test hook in time")
	}

	// Now dial A2 (it will register before A1 proceeds)
	cA2, err := relayc.Dial(ctx, svc.Addr(), relayID.X25519Public, idA, idB.X25519Public)
	if err != nil {
		t.Fatalf("Dial A2: %v", err)
	}

	// Wait for A2 to actually register in svc.waiting
	deadline := time.Now().Add(2 * time.Second)
	for {
		svc.mu.Lock()
		registered := svc.waiting[channel] != nil
		svc.mu.Unlock()
		if registered {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("A2 did not register in svc.waiting before deadline")
		}
		time.Sleep(time.Millisecond)
	}

	// Now dial B - it should pair with A2
	cB, err := relayc.Dial(ctx, svc.Addr(), relayID.X25519Public, idB, idA.X25519Public)
	if err != nil {
		t.Fatalf("Dial B: %v", err)
	}
	t.Cleanup(func() { _ = cA2.Close(); _ = cB.Close() })

	// Verify A2 and B are paired by sending a message
	want := []byte("B reaches A2")
	if err := cB.WriteMessage(want); err != nil {
		t.Fatalf("WriteMessage B: %v", err)
	}
	got, err := cA2.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage A2: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("A2 got %q, want %q", got, want)
	}

	// Now A2 has paired and left waiting. Signal A1 to proceed.
	close(a2Paired)

	// Wait for A1's handler to finish (it should be rejected and close)
	select {
	case <-a1Done:
	case <-time.After(2 * time.Second):
		t.Fatal("A1 handler did not complete in time")
	}

	// A1 must be closed by the relay (maxSeq check rejects it)
	if _, err := readWithTimeout(t, cA1, 3*time.Second); err == nil {
		t.Error("stale connection A1 must be closed, got no error")
	}

	// Verify A2 is still connected and working (not affected by A1's attempt)
	want2 := []byte("B still reaches A2")
	if err := cB.WriteMessage(want2); err != nil {
		t.Fatalf("WriteMessage B again: %v", err)
	}
	got2, err := cA2.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage A2 again: %v", err)
	}
	if !bytes.Equal(got2, want2) {
		t.Errorf("A2 got %q, want %q", got2, want2)
	}
}

// TestUnpairedConnectionEvicted verifies a client that never gets a partner
// is evicted after the waiting timeout instead of lingering forever.
func TestUnpairedConnectionEvicted(t *testing.T) {
	relayID := mustIdentity(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	svc := NewService(relayID, ln)
	svc.waitTimeout = 200 * time.Millisecond
	go svc.Serve(context.Background()) //nolint:errcheck
	t.Cleanup(func() { _ = svc.Close() })

	idA := mustIdentity(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := relayc.Dial(ctx, svc.Addr(), relayID.X25519Public, idA, [32]byte{0x42})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if _, err := readWithTimeout(t, c, 5*time.Second); !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected eviction to close the connection (EOF), got %v", err)
	}
}

func TestDialWrongRelayKey(t *testing.T) {
	relayID := mustIdentity(t)
	addr := startService(t, relayID)
	idA := mustIdentity(t)
	wrongKey := mustIdentity(t).X25519Public

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := relayc.Dial(ctx, addr, wrongKey, idA, [32]byte{1})
	if err == nil {
		t.Fatal("Dial with wrong relay key must fail")
	}
}

func TestProxy(t *testing.T) {
	relayID := mustIdentity(t)
	addr := startService(t, relayID)
	idA, idB := mustIdentity(t), mustIdentity(t)

	cA, cB := dialPair(t, addr, relayID.X25519Public, idA, idB)

	// Simulate two data-plane sockets.
	connA, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("connA: %v", err)
	}
	t.Cleanup(func() { connA.Close() })
	connB, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("connB: %v", err)
	}
	t.Cleanup(func() { connB.Close() })

	proxyA, err := relayc.NewProxy(cA, connA.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("NewProxy A: %v", err)
	}
	t.Cleanup(func() { proxyA.Close() })
	proxyB, err := relayc.NewProxy(cB, connB.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("NewProxy B: %v", err)
	}
	t.Cleanup(func() { proxyB.Close() })

	// A → B: send to A's proxy address, expect delivery on B's data conn.
	msg := []byte("datagram through relay")
	if _, err := connA.WriteToUDP(msg, net.UDPAddrFromAddrPort(proxyA.LocalAddr())); err != nil {
		t.Fatalf("write to proxyA: %v", err)
	}

	buf := make([]byte, 2048)
	connB.SetReadDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	n, from, err := connB.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("connB read: %v", err)
	}
	if !bytes.Equal(buf[:n], msg) {
		t.Errorf("connB got %q, want %q", buf[:n], msg)
	}
	// The dispatcher sees the datagram arriving from B's own proxy address.
	if from.Port != int(proxyB.LocalAddr().Port()) {
		t.Errorf("connB source = %v, want proxy B port %d", from, proxyB.LocalAddr().Port())
	}

	// B → A (reply path).
	reply := []byte("reply through relay")
	if _, err := connB.WriteToUDP(reply, net.UDPAddrFromAddrPort(proxyB.LocalAddr())); err != nil {
		t.Fatalf("write to proxyB: %v", err)
	}
	connA.SetReadDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	n, from, err = connA.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("connA read: %v", err)
	}
	if !bytes.Equal(buf[:n], reply) {
		t.Errorf("connA got %q, want %q", buf[:n], reply)
	}
	if from.Port != int(proxyA.LocalAddr().Port()) {
		t.Errorf("connA source = %v, want proxy A port %d", from, proxyA.LocalAddr().Port())
	}
}

// TestProxyDropsStraySender verifies the proxy only accepts datagrams from
// the daemon's data-plane socket, not from arbitrary local processes.
func TestProxyDropsStraySender(t *testing.T) {
	relayID := mustIdentity(t)
	addr := startService(t, relayID)
	idA, idB := mustIdentity(t), mustIdentity(t)

	cA, cB := dialPair(t, addr, relayID.X25519Public, idA, idB)

	connA, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("connA: %v", err)
	}
	t.Cleanup(func() { connA.Close() })
	connB, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("connB: %v", err)
	}
	t.Cleanup(func() { connB.Close() })
	stranger, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("stranger: %v", err)
	}
	t.Cleanup(func() { stranger.Close() })

	proxyA, err := relayc.NewProxy(cA, connA.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("NewProxy A: %v", err)
	}
	t.Cleanup(func() { proxyA.Close() })
	proxyB, err := relayc.NewProxy(cB, connB.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("NewProxy B: %v", err)
	}
	t.Cleanup(func() { proxyB.Close() })

	// A stray local process sends to proxy A first: it must be dropped.
	if _, err := stranger.WriteToUDP([]byte("intruder"), net.UDPAddrFromAddrPort(proxyA.LocalAddr())); err != nil {
		t.Fatalf("stranger write: %v", err)
	}
	// Then the real daemon socket sends: it must be delivered.
	msg := []byte("legit datagram")
	if _, err := connA.WriteToUDP(msg, net.UDPAddrFromAddrPort(proxyA.LocalAddr())); err != nil {
		t.Fatalf("connA write: %v", err)
	}

	buf := make([]byte, 2048)
	connB.SetReadDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	n, _, err := connB.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("connB read: %v", err)
	}
	if !bytes.Equal(buf[:n], msg) {
		t.Errorf("connB got %q, want %q (stray datagram must be dropped)", buf[:n], msg)
	}
}
