// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package relay

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/veldmesh/veld/internal/crypto"
)

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

func TestChannelID(t *testing.T) {
	var a, b, c [32]byte
	for i := range a {
		a[i] = byte(i)
		b[i] = byte(i + 1)
		c[i] = byte(i + 2)
	}

	t.Run("symmetric", func(t *testing.T) {
		if ChannelID(a, b) != ChannelID(b, a) {
			t.Error("ChannelID must be symmetric in the peer pair")
		}
	})

	t.Run("deterministic", func(t *testing.T) {
		first := ChannelID(a, b)
		if ChannelID(a, b) != first {
			t.Error("ChannelID must be deterministic")
		}
	})

	t.Run("distinct per pair", func(t *testing.T) {
		if ChannelID(a, b) == ChannelID(a, c) {
			t.Error("different peer pairs must derive different channel IDs")
		}
	})

	t.Run("self pair is valid", func(t *testing.T) {
		_ = ChannelID(a, a) // must not panic
	})
}

// dialPair connects two clients, each naming the other as its remote peer,
// and returns both Conns.
func dialPair(t *testing.T, relayAddr string, relayKey [32]byte, idA, idB *crypto.Identity) (*Conn, *Conn) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	type res struct {
		c   *Conn
		err error
	}
	ch := make(chan res, 2)
	// Dial both concurrently: the first waits for pairing.
	go func() {
		c, err := Dial(ctx, relayAddr, relayKey, idA, idB.X25519Public)
		ch <- res{c, err}
	}()
	go func() {
		c, err := Dial(ctx, relayAddr, relayKey, idB, idA.X25519Public)
		ch <- res{c, err}
	}()

	var conns []*Conn
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
		if err := cA.WriteMessage(make([]byte, maxMessage+1)); err == nil {
			t.Error("WriteMessage above maxMessage must fail")
		}
		// A max-size message still works.
		if err := cA.WriteMessage(make([]byte, maxMessage)); err != nil {
			t.Errorf("WriteMessage at maxMessage: %v", err)
		}
		got, err := cB.ReadMessage()
		if err != nil {
			t.Fatalf("ReadMessage max-size: %v", err)
		}
		if len(got) != maxMessage {
			t.Errorf("got %d bytes, want %d", len(got), maxMessage)
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
	cA, err := Dial(ctx, addr, relayID.X25519Public, idA, idB.X25519Public)
	if err != nil {
		t.Fatalf("Dial A: %v", err)
	}
	t.Cleanup(func() { _ = cA.Close() })

	// Impostor E also names B; it must land on a different channel.
	cE, err := Dial(ctx, addr, relayID.X25519Public, idE, idB.X25519Public)
	if err != nil {
		t.Fatalf("Dial E: %v", err)
	}
	t.Cleanup(func() { _ = cE.Close() })

	// E sends a frame; A must not receive it (A is unpaired with E).
	if err := cE.WriteMessage([]byte("hijack attempt")); err != nil {
		t.Fatalf("WriteMessage E: %v", err)
	}

	// Now the real B connects and pairs with A.
	cB, err := Dial(ctx, addr, relayID.X25519Public, idB, idA.X25519Public)
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

	cA1, err := Dial(ctx, addr, relayID.X25519Public, idA, idB.X25519Public)
	if err != nil {
		t.Fatalf("Dial A1: %v", err)
	}
	cA2, err := Dial(ctx, addr, relayID.X25519Public, idA, idB.X25519Public)
	if err != nil {
		t.Fatalf("Dial A2: %v", err)
	}

	// The stale connection must have been closed by the relay.
	cA1.raw.SetReadDeadline(time.Now().Add(3 * time.Second)) //nolint:errcheck
	if _, err := cA1.ReadMessage(); err == nil {
		t.Error("replaced connection A1 must be closed, got no error")
	}

	// B pairs with the fresh A2.
	cB, err := Dial(ctx, addr, relayID.X25519Public, idB, idA.X25519Public)
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
	c, err := Dial(ctx, svc.Addr(), relayID.X25519Public, idA, [32]byte{0x42})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	c.raw.SetReadDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	if _, err := c.ReadMessage(); !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
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
	_, err := Dial(ctx, addr, wrongKey, idA, [32]byte{1})
	if err == nil {
		t.Fatal("Dial with wrong relay key must fail")
	}
}

func TestDialUnreachable(t *testing.T) {
	idA := mustIdentity(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// Port 1 on loopback is never listening.
	_, err := Dial(ctx, "127.0.0.1:1", [32]byte{9}, idA, [32]byte{1})
	if err == nil {
		t.Fatal("Dial to unreachable relay must fail")
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

	proxyA, err := NewProxy(cA, connA.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("NewProxy A: %v", err)
	}
	t.Cleanup(func() { proxyA.Close() })
	proxyB, err := NewProxy(cB, connB.LocalAddr().(*net.UDPAddr))
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

	proxyA, err := NewProxy(cA, connA.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("NewProxy A: %v", err)
	}
	t.Cleanup(func() { proxyA.Close() })
	proxyB, err := NewProxy(cB, connB.LocalAddr().(*net.UDPAddr))
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
