// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package relay

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/flynn/noise"

	"github.com/veldmesh/veld/internal/crypto"
	relayc "github.com/veldmesh/veld/internal/relay"
)

// flakyListener fails its first Accept with EMFILE, as a relay out of file
// descriptors would, then behaves normally.
type flakyListener struct {
	net.Listener
	failed atomic.Bool
}

func (l *flakyListener) Accept() (net.Conn, error) {
	if !l.failed.Swap(true) {
		return nil, &net.OpError{Op: "accept", Net: "tcp", Err: syscall.EMFILE}
	}
	return l.Listener.Accept()
}

func TestServeSurvivesTransientAcceptError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(mustIdentity(t), &flakyListener{Listener: ln})
	served := make(chan error, 1)
	go func() { served <- svc.Serve(context.Background()) }()
	t.Cleanup(func() { _ = svc.Close() })

	select {
	case err := <-served:
		t.Fatalf("Serve returned after a transient Accept error: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	c, err := net.Dial("tcp", svc.Addr())
	if err != nil {
		t.Fatalf("relay stopped accepting: %v", err)
	}
	c.Close()
}

// waitClosed reports whether the relay closes c within d.
func waitClosed(c net.Conn, d time.Duration) bool {
	_ = c.SetReadDeadline(time.Now().Add(d))
	_, err := c.Read(make([]byte, 1))
	return err == io.EOF
}

func TestPerIPConnectionLimit(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(mustIdentity(t), ln, MaxConns(0, 2))
	go svc.Serve(context.Background()) //nolint:errcheck
	t.Cleanup(func() { _ = svc.Close() })

	var held []net.Conn
	for i := 0; i < 2; i++ {
		c, err := net.Dial("tcp", svc.Addr())
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, c)
	}
	over, err := net.Dial("tcp", svc.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer over.Close()
	if !waitClosed(over, time.Second) {
		t.Error("third connection from the same IP was not refused")
	}

	// Closing one frees its slot.
	held[0].Close()
	time.Sleep(50 * time.Millisecond)
	again, err := net.Dial("tcp", svc.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if waitClosed(again, 200*time.Millisecond) {
		t.Error("connection refused after a slot was released")
	}
	held[1].Close()
}

func TestOversizedFirstFrameDropped(t *testing.T) {
	addr := startService(t, mustIdentity(t))
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], 0xffff)
	if _, err := c.Write(hdr[:]); err != nil {
		t.Fatal(err)
	}
	if !waitClosed(c, time.Second) {
		t.Error("relay kept a connection that announced a 64 KiB first frame")
	}
}

// msg1For builds a message_1 from id to the relay for remoteKey, with the
// given client clock.
func msg1For(t *testing.T, relayKey [32]byte, id *crypto.Identity, remoteKey [32]byte, at time.Time) []byte {
	t.Helper()
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   relayc.NoiseSuite,
		Pattern:       noise.HandshakeIK,
		Initiator:     true,
		StaticKeypair: noise.DHKey{Private: id.X25519Private[:], Public: id.X25519Public[:]},
		PeerStatic:    relayKey[:],
	})
	if err != nil {
		t.Fatal(err)
	}
	msg1, _, _, err := hs.WriteMessage(nil, relayc.Msg1Payload(remoteKey, at))
	if err != nil {
		t.Fatal(err)
	}
	return msg1
}

// sendMsg1 sends msg1 on a new connection and reports whether the relay
// answered with message_2.
func sendMsg1(t *testing.T, addr string, msg1 []byte) (net.Conn, bool) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if err := relayc.WriteFrame(c, msg1); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	_, err = relayc.ReadFrame(c)
	_ = c.SetReadDeadline(time.Time{})
	return c, err == nil
}

func TestReplayedMsg1Refused(t *testing.T) {
	relayID := mustIdentity(t)
	addr := startService(t, relayID)
	idA, idB := mustIdentity(t), mustIdentity(t)

	msg1 := msg1For(t, relayID.X25519Public, idA, idB.X25519Public, time.Now())
	victim, ok := sendMsg1(t, addr, msg1)
	if !ok {
		t.Fatal("first message_1 refused")
	}

	// The same bytes again: refused, and the victim's waiting connection
	// is left alone.
	if _, ok := sendMsg1(t, addr, msg1); ok {
		t.Error("replayed message_1 accepted")
	}
	if waitClosed(victim, 200*time.Millisecond) {
		t.Error("replay evicted the waiting connection")
	}

	// A message_1 from a minute ago is refused too.
	old := msg1For(t, relayID.X25519Public, idA, idB.X25519Public, time.Now().Add(-time.Minute))
	if _, ok := sendMsg1(t, addr, old); ok {
		t.Error("stale message_1 accepted")
	}
}
