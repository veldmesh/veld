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
