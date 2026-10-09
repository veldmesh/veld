// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"bytes"
	"context"
	"log"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/flynn/noise"

	"github.com/veldmesh/veld/internal/crypto"
	relayc "github.com/veldmesh/veld/internal/relay"
)

// syncBuffer serializes writes so tests can read captured log output
// without racing the logger.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// captureLog redirects the standard logger — the one the relay service
// writes to with default flags — into a buffer for the duration of the
// test, and restores it afterwards.
func captureLog(t *testing.T) *syncBuffer {
	t.Helper()
	var logs syncBuffer
	oldW := log.Writer()
	oldFlags := log.Flags()
	log.SetOutput(&logs)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(oldW)
		log.SetFlags(oldFlags)
	})
	return &logs
}

// startOptService starts a relay Service configured with opts.
func startOptService(t *testing.T, id *crypto.Identity, opts ...Option) *Service {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	svc := NewService(id, ln, opts...)
	go svc.Serve(context.Background()) //nolint:errcheck
	t.Cleanup(func() { _ = svc.Close() })
	return svc
}

// dialManual performs the client side of the relay channel handshake over a
// raw TCP connection, using the same exported protocol pieces as
// relayc.Dial, and returns the raw connection so tests can inject frames
// the public client API cannot (e.g. corrupt ciphertext).
func dialManual(t *testing.T, ctx context.Context, addr string, relayKey [32]byte, id *crypto.Identity, remoteKey [32]byte) net.Conn {
	t.Helper()
	var d net.Dialer
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(dl)
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: relayc.NoiseSuite,
		Pattern:     noise.HandshakeIK,
		Initiator:   true,
		StaticKeypair: noise.DHKey{
			Private: id.X25519Private[:],
			Public:  id.X25519Public[:],
		},
		PeerStatic: relayKey[:],
	})
	if err != nil {
		t.Fatalf("handshake state: %v", err)
	}
	msg1, _, _, err := hs.WriteMessage(nil, remoteKey[:])
	if err != nil {
		t.Fatalf("handshake msg1: %v", err)
	}
	if err := relayc.WriteFrame(raw, msg1); err != nil {
		t.Fatalf("handshake send: %v", err)
	}
	msg2, err := relayc.ReadFrame(raw)
	if err != nil {
		t.Fatalf("handshake recv: %v", err)
	}
	if _, _, _, err := hs.ReadMessage(nil, msg2); err != nil {
		t.Fatalf("handshake msg2: %v", err)
	}
	_ = raw.SetDeadline(time.Time{})
	return raw
}

// spliceErrorScenario pairs two manual clients on one channel and then
// corrupts A's outbound ciphertext, forcing a real (non-benign) splice
// error on the server. It returns once the relay has closed B's end, which
// happens after the error path — and any log line it emits — has run.
func spliceErrorScenario(t *testing.T, svc *Service, relayKey [32]byte) {
	t.Helper()
	idA, idB := mustIdentity(t), mustIdentity(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rawA := dialManual(t, ctx, svc.Addr(), relayKey, idA, idB.X25519Public)
	t.Cleanup(func() { _ = rawA.Close() })
	rawB := dialManual(t, ctx, svc.Addr(), relayKey, idB, idA.X25519Public)
	t.Cleanup(func() { _ = rawB.Close() })

	if err := relayc.WriteFrame(rawA, []byte("corrupt ciphertext")); err != nil {
		t.Fatalf("write corrupt frame: %v", err)
	}
	_ = rawB.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := rawB.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected the relay to close B's connection after the splice error")
	}
}

// networkTeardownScenario pairs two manual clients on one channel, then
// aborts A's TCP connection with an RST (SO_LINGER 0) instead of a clean
// FIN, so the relay's splice read fails with a real network error — the
// kind whose *net.OpError text embeds both endpoints' full ip:port. It
// returns A's local port and once the relay has torn down B's end, which
// happens after the error path — and any log line it emits — has run.
func networkTeardownScenario(t *testing.T, svc *Service, relayKey [32]byte) string {
	t.Helper()
	idA, idB := mustIdentity(t), mustIdentity(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rawA := dialManual(t, ctx, svc.Addr(), relayKey, idA, idB.X25519Public)
	rawB := dialManual(t, ctx, svc.Addr(), relayKey, idB, idA.X25519Public)
	t.Cleanup(func() { _ = rawB.Close() })

	_, portA, _ := net.SplitHostPort(rawA.LocalAddr().String())

	// SO_LINGER 0 makes Close send an RST rather than a FIN, so the relay's
	// splice read fails with "connection reset by peer" instead of a benign
	// EOF. The resulting error's text names both endpoints' ip:port.
	if tc, ok := rawA.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
	_ = rawA.Close()

	_ = rawB.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := rawB.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected the relay to close B's connection after the splice error")
	}
	return portA
}

// TestQuietByDefault drives a full connection lifecycle — connect, pair and
// a real splice error — and verifies the relay with default flags logs no
// per-connection lines at all: no channel IDs, no client addresses.
func TestQuietByDefault(t *testing.T) {
	relayID := mustIdentity(t)
	logs := captureLog(t)
	svc := startOptService(t, relayID) // default flags: no options

	spliceErrorScenario(t, svc, relayID.X25519Public)

	if got := logs.String(); got != "" {
		t.Errorf("relay with default flags logged per-connection lines:\n%s", got)
	}
}

// TestVerboseLogsTruncatedAddresses verifies that verbose mode re-enables
// per-connection logging and that every client address in it is truncated —
// the full address the server sees never appears.
func TestVerboseLogsTruncatedAddresses(t *testing.T) {
	relayID := mustIdentity(t)
	logs := captureLog(t)
	svc := startOptService(t, relayID, Verbose())

	spliceErrorScenario(t, svc, relayID.X25519Public)

	out := logs.String()
	if !strings.Contains(out, "127.0.0.x") {
		t.Errorf("verbose logs should contain the truncated client address, got:\n%s", out)
	}
	if strings.Contains(out, "127.0.0.1") {
		t.Errorf("verbose logs must not contain full client addresses, got:\n%s", out)
	}
	if !strings.Contains(out, "splice ended") {
		t.Errorf("verbose logs should report the splice error, got:\n%s", out)
	}
}

// TestVerboseSpliceErrorsLeakNoEndpoints forces a real network teardown
// error mid-splice (an RST, so the relay's read fails with *net.OpError)
// and verifies that even verbose per-connection logs carry no full client
// addresses or ports: network error text embeds both endpoints' ip:port and
// must be scrubbed before it is logged.
func TestVerboseSpliceErrorsLeakNoEndpoints(t *testing.T) {
	relayID := mustIdentity(t)
	logs := captureLog(t)
	svc := startOptService(t, relayID, Verbose())

	portA := networkTeardownScenario(t, svc, relayID.X25519Public)

	out := logs.String()
	if !strings.Contains(out, "splice ended") {
		t.Errorf("verbose logs should report the splice error, got:\n%s", out)
	}
	if strings.Contains(out, "127.0.0.1") {
		t.Errorf("verbose logs must not contain full client addresses, got:\n%s", out)
	}
	if strings.Contains(out, ":"+portA) {
		t.Errorf("verbose logs must not contain client ports, got:\n%s", out)
	}
	// The OS renders an RST differently — POSIX reports ECONNRESET as
	// "connection reset by peer" while Windows reports WSAECONNRESET as
	// "forcibly closed by the remote host" — but either way the scrubbed
	// error must keep the underlying cause: scrubbing strips the
	// endpoints, not the diagnosis.
	cause := "connection reset by peer"
	if runtime.GOOS == "windows" {
		cause = "forcibly closed by the remote host"
	}
	if !strings.Contains(out, cause) {
		t.Errorf("the scrubbed error should keep its underlying cause, got:\n%s", out)
	}
}
