// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package nat

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/veldmesh/veld/internal/crypto"
	"github.com/veldmesh/veld/internal/peer"
)

// idOf converts an Ed25519 public key to the [32]byte peer ID form.
func idOf(pub ed25519.PublicKey) [32]byte {
	var id [32]byte
	copy(id[:], pub)
	return id
}

// mustIdentity generates a fresh identity or fatals.
func mustIdentity(t *testing.T) *crypto.Identity {
	t.Helper()
	id, err := crypto.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return id
}

// buildEnvelope produces a version-1 sealed signal carrying jsonPayload,
// claimed to be from "claim", signed by signer for the claim→to pair, and
// encrypted for the recipient's X25519 key.
func buildEnvelope(t *testing.T, jsonPayload []byte, claim, to *crypto.Identity, recipientX25519 [32]byte, signer ed25519.PrivateKey, ts int64) []byte {
	t.Helper()
	enc, err := encryptSignal(jsonPayload, recipientX25519)
	if err != nil {
		t.Fatalf("encryptSignal: %v", err)
	}
	return sealSignal(enc, idOf(claim.Ed25519Public), idOf(to.Ed25519Public), signer, ts)
}

// candidatePayload builds a natSignalMsg whose only candidate is addr.
func candidatePayload(t *testing.T, addr netip.AddrPort) []byte {
	t.Helper()
	msg := natSignalMsg{
		ProbeNonce: "aabbccddeeff0011",
		Candidates: []string{addr.String()},
	}
	payload, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal signal payload: %v", err)
	}
	return payload
}

func TestSealOpenSignal_RoundTrip(t *testing.T) {
	idA := mustIdentity(t)
	idB := mustIdentity(t)
	now := time.Now().Unix()

	envelope := buildEnvelope(t, []byte("hello"), idA, idB, idB.X25519Public, idA.Ed25519Private, now)

	got, err := openSignal(envelope, idOf(idA.Ed25519Public), idOf(idB.Ed25519Public), idA.Ed25519Public, now)
	if err != nil {
		t.Fatalf("openSignal: %v", err)
	}
	plain, err := decryptSignal(got, idB.X25519Private)
	if err != nil {
		t.Fatalf("decryptSignal: %v", err)
	}
	if string(plain) != "hello" {
		t.Errorf("payload mismatch: got %q, want %q", plain, "hello")
	}
}

func TestOpenSignal_RejectsWrongSigner(t *testing.T) {
	idA := mustIdentity(t) // claimed sender
	idB := mustIdentity(t) // recipient
	idM := mustIdentity(t) // Mallory, the actual signer
	now := time.Now().Unix()

	// Envelope claims to come from A but is signed by Mallory.
	envelope := buildEnvelope(t, []byte("forged"), idA, idB, idB.X25519Public, idM.Ed25519Private, now)

	if _, err := openSignal(envelope, idOf(idA.Ed25519Public), idOf(idB.Ed25519Public), idA.Ed25519Public, now); err == nil {
		t.Fatal("openSignal accepted a signal signed by the wrong key")
	}
}

func TestOpenSignal_RejectsTamperedPayload(t *testing.T) {
	idA := mustIdentity(t)
	idB := mustIdentity(t)
	now := time.Now().Unix()

	envelope := buildEnvelope(t, []byte("original"), idA, idB, idB.X25519Public, idA.Ed25519Private, now)

	// Flip a byte in the ciphertext portion.
	tampered := make([]byte, len(envelope))
	copy(tampered, envelope)
	tampered[len(tampered)-1] ^= 0xFF
	if _, err := openSignal(tampered, idOf(idA.Ed25519Public), idOf(idB.Ed25519Public), idA.Ed25519Public, now); err == nil {
		t.Fatal("openSignal accepted a tampered signal")
	}

	// Flip a byte in the signature.
	tampered = make([]byte, len(envelope))
	copy(tampered, envelope)
	tampered[20] ^= 0xFF
	if _, err := openSignal(tampered, idOf(idA.Ed25519Public), idOf(idB.Ed25519Public), idA.Ed25519Public, now); err == nil {
		t.Fatal("openSignal accepted a signal with a tampered signature")
	}
}

func TestOpenSignal_TimestampWindow(t *testing.T) {
	idA := mustIdentity(t)
	idB := mustIdentity(t)
	now := time.Now().Unix()

	from := idOf(idA.Ed25519Public)
	to := idOf(idB.Ed25519Public)

	// Boundary: exactly 60s old / 60s in the future is still valid.
	for _, ts := range []int64{now - signalMaxAgeSec, now + signalMaxSkewSec} {
		envelope := buildEnvelope(t, []byte("fresh enough"), idA, idB, idB.X25519Public, idA.Ed25519Private, ts)
		if _, err := openSignal(envelope, from, to, idA.Ed25519Public, now); err != nil {
			t.Errorf("openSignal rejected timestamp %d (diff %ds): %v", ts, ts-now, err)
		}
	}

	// Stale: older than 60s.
	envelope := buildEnvelope(t, []byte("stale"), idA, idB, idB.X25519Public, idA.Ed25519Private, now-signalMaxAgeSec-1)
	if _, err := openSignal(envelope, from, to, idA.Ed25519Public, now); err == nil {
		t.Fatal("openSignal accepted a stale signal")
	}

	// Replay from the future: more than 60s ahead.
	envelope = buildEnvelope(t, []byte("future"), idA, idB, idB.X25519Public, idA.Ed25519Private, now+signalMaxSkewSec+1)
	if _, err := openSignal(envelope, from, to, idA.Ed25519Public, now); err == nil {
		t.Fatal("openSignal accepted a signal timestamped in the future")
	}
}

func TestOpenSignal_RejectsUnknownVersion(t *testing.T) {
	idA := mustIdentity(t)
	idB := mustIdentity(t)
	now := time.Now().Unix()

	envelope := buildEnvelope(t, []byte("hello"), idA, idB, idB.X25519Public, idA.Ed25519Private, now)

	for _, v := range []byte{0x00, 0x02, 0xFF} {
		bad := make([]byte, len(envelope))
		copy(bad, envelope)
		bad[0] = v
		if _, err := openSignal(bad, idOf(idA.Ed25519Public), idOf(idB.Ed25519Public), idA.Ed25519Public, now); err == nil {
			t.Fatalf("openSignal accepted version byte %#02x", v)
		}
	}
}

func TestOpenSignal_RejectsUnsignedOldFormat(t *testing.T) {
	idA := mustIdentity(t)
	idB := mustIdentity(t)
	now := time.Now().Unix()

	// The pre-signalling format was the bare encrypted blob with no version
	// byte; it must never be accepted, whatever its first byte happens to be.
	for i := 0; i < 32; i++ {
		enc, err := encryptSignal([]byte("old format"), idB.X25519Public)
		if err != nil {
			t.Fatalf("encryptSignal: %v", err)
		}
		if _, err := openSignal(enc, idOf(idA.Ed25519Public), idOf(idB.Ed25519Public), idA.Ed25519Public, now); err == nil {
			t.Fatalf("openSignal accepted an unsigned old-format signal (first byte %#02x)", enc[0])
		}
	}
}

func TestOpenSignal_RejectsSenderKeyMismatch(t *testing.T) {
	idA := mustIdentity(t)
	idB := mustIdentity(t)
	idM := mustIdentity(t)
	now := time.Now().Unix()

	// Valid signature by A over the A→B pair, but the caller resolves the
	// claimed sender to a different registered key (Mallory's).
	envelope := buildEnvelope(t, []byte("hello"), idA, idB, idB.X25519Public, idA.Ed25519Private, now)

	if _, err := openSignal(envelope, idOf(idA.Ed25519Public), idOf(idB.Ed25519Public), idM.Ed25519Public, now); err == nil {
		t.Fatal("openSignal accepted a signal whose claimed sender does not match the registered key")
	}
}

func TestOpenSignal_RejectsShortEnvelope(t *testing.T) {
	idA := mustIdentity(t)
	idB := mustIdentity(t)
	now := time.Now().Unix()

	for _, n := range []int{0, 1, 16, 64, 128} {
		if _, err := openSignal(make([]byte, n), idOf(idA.Ed25519Public), idOf(idB.Ed25519Public), idA.Ed25519Public, now); err == nil {
			t.Fatalf("openSignal accepted a %d-byte envelope", n)
		}
	}
}

// deliveryFixture wires a recipient manager (B) with a live session for a
// known sender (A), plus a UDP "candidate sink": if a delivered signal is
// accepted, its advertised candidates are probed and the sink receives
// TypeNATProbe packets; if it is rejected, nothing arrives.
type deliveryFixture struct {
	idA *crypto.Identity
	// deliver delivers a sealed signal claiming to be from "claim", signed
	// by signer, with timestamp ts.
	deliver func(claim, signer *crypto.Identity, ts int64)
	// expectProbe reports whether a NAT probe reached the sink within the
	// given window.
	expectProbe func(within time.Duration) bool
}

// newDeliveryFixture builds the fixture: the sender A is in the recipient's
// peer table and has an active session.
func newDeliveryFixture(t *testing.T) *deliveryFixture {
	t.Helper()

	idA := mustIdentity(t) // sender
	idB := mustIdentity(t) // recipient (us)

	connB, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	t.Cleanup(func() { connB.Close() })
	portB := connB.LocalAddr().(*net.UDPAddr).Port

	sinkConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket sink: %v", err)
	}
	t.Cleanup(func() { sinkConn.Close() })
	sinkAddr := sinkConn.LocalAddr().(*net.UDPAddr).AddrPort()

	entryA := &peer.Entry{
		ID:        idOf(idA.Ed25519Public),
		X25519Pub: idA.X25519Public,
		VPNAddr:   netip.MustParseAddr("10.0.0.1"),
	}
	tbl := peer.New()
	tbl.Upsert(entryA)

	mgr := New(connB, uint16(portB), "" /*no STUN*/, idB, tbl)

	f := &deliveryFixture{idA: idA}

	f.deliver = func(claim, signer *crypto.Identity, ts int64) {
		envelope := buildEnvelope(t, candidatePayload(t, sinkAddr), claim, idB, idB.X25519Public, signer.Ed25519Private, ts)
		mgr.DeliverSignal(hex.EncodeToString(claim.Ed25519Public), envelope)
	}
	f.expectProbe = func(within time.Duration) bool {
		_ = sinkConn.SetReadDeadline(time.Now().Add(within))
		buf := make([]byte, 64)
		for {
			n, _, err := sinkConn.ReadFrom(buf)
			if err != nil {
				return false // deadline: no probe arrived
			}
			if n >= 4 && buf[0] == 0 && buf[1] == 0 && buf[2] == 0 && buf[3] == 0x05 {
				return true // TypeNATProbe
			}
		}
	}

	// Start the session for A with a no-op send function.
	mgr.Start(context.Background(), entryA, func([]byte) error { return nil })
	return f
}

func TestManager_DeliverSignal_AcceptsValidSignal(t *testing.T) {
	f := newDeliveryFixture(t)

	f.deliver(f.idA, f.idA, time.Now().Unix())

	if !f.expectProbe(2 * time.Second) {
		t.Fatal("valid signal was not delivered: no probe arrived at the advertised candidate")
	}
}

func TestManager_DeliverSignal_RejectsWrongSigner(t *testing.T) {
	f := newDeliveryFixture(t)
	mallory := mustIdentity(t)

	// Claims to be from A (who is in our table) but signed by Mallory.
	f.deliver(f.idA, mallory, time.Now().Unix())

	if f.expectProbe(800 * time.Millisecond) {
		t.Fatal("signal signed by the wrong key was accepted")
	}
}

func TestManager_DeliverSignal_RejectsStaleTimestamp(t *testing.T) {
	f := newDeliveryFixture(t)

	f.deliver(f.idA, f.idA, time.Now().Unix()-120)

	if f.expectProbe(800 * time.Millisecond) {
		t.Fatal("stale signal was accepted")
	}
}

func TestManager_DeliverSignal_RejectsFutureTimestamp(t *testing.T) {
	f := newDeliveryFixture(t)

	f.deliver(f.idA, f.idA, time.Now().Unix()+120)

	if f.expectProbe(800 * time.Millisecond) {
		t.Fatal("future-timestamped signal was accepted")
	}
}

func TestManager_DeliverSignal_RejectsUnknownSender(t *testing.T) {
	f := newDeliveryFixture(t)
	stranger := mustIdentity(t)

	// Correctly signed by the stranger's own key, but the stranger is not
	// in our peer table — coord never told us about this peer.
	f.deliver(stranger, stranger, time.Now().Unix())

	if f.expectProbe(800 * time.Millisecond) {
		t.Fatal("signal from an unknown peer was accepted")
	}
}

func TestManager_DeliverSignal_HoldsAndAuthenticatesPendingSignal(t *testing.T) {
	idA := mustIdentity(t) // sender
	idB := mustIdentity(t) // recipient (us)

	connB, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	t.Cleanup(func() { connB.Close() })
	portB := connB.LocalAddr().(*net.UDPAddr).Port

	sinkConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket sink: %v", err)
	}
	t.Cleanup(func() { sinkConn.Close() })
	sinkAddr := sinkConn.LocalAddr().(*net.UDPAddr).AddrPort()

	entryA := &peer.Entry{
		ID:        idOf(idA.Ed25519Public),
		X25519Pub: idA.X25519Public,
		VPNAddr:   netip.MustParseAddr("10.0.0.1"),
	}
	tbl := peer.New()
	mgr := New(connB, uint16(portB), "", idB, tbl)

	envelope := buildEnvelope(t, candidatePayload(t, sinkAddr), idA, idB, idB.X25519Public, idA.Ed25519Private, time.Now().Unix())

	// The signal arrives before the session exists — it must be held.
	mgr.DeliverSignal(hex.EncodeToString(idA.Ed25519Public), envelope)

	// Now the peer is discovered (registered with coord) and the session
	// starts; the held signal must be authenticated and delivered.
	tbl.Upsert(entryA)
	mgr.Start(context.Background(), entryA, func([]byte) error { return nil })

	_ = sinkConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, _, err := sinkConn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("held signal was not delivered after Start: %v", err)
	}
	if n < 4 || buf[3] != 0x05 {
		t.Fatalf("expected a NAT probe at the sink, got %d bytes: % x", n, buf[:n])
	}
}

func TestManager_DeliverSignal_DropsPendingFromUnknownSender(t *testing.T) {
	idA := mustIdentity(t) // sender that never joins our peer table
	idB := mustIdentity(t) // recipient (us)

	connB, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	t.Cleanup(func() { connB.Close() })
	portB := connB.LocalAddr().(*net.UDPAddr).Port

	sinkConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket sink: %v", err)
	}
	t.Cleanup(func() { sinkConn.Close() })
	sinkAddr := sinkConn.LocalAddr().(*net.UDPAddr).AddrPort()

	entryA := &peer.Entry{
		ID:        idOf(idA.Ed25519Public),
		X25519Pub: idA.X25519Public,
		VPNAddr:   netip.MustParseAddr("10.0.0.1"),
	}
	tbl := peer.New()
	mgr := New(connB, uint16(portB), "", idB, tbl)

	envelope := buildEnvelope(t, candidatePayload(t, sinkAddr), idA, idB, idB.X25519Public, idA.Ed25519Private, time.Now().Unix())

	// Signal arrives before Start and the sender is not in the table.
	mgr.DeliverSignal(hex.EncodeToString(idA.Ed25519Public), envelope)

	// Session starts for the peer, but coord never registered this sender
	// in our peer table — the held signal must be dropped, not delivered.
	mgr.Start(context.Background(), entryA, func([]byte) error { return nil })

	_ = sinkConn.SetReadDeadline(time.Now().Add(800 * time.Millisecond))
	buf := make([]byte, 64)
	if n, _, err := sinkConn.ReadFrom(buf); err == nil {
		t.Fatalf("held signal from unknown sender was accepted: %d bytes: % x", n, buf[:n])
	}
}
