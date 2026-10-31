// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package nat

import (
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"
)

// recordConn records the packets written to it.
type recordConn struct {
	net.PacketConn
	sent chan []byte
}

func (c *recordConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	c.sent <- append([]byte(nil), p...)
	return len(p), nil
}

func udp(s string) *net.UDPAddr { return net.UDPAddrFromAddrPort(netip.MustParseAddrPort(s)) }

// testSession registers a session that has received the peer's signal:
// our nonce 1..., the peer's nonce 2..., one candidate.
func testSession(m *Manager, candidate string) *natSession {
	sess := &natSession{
		probeNonce: [8]byte{1, 1, 1, 1, 1, 1, 1, 1},
		peerNonce:  [8]byte{2, 2, 2, 2, 2, 2, 2, 2},
		havePeer:   true,
		remotes:    map[netip.AddrPort]bool{netip.MustParseAddrPort(candidate): true},
		result:     make(chan netip.AddrPort, 1),
	}
	m.mu.Lock()
	m.sessions[[32]byte{9}] = sess
	m.answers[sess.peerNonce] = probeAnswer{tag: replyTag(sess.peerNonce, sess.probeNonce), expires: time.Now().Add(answerTTL)}
	m.mu.Unlock()
	return sess
}

func TestProbeReplyMustBeAuthentic(t *testing.T) {
	m := New(&recordConn{sent: make(chan []byte, 4)}, 0, "", nil, nil)
	sess := testSession(m, "203.0.113.5:4000")
	good := replyTag(sess.probeNonce, sess.peerNonce)

	// An echo of our cleartext nonce (what anyone who saw the probe can
	// send) is not a valid reply, even from the candidate address.
	m.HandleProbe(buildProbe(replyFlag, sess.probeNonce), udp("203.0.113.5:4000"))
	// A valid tag from an address we never probed is ignored too.
	m.HandleProbe(buildProbe(replyFlag, good), udp("198.51.100.66:4444"))
	select {
	case ep := <-sess.result:
		t.Fatalf("forged reply accepted: %v", ep)
	default:
	}

	m.HandleProbe(buildProbe(replyFlag, good), udp("203.0.113.5:4000"))
	select {
	case ep := <-sess.result:
		if ep != netip.MustParseAddrPort("203.0.113.5:4000") {
			t.Errorf("got %v", ep)
		}
	default:
		t.Fatal("valid reply not accepted")
	}
}

func TestProbeAnsweredOnlyForKnownNonce(t *testing.T) {
	conn := &recordConn{sent: make(chan []byte, 4)}
	m := New(conn, 0, "", nil, nil)
	sess := testSession(m, "203.0.113.5:4000")

	// A probe with an unknown nonce (a spoofed source, a scanner) gets no
	// reply.
	m.HandleProbe(buildProbe(probeFlag, [8]byte{7}), udp("192.0.2.1:9"))
	select {
	case p := <-conn.sent:
		t.Fatalf("answered an unknown probe: %x", p)
	default:
	}

	// The peer's probe gets the tag over both nonces.
	m.HandleProbe(buildProbe(probeFlag, sess.peerNonce), udp("203.0.113.5:4000"))
	select {
	case p := <-conn.sent:
		var tag [8]byte
		copy(tag[:], p[8:16])
		if tag != replyTag(sess.peerNonce, sess.probeNonce) {
			t.Errorf("reply tag %x", tag)
		}
	default:
		t.Fatal("peer probe not answered")
	}

	// Answers outlive the session (the peer may still be probing).
	m.mu.Lock()
	delete(m.sessions, [32]byte{9})
	m.mu.Unlock()
	m.HandleProbe(buildProbe(probeFlag, sess.peerNonce), udp("203.0.113.5:4000"))
	select {
	case <-conn.sent:
	default:
		t.Fatal("probe not answered after the session ended")
	}
}

func TestUsableCandidates(t *testing.T) {
	in := []string{"192.0.2.1:5", "192.0.2.1:5", "0.0.0.0:5", "192.0.2.2:0",
		"224.0.0.1:5", "255.255.255.255:5", "not-an-addr", "[::ffff:192.0.2.3]:5"}
	got := usableCandidates(in)
	want := []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:5"), netip.MustParseAddrPort("192.0.2.3:5")}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("got %v, want %v", got, want)
	}

	var many []string
	for i := 0; i < 1000; i++ {
		many = append(many, fmt.Sprintf("192.0.2.%d:%d", i%250+1, 1000+i))
	}
	if n := len(usableCandidates(many)); n != maxCandidates {
		t.Errorf("kept %d candidates, want %d", n, maxCandidates)
	}
}
