// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package e2e_test

import (
	"encoding/hex"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/veldmesh/veld/internal/acl"
	"github.com/veldmesh/veld/internal/crypto"
	"github.com/veldmesh/veld/internal/daemon"
	"github.com/veldmesh/veld/internal/peer"
	"github.com/veldmesh/veld/internal/session"
	"github.com/veldmesh/veld/internal/tun"
)

func buildTCPSYNPacket(src, dst [4]byte, srcPort, dstPort uint16) []byte {
	totalLen := 20 + 20
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45
	pkt[1] = 0x00
	pkt[2] = byte(totalLen >> 8)
	pkt[3] = byte(totalLen)
	pkt[4] = 0x00
	pkt[5] = 0x00
	pkt[6] = 0x00
	pkt[7] = 0x00
	pkt[8] = 64
	pkt[9] = 6
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])
	pkt[20] = byte(srcPort >> 8)
	pkt[21] = byte(srcPort)
	pkt[22] = byte(dstPort >> 8)
	pkt[23] = byte(dstPort)
	pkt[32] = 0x50
	pkt[33] = 0x02
	return pkt
}

// newTestSessionPair creates a pair of linked Noise IK sessions for testing
// using the provided identities. Returns (initiatorSession, responderSession).
func newTestSessionPair(t *testing.T, initiator, responder *crypto.Identity) (*session.Session, *session.Session) {
	t.Helper()

	initiatorHS, _ := crypto.NewInitiatorHS(initiator, responder.X25519Public, [16]byte{})
	responderHS, _ := crypto.NewResponderHS(responder, func(pub []byte) ([32]byte, bool) {
		if string(pub) == string(initiator.Ed25519Public) {
			return initiator.X25519Public, true
		}
		return [32]byte{}, false
	})
	now := time.Now().UnixNano()
	msg1, _ := initiatorHS.BuildMessage1(now)
	_, _ = responderHS.ProcessMessage1(msg1, now)
	msg2, respResult, _ := responderHS.BuildMessage2(now)
	initResult, _ := initiatorHS.ProcessMessage2(msg2, now)
	return session.New(initResult), session.New(respResult)
}

// TestACL_E2E_ThreePeers tests ACL enforcement with three peers:
// - A can reach B on tcp/8080
// - B cannot start connections to A
// - C is outbound-only, can reach B but nothing can reach C
func TestACL_E2E_ThreePeers(t *testing.T) {
	idA, _ := crypto.Generate()
	idB, _ := crypto.Generate()
	idC, _ := crypto.Generate()

	var peerAID, peerBID, peerCID [32]byte
	copy(peerAID[:], idA.Ed25519Public)
	copy(peerBID[:], idB.Ed25519Public)
	copy(peerCID[:], idC.Ed25519Public)

	t.Logf("peerAID: %x", peerAID[:8])
	t.Logf("peerBID: %x", peerBID[:8])
	t.Logf("peerCID: %x", peerCID[:8])

	var networkID [16]byte
	networkID[0] = 0xAC

	connA, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen A: %v", err)
	}
	defer connA.Close()
	connB, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen B: %v", err)
	}
	defer connB.Close()
	connC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen C: %v", err)
	}
	defer connC.Close()

	epA, _ := netip.ParseAddrPort(connA.LocalAddr().String())
	epB, _ := netip.ParseAddrPort(connB.LocalAddr().String())
	epC, _ := netip.ParseAddrPort(connC.LocalAddr().String())

	peerAHex := hex.EncodeToString(peerAID[:])
	peerBHex := hex.EncodeToString(peerBID[:])
	peerCHex := hex.EncodeToString(peerCID[:])

	// Policy A: A can start connections to B on tcp/8080
	policyA := "version = 1\ndefault = \"deny\"\n[peers]\nself = \"ed25519:" + peerAHex + "\"\nbob   = \"ed25519:" + peerBHex + "\"\ncarol = \"ed25519:" + peerCHex + "\"\n[[rule]]\nfrom = \"self\"\nto   = \"bob\"\nports = [\"tcp/8080\"]\n"

	// Policy B: B allows inbound from A and C on tcp/8080
	policyB := "version = 1\ndefault = \"deny\"\n[peers]\nalice = \"ed25519:" + peerAHex + "\"\nself  = \"ed25519:" + peerBHex + "\"\ncarol = \"ed25519:" + peerCHex + "\"\n[[rule]]\nfrom = \"alice\"\nto   = \"self\"\nports = [\"tcp/8080\"]\n[[rule]]\nfrom = \"carol\"\nto   = \"self\"\nports = [\"tcp/8080\"]\n"

	// Policy C: C can start connections to B on tcp/8080, but C is outbound-only
	policyC := "version = 1\ndefault = \"deny\"\n[peers]\nalice = \"ed25519:" + peerAHex + "\"\nbob   = \"ed25519:" + peerBHex + "\"\nself  = \"ed25519:" + peerCHex + "\"\n[[rule]]\nfrom = \"self\"\nto   = \"bob\"\nports = [\"tcp/8080\"]\n[outbound_only]\npeers = [\"self\"]\n"

	sessAB_init, sessAB_resp := newTestSessionPair(t, idA, idB)
	sessAC_init, sessAC_resp := newTestSessionPair(t, idA, idC)
	sessCB_init, sessCB_resp := newTestSessionPair(t, idC, idB)

	tblA := peer.New()
	entryB := makeEntry(idB, "bob", "10.100.0.2", epB)
	entryB.SetSession(sessAB_init)
	tblA.Upsert(entryB)

	entryC := makeEntry(idC, "carol", "10.100.0.3", epC)
	entryC.SetSession(sessAC_init)
	tblA.Upsert(entryC)

	tblB := peer.New()
	entryA := makeEntry(idA, "alice", "10.100.0.1", epA)
	entryA.SetSession(sessAB_resp)
	tblB.Upsert(entryA)

	entryC2 := makeEntry(idC, "carol", "10.100.0.3", epC)
	entryC2.SetSession(sessCB_resp)
	tblB.Upsert(entryC2)

	tblC := peer.New()
	entryA2 := makeEntry(idA, "alice", "10.100.0.1", epA)
	entryA2.SetSession(sessAC_resp)
	tblC.Upsert(entryA2)

	entryB2 := makeEntry(idB, "bob", "10.100.0.2", epB)
	entryB2.SetSession(sessCB_init)
	tblC.Upsert(entryB2)

	tunA := tun.NewMemTUN("tunA", netip.MustParsePrefix("10.100.0.1/24"), 1420)
	tunB := tun.NewMemTUN("tunB", netip.MustParsePrefix("10.100.0.2/24"), 1420)
	tunC := tun.NewMemTUN("tunC", netip.MustParsePrefix("10.100.0.3/24"), 1420)

	dA := daemon.New(idA, networkID, tunA, connA, tblA)
	dB := daemon.New(idB, networkID, tunB, connB, tblB)
	dC := daemon.New(idC, networkID, tunC, connC, tblC)

	pA, _, _ := acl.ParsePolicy(policyA)
	compiledA := pA.Compile()
	dA.SetPolicyDecider(compiledA)
	dA.SetSelfPeerID(peerAID)

	pB, _, _ := acl.ParsePolicy(policyB)
	compiledB := pB.Compile()
	dB.SetPolicyDecider(compiledB)
	dB.SetSelfPeerID(peerBID)

	pC, _, _ := acl.ParsePolicy(policyC)
	compiledC := pC.Compile()
	dC.SetPolicyDecider(compiledC)
	dC.SetSelfPeerID(peerCID)

	dA.Start()
	dB.Start()
	dC.Start()
	defer func() {
		dA.Stop()
		dB.Stop()
		dC.Stop()
		dA.Wait()
		dB.Wait()
		dC.Wait()
	}()

	time.Sleep(2 * time.Second)

	t.Run("A_to_B_8080_allowed", func(t *testing.T) {
		drainMemTUN(tunA)
		drainMemTUN(tunB)
		drainMemTUN(tunC)

		syn := buildTCPSYNPacket([4]byte{10, 100, 0, 1}, [4]byte{10, 100, 0, 2}, 12345, 8080)
		if _, err := tunA.Inject(syn); err != nil {
			t.Fatalf("tunA.Inject: %v", err)
		}

		buf := make([]byte, 1500)
		done := make(chan []byte, 1)
		go func() {
			n, err := tunB.ReadDelivered(buf)
			if err == nil {
				out := make([]byte, n)
				copy(out, buf[:n])
				done <- out
			}
		}()

		select {
		case got := <-done:
			if len(got) < 40 {
				t.Errorf("packet too short: %d", len(got))
			}
			if got[33]&0x02 == 0 {
				t.Errorf("expected SYN packet, got flags=%x", got[33])
			}
		case <-time.After(5 * time.Second):
			t.Fatal("timeout: A→B tcp/8080 packet did not arrive")
		}
	})

	t.Run("B_to_A_denied", func(t *testing.T) {
		drainMemTUN(tunA)
		drainMemTUN(tunB)
		drainMemTUN(tunC)

		syn := buildTCPSYNPacket([4]byte{10, 100, 0, 2}, [4]byte{10, 100, 0, 1}, 12345, 8080)
		if _, err := tunB.Inject(syn); err != nil {
			t.Fatalf("tunB.Inject: %v", err)
		}

		buf := make([]byte, 1500)
		done := make(chan []byte, 1)
		go func() {
			n, err := tunA.ReadDelivered(buf)
			if err == nil {
				out := make([]byte, n)
				copy(out, buf[:n])
				done <- out
			}
		}()

		select {
		case <-done:
			t.Error("B→A should have been denied")
		case <-time.After(500 * time.Millisecond):
		}
	})

	t.Run("C_to_B_8080_allowed", func(t *testing.T) {
		drainMemTUN(tunA)
		drainMemTUN(tunB)
		drainMemTUN(tunC)

		syn := buildTCPSYNPacket([4]byte{10, 100, 0, 3}, [4]byte{10, 100, 0, 2}, 12345, 8080)
		if _, err := tunC.Inject(syn); err != nil {
			t.Fatalf("tunC.Inject: %v", err)
		}

		buf := make([]byte, 1500)
		done := make(chan []byte, 1)
		go func() {
			n, err := tunB.ReadDelivered(buf)
			if err == nil {
				out := make([]byte, n)
				copy(out, buf[:n])
				done <- out
			}
		}()

		select {
		case got := <-done:
			if len(got) < 40 {
				t.Errorf("packet too short: %d", len(got))
			}
			if got[33]&0x02 == 0 {
				t.Errorf("expected SYN packet, got flags=%x", got[33])
			}
		case <-time.After(5 * time.Second):
			t.Fatal("timeout: C→B tcp/8080 packet did not arrive")
		}
	})

	t.Run("A_to_C_denied_outbound_only", func(t *testing.T) {
		drainMemTUN(tunA)
		drainMemTUN(tunB)
		drainMemTUN(tunC)

		syn := buildTCPSYNPacket([4]byte{10, 100, 0, 1}, [4]byte{10, 100, 0, 3}, 12345, 8080)
		if _, err := tunA.Inject(syn); err != nil {
			t.Fatalf("tunA.Inject: %v", err)
		}

		buf := make([]byte, 1500)
		done := make(chan []byte, 1)
		go func() {
			n, err := tunC.ReadDelivered(buf)
			if err == nil {
				out := make([]byte, n)
				copy(out, buf[:n])
				done <- out
			}
		}()

		select {
		case <-done:
			t.Error("A→C should have been denied (C is outbound-only)")
		case <-time.After(500 * time.Millisecond):
		}
	})

	t.Run("B_to_C_denied_outbound_only", func(t *testing.T) {
		drainMemTUN(tunA)
		drainMemTUN(tunB)
		drainMemTUN(tunC)

		syn := buildTCPSYNPacket([4]byte{10, 100, 0, 2}, [4]byte{10, 100, 0, 3}, 12345, 8080)
		if _, err := tunB.Inject(syn); err != nil {
			t.Fatalf("tunB.Inject: %v", err)
		}

		buf := make([]byte, 1500)
		done := make(chan []byte, 1)
		go func() {
			n, err := tunC.ReadDelivered(buf)
			if err == nil {
				out := make([]byte, n)
				copy(out, buf[:n])
				done <- out
			}
		}()

		select {
		case <-done:
			t.Error("B→C should have been denied (C is outbound-only)")
		case <-time.After(500 * time.Millisecond):
		}
	})
}
