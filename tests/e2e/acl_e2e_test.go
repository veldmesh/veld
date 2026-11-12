// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package e2e_test

import (
	"encoding/binary"
	"encoding/hex"
	"net"
	"net/netip"
	"os"
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

func buildTCPACKPacket(src, dst [4]byte, srcPort, dstPort uint16) []byte {
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
	pkt[33] = 0x10 // ACK flag
	return pkt
}

// buildDataPacket assembles a wire-format UDP payload from a nonce and ciphertext.
// Matches internal/dataplane/packet.go
func buildDataPacket(nonce uint64, ct []byte) []byte {
	buf := make([]byte, 16+len(ct))
	binary.BigEndian.PutUint32(buf[0:4], 0x01) // TypeData
	binary.BigEndian.PutUint32(buf[4:8], 0)    // sender_index: reserved
	binary.BigEndian.PutUint64(buf[8:16], nonce)
	copy(buf[16:], ct)
	return buf
}

// encryptAndSend encrypts a plaintext packet using the session and sends it
// from the sender's UDP socket to the receiver's UDP address.
func encryptAndSend(sess *session.Session, plain []byte, senderConn net.PacketConn, receiverAddr net.Addr) error {
	nonce, ct, err := sess.Encrypt(plain)
	if err != nil {
		return err
	}
	pkt := buildDataPacket(nonce, ct)
	_, err = senderConn.WriteTo(pkt, receiverAddr)
	return err
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

// TestACL_E2E_CombinedLocalNetworkPolicy tests combined local + network policy enforcement.
// A packet passes only if BOTH local and network policies allow it.
// This test simulates a network policy that denies A->B on tcp/8080 while the local policy allows it.
func TestACL_E2E_CombinedLocalNetworkPolicy(t *testing.T) {
	idA, _ := crypto.Generate()
	idB, _ := crypto.Generate()

	var peerAID, peerBID [32]byte
	copy(peerAID[:], idA.Ed25519Public)
	copy(peerBID[:], idB.Ed25519Public)

	t.Logf("peerAID: %x", peerAID[:8])
	t.Logf("peerBID: %x", peerBID[:8])

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

	epA, _ := netip.ParseAddrPort(connA.LocalAddr().String())
	epB, _ := netip.ParseAddrPort(connB.LocalAddr().String())

	peerAHex := hex.EncodeToString(peerAID[:])
	peerBHex := hex.EncodeToString(peerBID[:])

	// Local policy on A: allows A to start connections to B on tcp/8080
	localPolicyA := "version = 1\ndefault = \"deny\"\n[peers]\nself = \"ed25519:" + peerAHex + "\"\nbob   = \"ed25519:" + peerBHex + "\"\n[[rule]]\nfrom = \"self\"\nto   = \"bob\"\nports = [\"tcp/8080\"]\n"

	// Local policy on B: allows inbound from A on tcp/8080
	localPolicyB := "version = 1\ndefault = \"deny\"\n[peers]\nalice = \"ed25519:" + peerAHex + "\"\nself  = \"ed25519:" + peerBHex + "\"\n[[rule]]\nfrom = \"alice\"\nto   = \"self\"\nports = [\"tcp/8080\"]\n"

	// Network policy: denies A->B on tcp/8080 (stricter than local)
	// This network policy will be applied on both peers
	networkPolicyTOML := "version = 2\ndefault = \"deny\"\n[peers]\nalice = \"ed25519:" + peerAHex + "\"\nbob   = \"ed25519:" + peerBHex + "\"\n# No rules allowing alice->bob, so default deny applies\n"

	// Generate admin key for signing network policy
	adminPriv, adminPub, err := acl.GenerateAdminKey()
	if err != nil {
		t.Fatalf("generate admin key: %v", err)
	}
	var adminPubKeyArray [32]byte
	copy(adminPubKeyArray[:], adminPub)

	// Sign the network policy
	networkPolicyEnvelope, err := acl.SignPolicy(networkPolicyTOML, adminPriv)
	if err != nil {
		t.Fatalf("sign network policy: %v", err)
	}

	// Write network policy to temp file
	netPolicyFile := t.TempDir() + "/policy.signed"
	if err := os.WriteFile(netPolicyFile, networkPolicyEnvelope, 0o600); err != nil {
		t.Fatalf("write network policy file: %v", err)
	}

	// Write local policy files
	localPolicyFileA := t.TempDir() + "/policyA.toml"
	if err := os.WriteFile(localPolicyFileA, []byte(localPolicyA), 0o600); err != nil {
		t.Fatalf("write local policy A: %v", err)
	}
	localPolicyFileB := t.TempDir() + "/policyB.toml"
	if err := os.WriteFile(localPolicyFileB, []byte(localPolicyB), 0o600); err != nil {
		t.Fatalf("write local policy B: %v", err)
	}

	sessAB_init, sessAB_resp := newTestSessionPair(t, idA, idB)

	tblA := peer.New()
	entryB := makeEntry(idB, "bob", "10.100.0.2", epB)
	entryB.SetSession(sessAB_init)
	tblA.Upsert(entryB)

	tblB := peer.New()
	entryA := makeEntry(idA, "alice", "10.100.0.1", epA)
	entryA.SetSession(sessAB_resp)
	tblB.Upsert(entryA)

	tunA := tun.NewMemTUN("tunA", netip.MustParsePrefix("10.100.0.1/24"), 1420)
	tunB := tun.NewMemTUN("tunB", netip.MustParsePrefix("10.100.0.2/24"), 1420)

	// Create daemons with both local and network policies
	dA := daemon.New(idA, networkID, tunA, connA, tblA)
	dB := daemon.New(idB, networkID, tunB, connB, tblB)

	// Set up local policy loaders with file paths
	peerLookupA := func(name string) ([32]byte, bool) {
		if name == "self" {
			return peerAID, true
		}
		if e, ok := tblA.LookupByName(name); ok {
			return e.ID, true
		}
		return [32]byte{}, false
	}
	peerLookupB := func(name string) ([32]byte, bool) {
		if name == "self" {
			return peerBID, true
		}
		if e, ok := tblB.LookupByName(name); ok {
			return e.ID, true
		}
		return [32]byte{}, false
	}

	// Use LocalPolicyLoader with network policy swap
	localPolicySwapA := &acl.PolicySwap{}
	localPolicySwapB := &acl.PolicySwap{}
	netPolicySwapA := &acl.PolicySwap{}
	netPolicySwapB := &acl.PolicySwap{}

	localLoaderA := acl.NewLocalPolicyLoader(localPolicyFileA, peerAID, peerLookupA, localPolicySwapA, nil)
	if err := localLoaderA.Load(); err != nil {
		t.Fatalf("load local policy A: %v", err)
	}

	localLoaderB := acl.NewLocalPolicyLoader(localPolicyFileB, peerBID, peerLookupB, localPolicySwapB, nil)
	if err := localLoaderB.Load(); err != nil {
		t.Fatalf("load local policy B: %v", err)
	}

	// Set up network policy loaders
	adminKeys := map[[32]byte]struct{}{adminPubKeyArray: {}}
	netLoaderA := acl.NewNetworkPolicyLoader(netPolicyFile, localPolicyFileA, adminKeys, netPolicySwapA)
	if err := netLoaderA.Load(); err != nil {
		t.Fatalf("load network policy A: %v", err)
	}
	netLoaderB := acl.NewNetworkPolicyLoader(netPolicyFile, localPolicyFileB, adminKeys, netPolicySwapB)
	if err := netLoaderB.Load(); err != nil {
		t.Fatalf("load network policy B: %v", err)
	}

	// Combine local and network policies using the new API
	localLoaderA.SetNetworkPolicy(netPolicySwapA)
	localLoaderB.SetNetworkPolicy(netPolicySwapB)

	dA.SetPolicyDecider(localLoaderA.CombinedPolicy())
	dA.SetSelfPeerID(peerAID)
	dB.SetPolicyDecider(localLoaderB.CombinedPolicy())
	dB.SetSelfPeerID(peerBID)

	dA.Start()
	dB.Start()
	defer func() {
		dA.Stop()
		dB.Stop()
		dA.Wait()
		dB.Wait()
	}()

	time.Sleep(2 * time.Second)

	// Test: A->B on tcp/8080 should be DENIED by network policy even though local allows it
	t.Run("A_to_B_8080_denied_by_network_policy", func(t *testing.T) {
		drainMemTUN(tunA)
		drainMemTUN(tunB)

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
		case <-done:
			t.Error("A→B should have been denied by network policy (local allows but network denies)")
		case <-time.After(500 * time.Millisecond):
			// Expected: packet dropped
		}
	})
}

// TestACL_E2E_NetworkPolicySwapRevokesFlows tests that swapping to a stricter
// network policy cuts established flows that are no longer allowed, while
// allowed flows continue to work.
func TestACL_E2E_NetworkPolicySwapRevokesFlows(t *testing.T) {
	idA, _ := crypto.Generate()
	idB, _ := crypto.Generate()

	var peerAID, peerBID [32]byte
	copy(peerAID[:], idA.Ed25519Public)
	copy(peerBID[:], idB.Ed25519Public)

	t.Logf("peerAID: %x", peerAID[:8])
	t.Logf("peerBID: %x", peerBID[:8])

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

	epA, _ := netip.ParseAddrPort(connA.LocalAddr().String())
	epB, _ := netip.ParseAddrPort(connB.LocalAddr().String())

	peerAHex := hex.EncodeToString(peerAID[:])
	peerBHex := hex.EncodeToString(peerBID[:])

	// Local policy on A: allows A to start connections to B on tcp/8080 and tcp/8081
	localPolicyA := "version = 1\ndefault = \"deny\"\n[peers]\nself = \"ed25519:" + peerAHex + "\"\nbob   = \"ed25519:" + peerBHex + "\"\n[[rule]]\nfrom = \"self\"\nto   = \"bob\"\nports = [\"tcp/8080\", \"tcp/8081\"]\n"

	// Local policy on B: allows inbound from A on tcp/8080 and tcp/8081
	localPolicyB := "version = 1\ndefault = \"deny\"\n[peers]\nalice = \"ed25519:" + peerAHex + "\"\nself  = \"ed25519:" + peerBHex + "\"\n[[rule]]\nfrom = \"alice\"\nto   = \"self\"\nports = [\"tcp/8080\", \"tcp/8081\"]\n"

	// Network policy v1: allows both tcp/8080 and tcp/8081
	networkPolicyV1 := "version = 1\ndefault = \"deny\"\n[peers]\nalice = \"ed25519:" + peerAHex + "\"\nbob   = \"ed25519:" + peerBHex + "\"\n[[rule]]\nfrom = \"alice\"\nto   = \"bob\"\nports = [\"tcp/8080\", \"tcp/8081\"]\n"

	// Network policy v2: allows only tcp/8081 (stricter - removes tcp/8080)
	networkPolicyV2 := "version = 2\ndefault = \"deny\"\n[peers]\nalice = \"ed25519:" + peerAHex + "\"\nbob   = \"ed25519:" + peerBHex + "\"\n[[rule]]\nfrom = \"alice\"\nto   = \"bob\"\nports = [\"tcp/8081\"]\n"

	// Generate admin key for signing network policy
	adminPriv, adminPub, err := acl.GenerateAdminKey()
	if err != nil {
		t.Fatalf("generate admin key: %v", err)
	}
	var adminPubKeyArray [32]byte
	copy(adminPubKeyArray[:], adminPub)

	// Sign network policy v1
	networkPolicyEnvelopeV1, err := acl.SignPolicy(networkPolicyV1, adminPriv)
	if err != nil {
		t.Fatalf("sign network policy v1: %v", err)
	}

	// Write network policy v1 to temp file
	netPolicyFile := t.TempDir() + "/policy.signed"
	if err := os.WriteFile(netPolicyFile, networkPolicyEnvelopeV1, 0o600); err != nil {
		t.Fatalf("write network policy file: %v", err)
	}

	// Write local policy files
	localPolicyFileA := t.TempDir() + "/policyA.toml"
	if err := os.WriteFile(localPolicyFileA, []byte(localPolicyA), 0o600); err != nil {
		t.Fatalf("write local policy A: %v", err)
	}
	localPolicyFileB := t.TempDir() + "/policyB.toml"
	if err := os.WriteFile(localPolicyFileB, []byte(localPolicyB), 0o600); err != nil {
		t.Fatalf("write local policy B: %v", err)
	}

	sessAB_init, sessAB_resp := newTestSessionPair(t, idA, idB)

	tblA := peer.New()
	entryB := makeEntry(idB, "bob", "10.100.0.2", epB)
	entryB.SetSession(sessAB_init)
	tblA.Upsert(entryB)

	tblB := peer.New()
	entryA := makeEntry(idA, "alice", "10.100.0.1", epA)
	entryA.SetSession(sessAB_resp)
	tblB.Upsert(entryA)

	tunA := tun.NewMemTUN("tunA", netip.MustParsePrefix("10.100.0.1/24"), 1420)
	tunB := tun.NewMemTUN("tunB", netip.MustParsePrefix("10.100.0.2/24"), 1420)

	// Create daemons with both local and network policies
	dA := daemon.New(idA, networkID, tunA, connA, tblA)
	dB := daemon.New(idB, networkID, tunB, connB, tblB)

	// Set up local policy loaders
	peerLookupA := func(name string) ([32]byte, bool) {
		if name == "self" {
			return peerAID, true
		}
		if e, ok := tblA.LookupByName(name); ok {
			return e.ID, true
		}
		return [32]byte{}, false
	}
	peerLookupB := func(name string) ([32]byte, bool) {
		if name == "self" {
			return peerBID, true
		}
		if e, ok := tblB.LookupByName(name); ok {
			return e.ID, true
		}
		return [32]byte{}, false
	}

	localPolicySwapA := &acl.PolicySwap{}
	localPolicySwapB := &acl.PolicySwap{}
	netPolicySwapA := &acl.PolicySwap{}
	netPolicySwapB := &acl.PolicySwap{}

	localLoaderA := acl.NewLocalPolicyLoader(localPolicyFileA, peerAID, peerLookupA, localPolicySwapA, nil)
	if err := localLoaderA.Load(); err != nil {
		t.Fatalf("load local policy A: %v", err)
	}

	localLoaderB := acl.NewLocalPolicyLoader(localPolicyFileB, peerBID, peerLookupB, localPolicySwapB, nil)
	if err := localLoaderB.Load(); err != nil {
		t.Fatalf("load local policy B: %v", err)
	}

	// Set up network policy loaders
	adminKeys := map[[32]byte]struct{}{adminPubKeyArray: {}}
	netLoaderA := acl.NewNetworkPolicyLoader(netPolicyFile, localPolicyFileA, adminKeys, netPolicySwapA)
	if err := netLoaderA.Load(); err != nil {
		t.Fatalf("load network policy A: %v", err)
	}
	netLoaderB := acl.NewNetworkPolicyLoader(netPolicyFile, localPolicyFileB, adminKeys, netPolicySwapB)
	if err := netLoaderB.Load(); err != nil {
		t.Fatalf("load network policy B: %v", err)
	}

	// Combine local and network policies
	localLoaderA.SetNetworkPolicy(netPolicySwapA)
	localLoaderB.SetNetworkPolicy(netPolicySwapB)

	dA.SetPolicyDecider(localLoaderA.CombinedPolicy())
	dA.SetSelfPeerID(peerAID)
	dB.SetPolicyDecider(localLoaderB.CombinedPolicy())
	dB.SetSelfPeerID(peerBID)

	dA.Start()
	dB.Start()
	defer func() {
		dA.Stop()
		dB.Stop()
		dA.Wait()
		dB.Wait()
	}()

	time.Sleep(2 * time.Second)

	// Establish two flows: A->B on tcp/8080 and A->B on tcp/8081
	// Both should be allowed under network policy v1

	// Establish flow on tcp/8080 (will be revoked)
	drainMemTUN(tunA)
	drainMemTUN(tunB)

	syn8080 := buildTCPSYNPacket([4]byte{10, 100, 0, 1}, [4]byte{10, 100, 0, 2}, 12345, 8080)
	if _, err := tunA.Inject(syn8080); err != nil {
		t.Fatalf("tunA.Inject syn8080: %v", err)
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
		if len(got) < 40 || got[33]&0x02 == 0 {
			t.Fatalf("expected SYN packet on 8080, got len=%d flags=%x", len(got), got[33])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout: initial A→B tcp/8080 did not arrive")
	}

	// Establish flow on tcp/8081 (will remain allowed)
	drainMemTUN(tunA)
	drainMemTUN(tunB)

	syn8081 := buildTCPSYNPacket([4]byte{10, 100, 0, 1}, [4]byte{10, 100, 0, 2}, 12346, 8081)
	if _, err := tunA.Inject(syn8081); err != nil {
		t.Fatalf("tunA.Inject syn8081: %v", err)
	}

	done = make(chan []byte, 1)
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
		if len(got) < 40 || got[33]&0x02 == 0 {
			t.Fatalf("expected SYN packet on 8081, got len=%d flags=%x", len(got), got[33])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout: initial A→B tcp/8081 did not arrive")
	}

	// Now swap to network policy v2 (denies tcp/8080, allows tcp/8081)
	networkPolicyEnvelopeV2, err := acl.SignPolicy(networkPolicyV2, adminPriv)
	if err != nil {
		t.Fatalf("sign network policy v2: %v", err)
	}

	// Write new policy to file (simulates network policy update)
	if err := os.WriteFile(netPolicyFile, networkPolicyEnvelopeV2, 0o600); err != nil {
		t.Fatalf("write network policy v2: %v", err)
	}

	// Trigger reload
	if err := netLoaderA.Reload(); err != nil {
		t.Fatalf("reload network policy A: %v", err)
	}
	if err := netLoaderB.Reload(); err != nil {
		t.Fatalf("reload network policy B: %v", err)
	}

	// Wait for reload to propagate
	time.Sleep(500 * time.Millisecond)

	// Now test: A->B on tcp/8080 should be DENIED (flow revoked)
	// Send a TCP ACK on the established 8080 flow - should be dropped now
	drainMemTUN(tunA)
	drainMemTUN(tunB)

	ack8080 := buildTCPACKPacket([4]byte{10, 100, 0, 1}, [4]byte{10, 100, 0, 2}, 12345, 8080)
	if _, err := tunA.Inject(ack8080); err != nil {
		t.Fatalf("tunA.Inject ack8080: %v", err)
	}

	select {
	case <-done:
		t.Error("A→B tcp/8080 should have been denied after policy swap (flow revoked)")
	case <-time.After(500 * time.Millisecond):
		// Expected: packet dropped
	}

	// But A->B on tcp/8081 should STILL WORK (flow still allowed)
	drainMemTUN(tunA)
	drainMemTUN(tunB)

	ack8081 := buildTCPACKPacket([4]byte{10, 100, 0, 1}, [4]byte{10, 100, 0, 2}, 12346, 8081)
	if _, err := tunA.Inject(ack8081); err != nil {
		t.Fatalf("tunA.Inject ack8081: %v", err)
	}

	done = make(chan []byte, 1)
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
			t.Errorf("packet too short on 8081: %d", len(got))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout: A→B tcp/8081 should still work after policy swap")
	}
}

// TestACL_E2E_ReplyToOutbound_AfterNetworkPolicySwap tests that replies to an
// outbound connection (initiated by A) are allowed before a network policy swap
// but dropped after swapping to a stricter network policy.
//
// Scenario:
//  1. A's SYN to B:8080 is delivered (establishes flow)
//  2. B sends reply B:8080 -> A:ephemeral; it MUST reach A (before swap)
//     This is simulated by encrypting with B's session (sessAB_resp) and sending from B's socket (connB) to A's address.
//  3. Swap to network policy v2 allowing only tcp/8081 (stricter - removes tcp/8080)
//  4. B sends another reply B:8080 -> A:ephemeral; it must NOT reach A after swap
func TestACL_E2E_ReplyToOutbound_AfterNetworkPolicySwap(t *testing.T) {
	idA, _ := crypto.Generate()
	idB, _ := crypto.Generate()

	var peerAID, peerBID [32]byte
	copy(peerAID[:], idA.Ed25519Public)
	copy(peerBID[:], idB.Ed25519Public)

	t.Logf("peerAID: %x", peerAID[:8])
	t.Logf("peerBID: %x", peerBID[:8])

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

	epA, _ := netip.ParseAddrPort(connA.LocalAddr().String())
	epB, _ := netip.ParseAddrPort(connB.LocalAddr().String())

	peerAHex := hex.EncodeToString(peerAID[:])
	peerBHex := hex.EncodeToString(peerBID[:])

	// Local policy on A: allows A to start connections to B on tcp/8080 and tcp/8081
	localPolicyA := "version = 1\ndefault = \"deny\"\n[peers]\nself = \"ed25519:" + peerAHex + "\"\nbob   = \"ed25519:" + peerBHex + "\"\n[[rule]]\nfrom = \"self\"\nto   = \"bob\"\nports = [\"tcp/8080\", \"tcp/8081\"]\n"

	// Local policy on B: allows inbound from A on tcp/8080 and tcp/8081
	localPolicyB := "version = 1\ndefault = \"deny\"\n[peers]\nalice = \"ed25519:" + peerAHex + "\"\nself  = \"ed25519:" + peerBHex + "\"\n[[rule]]\nfrom = \"alice\"\nto   = \"self\"\nports = [\"tcp/8080\", \"tcp/8081\"]\n"

	// Network policy v1: allows both tcp/8080 and tcp/8081
	networkPolicyV1 := "version = 1\ndefault = \"deny\"\n[peers]\nalice = \"ed25519:" + peerAHex + "\"\nbob   = \"ed25519:" + peerBHex + "\"\n[[rule]]\nfrom = \"alice\"\nto   = \"bob\"\nports = [\"tcp/8080\", \"tcp/8081\"]\n"

	// Network policy v2: allows only tcp/8081 (stricter - removes tcp/8080)
	networkPolicyV2 := "version = 2\ndefault = \"deny\"\n[peers]\nalice = \"ed25519:" + peerAHex + "\"\nbob   = \"ed25519:" + peerBHex + "\"\n[[rule]]\nfrom = \"alice\"\nto   = \"bob\"\nports = [\"tcp/8081\"]\n"

	// Generate admin key for signing network policy
	adminPriv, adminPub, err := acl.GenerateAdminKey()
	if err != nil {
		t.Fatalf("generate admin key: %v", err)
	}
	var adminPubKeyArray [32]byte
	copy(adminPubKeyArray[:], adminPub)

	// Sign network policy v1
	networkPolicyEnvelopeV1, err := acl.SignPolicy(networkPolicyV1, adminPriv)
	if err != nil {
		t.Fatalf("sign network policy v1: %v", err)
	}

	// Write network policy v1 to temp file
	netPolicyFile := t.TempDir() + "/policy.signed"
	if err := os.WriteFile(netPolicyFile, networkPolicyEnvelopeV1, 0o600); err != nil {
		t.Fatalf("write network policy file: %v", err)
	}

	// Write local policy files
	localPolicyFileA := t.TempDir() + "/policyA.toml"
	if err := os.WriteFile(localPolicyFileA, []byte(localPolicyA), 0o600); err != nil {
		t.Fatalf("write local policy A: %v", err)
	}
	localPolicyFileB := t.TempDir() + "/policyB.toml"
	if err := os.WriteFile(localPolicyFileB, []byte(localPolicyB), 0o600); err != nil {
		t.Fatalf("write local policy B: %v", err)
	}

	sessAB_init, sessAB_resp := newTestSessionPair(t, idA, idB)

	tblA := peer.New()
	entryB := makeEntry(idB, "bob", "10.100.0.2", epB)
	entryB.SetSession(sessAB_init)
	tblA.Upsert(entryB)

	tblB := peer.New()
	entryA := makeEntry(idA, "alice", "10.100.0.1", epA)
	entryA.SetSession(sessAB_resp)
	tblB.Upsert(entryA)

	tunA := tun.NewMemTUN("tunA", netip.MustParsePrefix("10.100.0.1/24"), 1420)
	tunB := tun.NewMemTUN("tunB", netip.MustParsePrefix("10.100.0.2/24"), 1420)

	// Create daemons with both local and network policies
	dA := daemon.New(idA, networkID, tunA, connA, tblA)
	dB := daemon.New(idB, networkID, tunB, connB, tblB)

	// Set up local policy loaders
	peerLookupA := func(name string) ([32]byte, bool) {
		if name == "self" {
			return peerAID, true
		}
		if e, ok := tblA.LookupByName(name); ok {
			return e.ID, true
		}
		return [32]byte{}, false
	}
	peerLookupB := func(name string) ([32]byte, bool) {
		if name == "self" {
			return peerBID, true
		}
		if e, ok := tblB.LookupByName(name); ok {
			return e.ID, true
		}
		return [32]byte{}, false
	}

	localPolicySwapA := &acl.PolicySwap{}
	localPolicySwapB := &acl.PolicySwap{}
	netPolicySwapA := &acl.PolicySwap{}
	netPolicySwapB := &acl.PolicySwap{}

	localLoaderA := acl.NewLocalPolicyLoader(localPolicyFileA, peerAID, peerLookupA, localPolicySwapA, nil)
	if err := localLoaderA.Load(); err != nil {
		t.Fatalf("load local policy A: %v", err)
	}

	localLoaderB := acl.NewLocalPolicyLoader(localPolicyFileB, peerBID, peerLookupB, localPolicySwapB, nil)
	if err := localLoaderB.Load(); err != nil {
		t.Fatalf("load local policy B: %v", err)
	}

	// Set up network policy loaders
	adminKeys := map[[32]byte]struct{}{adminPubKeyArray: {}}
	netLoaderA := acl.NewNetworkPolicyLoader(netPolicyFile, localPolicyFileA, adminKeys, netPolicySwapA)
	if err := netLoaderA.Load(); err != nil {
		t.Fatalf("load network policy A: %v", err)
	}
	netLoaderB := acl.NewNetworkPolicyLoader(netPolicyFile, localPolicyFileB, adminKeys, netPolicySwapB)
	if err := netLoaderB.Load(); err != nil {
		t.Fatalf("load network policy B: %v", err)
	}

	// Combine local and network policies
	localLoaderA.SetNetworkPolicy(netPolicySwapA)
	localLoaderB.SetNetworkPolicy(netPolicySwapB)

	dA.SetPolicyDecider(localLoaderA.CombinedPolicy())
	dA.SetSelfPeerID(peerAID)
	dB.SetPolicyDecider(localLoaderB.CombinedPolicy())
	dB.SetSelfPeerID(peerBID)

	dA.Start()
	dB.Start()
	defer func() {
		dA.Stop()
		dB.Stop()
		dA.Wait()
		dB.Wait()
	}()

	time.Sleep(2 * time.Second)

	// Step 1: A's SYN to B:8080 is delivered (establishes flow)
	drainMemTUN(tunA)
	drainMemTUN(tunB)

	syn := buildTCPSYNPacket([4]byte{10, 100, 0, 1}, [4]byte{10, 100, 0, 2}, 12345, 8080)
	if _, err := tunA.Inject(syn); err != nil {
		t.Fatalf("tunA.Inject SYN: %v", err)
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
		if len(got) < 40 || got[33]&0x02 == 0 {
			t.Fatalf("expected SYN packet, got len=%d flags=%x", len(got), got[33])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout: initial A→B tcp/8080 SYN did not arrive")
	}

	// Step 2: B sends reply B:8080 -> A:12345 (SYN-ACK); it MUST reach A before swap
	// Simulate by encrypting with B's session (sessAB_resp) and sending from B's socket (connB) to A's address.
	drainMemTUN(tunA)
	drainMemTUN(tunB)

	synack := buildTCPSYNACKPacket(
		[4]byte{10, 100, 0, 2}, // src (B)
		[4]byte{10, 100, 0, 1}, // dst (A)
		8080,                   // src port (B's service port)
		12345,                  // dst port (A's ephemeral port)
	)
	if err := encryptAndSend(sessAB_resp, synack, connB, connA.LocalAddr()); err != nil {
		t.Fatalf("encryptAndSend SYN-ACK: %v", err)
	}

	done = make(chan []byte, 1)
	go func() {
		n, err := tunA.ReadDelivered(buf)
		if err == nil {
			out := make([]byte, n)
			copy(out, buf[:n])
			done <- out
		}
	}()

	select {
	case got := <-done:
		if len(got) < 40 {
			t.Errorf("SYN-ACK packet too short: %d", len(got))
		}
		// Verify it's a SYN-ACK (flags = SYN|ACK = 0x12)
		if got[33]&0x12 != 0x12 {
			t.Errorf("expected SYN-ACK flags, got %x", got[33])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout: B→A SYN-ACK (reply to outbound) should arrive BEFORE swap")
	}

	// Step 3: Swap to network policy v2 (denies tcp/8080, allows tcp/8081)
	networkPolicyEnvelopeV2, err := acl.SignPolicy(networkPolicyV2, adminPriv)
	if err != nil {
		t.Fatalf("sign network policy v2: %v", err)
	}

	if err := os.WriteFile(netPolicyFile, networkPolicyEnvelopeV2, 0o600); err != nil {
		t.Fatalf("write network policy v2: %v", err)
	}

	if err := netLoaderA.Reload(); err != nil {
		t.Fatalf("reload network policy A: %v", err)
	}
	if err := netLoaderB.Reload(); err != nil {
		t.Fatalf("reload network policy B: %v", err)
	}

	// Wait for reload to propagate
	time.Sleep(500 * time.Millisecond)

	// Step 4: B sends another reply B:8080 -> A:12345 (data/ACK); it must NOT reach A after swap
	drainMemTUN(tunA)
	drainMemTUN(tunB)

	dataAck := buildTCPACKPacket(
		[4]byte{10, 100, 0, 2}, // src (B)
		[4]byte{10, 100, 0, 1}, // dst (A)
		8080,                   // src port (B's service port)
		12345,                  // dst port (A's ephemeral port)
	)
	if err := encryptAndSend(sessAB_resp, dataAck, connB, connA.LocalAddr()); err != nil {
		t.Fatalf("encryptAndSend data/ACK: %v", err)
	}

	done = make(chan []byte, 1)
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
		t.Error("B→A data/ACK on tcp/8080 should have been denied after policy swap (flow revoked)")
	case <-time.After(500 * time.Millisecond):
		// Expected: packet dropped
	}

	// Verify that a new connection on tcp/8081 still works after swap
	drainMemTUN(tunA)
	drainMemTUN(tunB)

	newSyn8081 := buildTCPSYNPacket([4]byte{10, 100, 0, 1}, [4]byte{10, 100, 0, 2}, 12347, 8081)
	if _, err := tunA.Inject(newSyn8081); err != nil {
		t.Fatalf("tunA.Inject new SYN on 8081: %v", err)
	}

	done = make(chan []byte, 1)
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
		if len(got) < 40 || got[33]&0x02 == 0 {
			t.Fatalf("expected SYN packet on 8081, got len=%d flags=%x", len(got), got[33])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout: new A→B tcp/8081 should work after policy swap")
	}
}

// buildTCPSYNACKPacket builds a minimal IPv4 TCP SYN-ACK packet.
func buildTCPSYNACKPacket(src, dst [4]byte, srcPort, dstPort uint16) []byte {
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
	pkt[9] = 6 // TCP
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])
	pkt[20] = byte(srcPort >> 8)
	pkt[21] = byte(srcPort)
	pkt[22] = byte(dstPort >> 8)
	pkt[23] = byte(dstPort)
	pkt[24] = 0
	pkt[25] = 0
	pkt[26] = 0
	pkt[27] = 0
	pkt[28] = 0
	pkt[29] = 0
	pkt[30] = 0
	pkt[31] = 0
	pkt[32] = 0x50
	pkt[33] = 0x12 // SYN|ACK
	return pkt
}
