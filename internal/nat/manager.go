// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT

// Package nat implements NAT hole-punching for Veld peers.
//
// Flow:
//  1. When a peer is discovered via coord (OnPeerAdded), call Manager.Start.
//  2. The manager gathers local candidates (host IPs + optional STUN).
//  3. Candidates are JSON-marshalled, encrypted for the peer's X25519 key,
//     and sent via coord SendSignal — the coord server cannot read them.
//  4. The peer does the same concurrently.
//  5. Upon receiving the peer's signal, each side sends UDP TypeNATProbe
//     packets (via the shared data-plane conn) to every remote candidate.
//  6. When a probe is received, a reply is sent. When a reply is received,
//     OnEndpointDiscovered is called with the validated remote AddrPort.
//  7. The daemon wires OnEndpointDiscovered → peer table update → handshake.
package nat

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/veldmesh/veld/internal/crypto"
	"github.com/veldmesh/veld/internal/peer"
)

const (
	probeTimeout      = 10 * time.Second
	probeSendInterval = 100 * time.Millisecond
	probeFlag         = uint32(0) // outgoing probe
	replyFlag         = uint32(1) // probe reply
)

// Manager handles NAT hole-punch negotiation for all active peer pairs.
// One Manager is created per daemon and shared across all peers.
type Manager struct {
	conn       net.PacketConn
	localPort  uint16
	stunServer string // empty → skip STUN, host candidates only
	identity   *crypto.Identity

	// OnEndpointDiscovered is called when a reachable endpoint is confirmed
	// for a peer. The caller should update the peer table and initiate a
	// Noise handshake. Called at most once per Start invocation.
	OnEndpointDiscovered func(peerID [32]byte, ep netip.AddrPort)

	mu      sync.Mutex
	sessions map[[32]byte]*natSession
	// pending holds encrypted signal payloads that arrived before the session
	// for that peer was created. Keyed by sender peer ID.
	pending  map[[32]byte][]byte
}

type natSession struct {
	peerID     [32]byte
	peerX25519 [32]byte
	sendFn     func([]byte) error

	probeNonce [8]byte        // random nonce identifies our probes
	signalIn   chan []byte     // receives decrypted peer signal payloads
	result     chan netip.AddrPort // receives the winning endpoint

	cancel context.CancelFunc
}

// natSignalMsg is the JSON payload exchanged between peers via coord signals.
type natSignalMsg struct {
	ProbeNonce string   `json:"probe_nonce"` // hex-encoded 8 bytes
	Candidates []string `json:"candidates"`  // "ip:port" strings
}

// New creates a Manager. conn is the shared data-plane UDP connection.
// localPort must match the port that conn is listening on.
// stunServer is a "host:port" STUN server address; empty string disables STUN.
func New(conn net.PacketConn, localPort uint16, stunServer string, identity *crypto.Identity) *Manager {
	return &Manager{
		conn:       conn,
		localPort:  localPort,
		stunServer: stunServer,
		identity:   identity,
		sessions:   make(map[[32]byte]*natSession),
		pending:    make(map[[32]byte][]byte),
	}
}

// Start begins NAT negotiation for entry.
// sendFn must call coord SendSignal with the provided encrypted payload,
// addressed to entry's peer ID.
// Returns immediately; negotiation runs in the background.
// Calling Start for a peer that already has an active session is a no-op.
func (m *Manager) Start(ctx context.Context, e *peer.Entry, sendFn func([]byte) error) {
	m.mu.Lock()
	if _, exists := m.sessions[e.ID]; exists {
		m.mu.Unlock()
		return
	}

	var nonce [8]byte
	rand.Read(nonce[:])

	sessCtx, cancel := context.WithTimeout(ctx, probeTimeout+5*time.Second)
	sess := &natSession{
		peerID:     e.ID,
		peerX25519: e.X25519Pub,
		sendFn:     sendFn,
		probeNonce: nonce,
		signalIn:   make(chan []byte, 4),
		result:     make(chan netip.AddrPort, 1),
		cancel:     cancel,
	}
	m.sessions[e.ID] = sess

	// Drain any signal that arrived before this session was created.
	var buffered []byte
	if enc, ok := m.pending[e.ID]; ok {
		buffered = enc
		delete(m.pending, e.ID)
	}
	m.mu.Unlock()

	if buffered != nil {
		if plain, err := decryptSignal(buffered, m.identity.X25519Private); err == nil {
			select {
			case sess.signalIn <- plain:
			default:
			}
		}
	}

	go m.negotiate(sessCtx, sess)
}

// DeliverSignal is called by the coord client's OnSignal callback.
// It decrypts the payload and routes it to the matching peer session.
// If no session exists yet for this peer, the encrypted payload is pre-buffered
// and delivered when Start is called for that peer.
func (m *Manager) DeliverSignal(fromPeerID string, encPayload []byte) {
	id, ok := hexToNatID(fromPeerID)
	if !ok {
		return
	}

	m.mu.Lock()
	sess, hasSess := m.sessions[id]
	if !hasSess {
		// Pre-buffer: session will pick this up when Start is called.
		m.pending[id] = encPayload
		m.mu.Unlock()
		return
	}
	m.mu.Unlock()

	plain, err := decryptSignal(encPayload, m.identity.X25519Private)
	if err != nil {
		return
	}
	select {
	case sess.signalIn <- plain:
	default:
	}
}

// HandleProbe is called by the dispatcher's OnNATProbePacket callback.
// pkt is the full 16-byte wire packet; addr is the sender.
func (m *Manager) HandleProbe(pkt []byte, addr net.Addr) {
	if len(pkt) < 16 {
		return
	}
	flags := binary.BigEndian.Uint32(pkt[4:8])
	var nonce [8]byte
	copy(nonce[:], pkt[8:16])

	if flags == probeFlag {
		// Incoming probe — reply immediately with the same nonce.
		reply := buildProbe(replyFlag, nonce)
		m.conn.WriteTo(reply, addr) //nolint:errcheck
		return
	}

	// Reply to one of our probes — find the matching session.
	ep, ok := addrToAddrPort(addr)
	if !ok {
		return
	}
	m.mu.Lock()
	for _, sess := range m.sessions {
		if sess.probeNonce == nonce {
			select {
			case sess.result <- ep:
			default:
			}
			break
		}
	}
	m.mu.Unlock()
}

func (m *Manager) negotiate(ctx context.Context, sess *natSession) {
	defer func() {
		sess.cancel()
		m.mu.Lock()
		delete(m.sessions, sess.peerID)
		m.mu.Unlock()
	}()

	// Gather local candidates.
	candidates := m.gatherCandidates(ctx)
	if len(candidates) == 0 {
		return
	}

	// Build and send our signal.
	msg := natSignalMsg{
		ProbeNonce: hex.EncodeToString(sess.probeNonce[:]),
		Candidates: make([]string, len(candidates)),
	}
	for i, c := range candidates {
		msg.Candidates[i] = c.String()
	}
	jsonPayload, err := json.Marshal(msg)
	if err != nil {
		return
	}
	enc, err := encryptSignal(jsonPayload, sess.peerX25519)
	if err != nil {
		return
	}
	if err := sess.sendFn(enc); err != nil {
		return
	}

	// Wait for the peer's signal.
	var peerMsg natSignalMsg
	select {
	case <-ctx.Done():
		return
	case plain := <-sess.signalIn:
		if err := json.Unmarshal(plain, &peerMsg); err != nil {
			return
		}
	}

	// Parse the peer's probe nonce and candidates.
	peerNonceBytes, err := hex.DecodeString(peerMsg.ProbeNonce)
	if err != nil || len(peerNonceBytes) != 8 {
		return
	}
	var peerNonce [8]byte
	copy(peerNonce[:], peerNonceBytes)

	var remotes []netip.AddrPort
	for _, s := range peerMsg.Candidates {
		if ep, err := netip.ParseAddrPort(s); err == nil {
			remotes = append(remotes, ep)
		}
	}
	if len(remotes) == 0 {
		return
	}

	// Probe all remote candidates simultaneously.
	// We also need to reply to the peer's probes (done by HandleProbe).
	probeCtx, probeCancel := context.WithTimeout(ctx, probeTimeout)
	defer probeCancel()

	probe := buildProbe(probeFlag, sess.probeNonce)
	for _, ep := range remotes {
		go func(target netip.AddrPort) {
			ticker := time.NewTicker(probeSendInterval)
			defer ticker.Stop()
			for {
				select {
				case <-probeCtx.Done():
					return
				case <-ticker.C:
					m.conn.WriteTo(probe, net.UDPAddrFromAddrPort(target)) //nolint:errcheck
				}
			}
		}(ep)
	}

	// Wait for a successful reply (delivered by HandleProbe).
	select {
	case <-probeCtx.Done():
		return
	case ep := <-sess.result:
		if m.OnEndpointDiscovered != nil {
			m.OnEndpointDiscovered(sess.peerID, ep)
		}
	}
}

// gatherCandidates returns all candidate endpoints this node can be reached at.
func (m *Manager) gatherCandidates(ctx context.Context) []netip.AddrPort {
	seen := make(map[netip.AddrPort]bool)
	var candidates []netip.AddrPort

	add := func(ep netip.AddrPort) {
		if ep.IsValid() && !seen[ep] {
			seen[ep] = true
			candidates = append(candidates, ep)
		}
	}

	// Primary: use the conn's own bound address if it's not 0.0.0.0.
	// This covers the common case where the conn is bound to a specific interface
	// or to the loopback address (tests).
	if laddr, ok := m.conn.LocalAddr().(*net.UDPAddr); ok {
		if ip, ok2 := netip.AddrFromSlice(laddr.IP); ok2 {
			ip = ip.Unmap()
			if ip.IsValid() && !ip.IsUnspecified() {
				add(netip.AddrPortFrom(ip, m.localPort))
			}
		}
	}

	// Host candidates: all non-loopback local IPs + the data-plane port.
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, a := range addrs {
				var ip netip.Addr
				switch v := a.(type) {
				case *net.IPNet:
					if addr, ok := netip.AddrFromSlice(v.IP); ok {
						ip = addr.Unmap()
					}
				case *net.IPAddr:
					if addr, ok := netip.AddrFromSlice(v.IP); ok {
						ip = addr.Unmap()
					}
				}
				if ip.IsValid() && !ip.IsLoopback() && ip.Is4() {
					add(netip.AddrPortFrom(ip, m.localPort))
				}
			}
		}
	}

	// Fallback: if still no candidates, use loopback.
	if len(candidates) == 0 {
		add(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), m.localPort))
	}

	// Server-reflexive candidate via STUN (optional).
	if m.stunServer != "" {
		stunCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		if srflx, err := QuerySTUN(stunCtx, m.stunServer); err == nil {
			// Combine the external IP from STUN with our local data-plane port.
			// Correct for full-cone and address-restricted cone NATs.
			add(netip.AddrPortFrom(srflx.Addr(), m.localPort))
		}
	}

	return candidates
}

// buildProbe assembles a 16-byte TypeNATProbe wire packet.
func buildProbe(flags uint32, nonce [8]byte) []byte {
	pkt := make([]byte, 16)
	binary.BigEndian.PutUint32(pkt[0:4], 0x05) // TypeNATProbe
	binary.BigEndian.PutUint32(pkt[4:8], flags)
	copy(pkt[8:16], nonce[:])
	return pkt
}

// addrToAddrPort converts a net.Addr to netip.AddrPort, normalising
// IPv4-mapped IPv6 addresses to plain IPv4.
func addrToAddrPort(a net.Addr) (netip.AddrPort, bool) {
	if ua, ok := a.(*net.UDPAddr); ok {
		ap := ua.AddrPort()
		ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
		return ap, ap.IsValid()
	}
	ap, err := netip.ParseAddrPort(a.String())
	if err == nil {
		ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}
	return ap, err == nil
}

// hexToNatID decodes a 64-hex-char peer ID to [32]byte.
func hexToNatID(s string) ([32]byte, bool) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return [32]byte{}, false
	}
	var id [32]byte
	copy(id[:], b)
	return id, true
}
