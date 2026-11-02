// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package dataplane

import (
	"encoding/binary"
	"errors"
	"log"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/veldmesh/veld/internal/acl"
	"github.com/veldmesh/veld/internal/peer"
	"github.com/veldmesh/veld/internal/session"
	"github.com/veldmesh/veld/internal/tun"
)

const (
	maxMTU             = 1500
	authTagSize        = 16 // ChaCha20-Poly1305 tag
	udpBufSize         = HeaderSize + maxMTU + authTagSize
	rekeyCheckInterval = 30 * time.Second // periodic check for time-based rekey
)

// Dispatcher routes encrypted packets between TUN and UDP.
type Dispatcher struct {
	tun   tun.TUN
	conn  net.PacketConn
	peers *peer.Table
	tunMu sync.RWMutex

	// OnHandshakeRequired is called when a TUN packet is destined for a peer
	// that has no active session. The packet is already in the peer's hold queue.
	// The caller must eventually call entry.SetSession to drain the hold queue.
	// May be nil (hold queue fills and drops if no handler registered).
	OnHandshakeRequired func(entry *peer.Entry)

	// OnRekeyRequired is called when the current session hits the nonce threshold
	// (2^32 packets) or the time-based rekey limit (2 minutes). The packet is
	// already in the peer's hold queue. The caller must clear the old session and
	// initiate a fresh handshake -- SetSession will drain the hold queue once the
	// new session is ready. May be nil (packets queued until queue is full, then dropped).
	OnRekeyRequired func(entry *peer.Entry)

	// OnHandshakePacket is called for TypeHandshakeInit and TypeHandshakeResp packets.
	// pkt is the full wire packet (including 16-byte header); addr is the sender.
	OnHandshakePacket func(pkt []byte, addr net.Addr)

	// OnNATProbePacket is called for TypeNATProbe packets.
	// pkt is the full wire packet (including 16-byte header); addr is the sender.
	OnNATProbePacket func(pkt []byte, addr net.Addr)

	// OnSessionEstablished is called when a pending session is promoted to active
	// (WireGuard-style handshake confirmation). The caller uses this to flush the
	// peer's hold queue via FlushHoldQueue.
	OnSessionEstablished func(entry *peer.Entry)

	// ACL policy decider (local + network)
	policyDecider atomic.Pointer[acl.PolicyDecider]

	// This node's Ed25519 public key (for ACL decisions)
	selfPeerID [32]byte

	// Flow table for connection tracking
	flowTable *acl.FlowTable

	// Drop counters and logging
	dropCounters *acl.DropCounters
	lastDropLog  atomic.Int64 // unix nano of last drop log
	flowLogged   sync.Map     // flow key -> bool (whether first drop logged)

	stopOnce sync.Once
	stopCh   chan struct{}
	wg       sync.WaitGroup
}

// New creates a Dispatcher. Call Start to launch the I/O goroutines.
func New(t tun.TUN, conn net.PacketConn, peers *peer.Table) *Dispatcher {
	return &Dispatcher{
		tun:           t,
		conn:          conn,
		peers:         peers,
		stopCh:        make(chan struct{}),
		flowTable:     acl.NewFlowTable(acl.DefaultFlowTableConfig()),
		dropCounters:  acl.NewDropCounters(),
	}
}

// Start launches the TUN->UDP and UDP->TUN goroutines.
func (d *Dispatcher) Start() {
	d.wg.Add(3)
	go d.tunLoop()
	go d.udpLoop()
	go d.rekeyLoop()
	// Flow expiration loop
	d.wg.Add(1)
	go d.expireFlowsLoop()
}

// SetTUN sets the TUN device. If the dispatcher was started with a nil TUN
// (coord mode before VPN address assignment), this starts the tunLoop goroutine.
func (d *Dispatcher) SetTUN(t tun.TUN) {
	d.tunMu.Lock()
	d.tun = t
	d.tunMu.Unlock()
	if t != nil {
		d.wg.Add(1)
		go d.tunLoop()
	}
}

// SetPolicyDecider sets the ACL policy decider for this dispatcher.
func (d *Dispatcher) SetPolicyDecider(pd acl.PolicyDecider) {
	d.policyDecider.Store(&pd)
}

// SetSelfPeerID sets this node's Ed25519 public key for ACL decisions.
func (d *Dispatcher) SetSelfPeerID(id [32]byte) {
	d.selfPeerID = id
}

// getPolicyDecider returns the current policy decider, or nil if not set.
func (d *Dispatcher) getPolicyDecider() acl.PolicyDecider {
	ptr := d.policyDecider.Load()
	if ptr == nil {
		return nil
	}
	return *ptr
}

// Stop closes the TUN and UDP conn, causing both loops to exit.
// Safe to call multiple times.
func (d *Dispatcher) Stop() {
	d.stopOnce.Do(func() {
		close(d.stopCh)
		d.tunMu.Lock()
		if d.tun != nil {
			_ = d.tun.Close()
		}
		d.tunMu.Unlock()
		_ = d.conn.Close()
	})
}

// Wait blocks until both loops have exited.
func (d *Dispatcher) Wait() {
	d.wg.Wait()
}

// FlushHoldQueue drains the peer's hold queue and sends all held packets as
// encrypted data over UDP. Called by handshake.Manager.OnSessionEstablished.
func (d *Dispatcher) FlushHoldQueue(entry *peer.Entry) {
	sess := entry.GetSession()
	if sess == nil {
		return
	}
	ep := entry.GetEndpoint()
	if !ep.IsValid() {
		return
	}
	for _, pkt := range entry.DrainQueue() {
		nonce, ct, err := sess.Encrypt(pkt)
		if err != nil {
			continue
		}
		d.conn.WriteTo(buildDataPacket(nonce, ct), net.UDPAddrFromAddrPort(ep))
	}
}

// rekeyLoop periodically scans all peers and triggers rekey for sessions
// that have exceeded the time limit (but not the nonce threshold, which is
// checked inline in handleTunPacket).
func (d *Dispatcher) rekeyLoop() {
	defer d.wg.Done()
	ticker := time.NewTicker(rekeyCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			d.checkRekey()
		}
	}
}

func (d *Dispatcher) checkRekey() {
	for _, e := range d.peers.List() {
		sess := e.GetSession()
		if sess != nil && sess.NeedsRekey() {
			if d.OnRekeyRequired != nil {
				d.OnRekeyRequired(e)
			}
		}
	}
}

// expireFlowsLoop periodically expires old flows and logs drop counters.
func (d *Dispatcher) expireFlowsLoop() {
	defer d.wg.Done()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			d.flowTable.ExpireOldFlows()
			d.logDropCounters()
		}
	}
}

// logDropCounters logs a periodic summary of drop counters.
func (d *Dispatcher) logDropCounters() {
	byPeer, byRule, byOO := d.dropCounters.Snapshot()
	total := uint64(0)
	for _, v := range byPeer {
		total += v
	}
	for _, v := range byRule {
		total += v
	}
	for _, v := range byOO {
		total += v
	}
	if total > 0 {
		log.Printf("acl: drops - total=%d by_peer=%d by_rule=%d by_outbound_only=%d",
			total, len(byPeer), len(byRule), len(byOO))
	}
}

// tunLoop reads raw IP packets from TUN and sends them encrypted over UDP.
// If TUN is nil (coord mode before VPN address assignment), the loop exits immediately.
func (d *Dispatcher) tunLoop() {
	defer d.wg.Done()
	d.tunMu.RLock()
	t := d.tun
	d.tunMu.RUnlock()
	if t == nil {
		return
	}
	plainBuf := make([]byte, maxMTU)

	for {
		n, err := t.Read(plainBuf)
		if err != nil {
			return
		}
		if n == 0 {
			continue
		}
		d.handleTunPacket(plainBuf[:n])
	}
}

func (d *Dispatcher) handleTunPacket(pkt []byte) {
	destIP, ok := extractDestIP(pkt)
	if !ok {
		log.Printf("handleTunPacket: failed to extract dest IP")
		return
	}

	entry, ok := d.peers.LookupByVPN(destIP)
	if !ok {
		log.Printf("handleTunPacket: no peer for dest IP %v", destIP)
		return
	}

	// Parse packet to get protocol and port for ACL check
	flow, kind, err := acl.ParsePacket(pkt)
	if err != nil {
		log.Printf("handleTunPacket: parse packet error: %v", err)
		// Unparseable packet - skip ACL check for outbound (local app may send various packet types)
		// but continue with encryption
		flow = acl.Flow{}
		kind = acl.KindOther
	}

	// Outbound ACL check: this peer (self) -> destination peer
	pd := d.getPolicyDecider()
	log.Printf("handleTunPacket: policyDecider=%v, selfPeerID=%x, dstPeerID=%x, flow=%+v", pd != nil, d.selfPeerID[:8], entry.ID[:8], flow)
	if pd != nil && flow.Proto != 0 {
		dstPeerID := entry.ID
		srcPeerID := d.selfPeerID
		dec := pd.Decide(srcPeerID, dstPeerID, flow.Proto, flow.DstPort)
		log.Printf("handleTunPacket: ACL decision: %+v", dec)
		if dec.Action == acl.ActionDeny {
			d.recordDrop(dstPeerID, dec, kind)
			d.sendReject(entry, flow, pkt)
			return
		}
	}

	sess := entry.GetSession()
	if sess == nil {
		entry.Enqueue(pkt)
		if d.OnHandshakeRequired != nil {
			d.OnHandshakeRequired(entry)
		}
		return
	}

	// Check NeedsRekey before encrypting: a session at the nonce threshold
	// or beyond the time limit must not be used for new packets.
	if sess.NeedsRekey() {
		entry.Enqueue(pkt)
		if d.OnRekeyRequired != nil {
			d.OnRekeyRequired(entry)
		}
		return
	}

	nonce, ct, err := sess.Encrypt(pkt)
	if err != nil {
		if errors.Is(err, session.ErrRekeyRequired) {
			entry.Enqueue(pkt)
			if d.OnRekeyRequired != nil {
				d.OnRekeyRequired(entry)
			}
		}
		return
	}

	ep := entry.GetEndpoint()
	if !ep.IsValid() {
		return
	}

	// Record flow for reply tracking (outbound direction)
	if kind == acl.KindStart {
		d.flowTable.Lookup(flow, true, acl.FlowStateNew)
	}

	udpPkt := buildDataPacket(nonce, ct)
	d.conn.WriteTo(udpPkt, net.UDPAddrFromAddrPort(ep))
}

// udpLoop reads UDP packets and injects decrypted IP packets into TUN.
func (d *Dispatcher) udpLoop() {
	defer d.wg.Done()
	recvBuf := make([]byte, udpBufSize)

	for {
		n, addr, err := d.conn.ReadFrom(recvBuf)
		if err != nil {
			return
		}
		if n < HeaderSize {
			continue
		}
		d.handleUDPPacket(recvBuf[:n], addr)
	}
}

func (d *Dispatcher) handleUDPPacket(pkt []byte, addr net.Addr) {
	pktType, _, nonce := parseHeader(pkt[:HeaderSize])
	payload := pkt[HeaderSize:]

	switch pktType {
	case TypeData:
		ep, ok := addrToAddrPort(addr)
		if !ok {
			return
		}
		entry, ok := d.peers.LookupByEndpoint(ep)
		if !ok {
			return
		}
		sess := entry.GetSession()

		plain := d.decryptDataPacket(entry, sess, nonce, payload)

		if plain == nil {
			return
		}
		if !d.sourceAllowed(entry, plain) {
			// Authenticated as this peer but claims another source address:
			// drop it, so no peer can speak for another inside the tunnel.
			return
		}

		// Inbound ACL check and flow tracking
		var flow acl.Flow
		var kind acl.Kind
		pd := d.getPolicyDecider()
		if pd != nil {
			// Parse packet for ACL check only when policy is enforced
			var err error
			flow, kind, err = acl.ParsePacket(plain)
			if err != nil {
				// Unparseable packet - drop under default deny for inbound
				log.Printf("handleUDPPacket: parse packet error: %v", err)
				return
			}

			srcPeerID := entry.ID
			dstPeerID := d.selfPeerID
			dec := pd.Decide(srcPeerID, dstPeerID, flow.Proto, flow.DstPort)
			if dec.Action == acl.ActionDeny {
				d.recordDrop(srcPeerID, dec, kind)
				return
			}
		}

		// Flow tracking (only if we parsed the packet)
		if pd != nil {
			flowEntry, isReply, created := d.flowTable.Lookup(flow, true, acl.FlowStateNew)
			if kind == acl.KindStart && !isReply && created {
				// New outbound flow started - already recorded in handleTunPacket
				// For inbound, we need to check if there's a matching outbound flow
				if isReply {
					// This is a reply to an existing flow
					if flowEntry != nil {
						flowEntry.State = acl.FlowStateEstablished
					}
				}
			} else if kind == acl.KindEnd {
				// Connection end (TCP FIN/RST) - mark flow as closing
				if flowEntry != nil {
					d.flowTable.UpdateState(flow, acl.FlowStateClosing)
				}
			}
		}

		entry.Touch()
		d.tunMu.RLock()
		t := d.tun
		d.tunMu.RUnlock()
		if t != nil {
			// A failed write drops this packet only: one packet the
			// kernel rejects must not take the whole data plane down.
			_, _ = t.Write(plain)
		}

	case TypeKeepalive:
		ep, ok := addrToAddrPort(addr)
		if !ok {
			return
		}
		if entry, ok := d.peers.LookupByEndpoint(ep); ok {
			entry.Touch()
		}

	case TypeHandshakeInit, TypeHandshakeResp:
		if d.OnHandshakePacket != nil {
			pktCopy := make([]byte, len(pkt))
			copy(pktCopy, pkt)
			d.OnHandshakePacket(pktCopy, addr)
		}

	case TypeNATProbe:
		if d.OnNATProbePacket != nil {
			pktCopy := make([]byte, len(pkt))
			copy(pktCopy, pkt)
			d.OnNATProbePacket(pktCopy, addr)
		}
	}
}

// recordDrop records a dropped packet and logs the first drop per flow.
func (d *Dispatcher) recordDrop(peerID [32]byte, dec acl.Decision, kind acl.Kind) {
	d.dropCounters.IncrementPeer(peerID)
	if dec.RuleIndex >= 0 {
		d.dropCounters.IncrementRule(dec.RuleIndex)
	}
	if dec.OutboundOnly {
		d.dropCounters.IncrementOutboundOnly(peerID)
	}

	// Log first drop per flow (rate-limited by flow)
	// We use a simple approach: log if it's been more than 60 seconds since last log
	now := time.Now().UnixNano()
	lastLog := d.lastDropLog.Load()
	if now-lastLog > 60*time.Second.Nanoseconds() {
		if d.lastDropLog.CompareAndSwap(lastLog, now) {
			log.Printf("acl: drop peer=%x action=deny rule=%d outbound_only=%v kind=%v",
				peerID[:8], dec.RuleIndex, dec.OutboundOnly, kind)
		}
	}
}

// sendReject sends a rejection packet (TCP RST or ICMP admin prohibited) back to the local app.
func (d *Dispatcher) sendReject(entry *peer.Entry, flow acl.Flow, originalPkt []byte) {
	// Build a reject packet and inject it into the TUN
	// For TCP, send RST; for others, send ICMP admin prohibited
	d.tunMu.RLock()
	t := d.tun
	d.tunMu.RUnlock()
	if t == nil {
		return
	}

	// Extract source and dest from original packet
	srcIP, _ := extractSrcIP(originalPkt)
	dstIP, _ := extractDestIP(originalPkt)

	var rejectPkt []byte
	if flow.Proto == acl.ProtoTCP {
		// Build TCP RST packet
		rejectPkt = buildTCPRST(flow, srcIP, dstIP)
	} else {
		// Build ICMP/ICMPv6 admin prohibited
		rejectPkt = buildICMPAdminProhibited(flow, srcIP, dstIP, originalPkt)
	}

	if rejectPkt != nil {
		_, _ = t.Write(rejectPkt)
	}
}

// buildTCPRST builds a TCP RST packet in response to a SYN.
func buildTCPRST(flow acl.Flow, srcIP, dstIP netip.Addr) []byte {
	// Swap src/dst for the response
	rstFlow := flow
	rstFlow.SrcIP, rstFlow.DstIP = flow.DstIP, flow.SrcIP
	rstFlow.SrcPort, rstFlow.DstPort = flow.DstPort, flow.SrcPort

	if flow.IPv6 {
		// IPv6 TCP RST
		pkt := make([]byte, 40+20) // IPv6 header + TCP header
		// IPv6 header
		pkt[0] = 0x60 // Version=6
		pkt[1] = 0x00
		pkt[2] = 0x00
		pkt[3] = 0x00
		binary.BigEndian.PutUint16(pkt[4:6], 20) // Payload length
		pkt[6] = 6                               // Next header = TCP
		pkt[7] = 64                              // Hop limit
		// Src/Dst IP
		copy(pkt[8:24], rstFlow.SrcIP[:])
		copy(pkt[24:40], rstFlow.DstIP[:])
		// TCP header
		binary.BigEndian.PutUint16(pkt[40:42], rstFlow.SrcPort)
		binary.BigEndian.PutUint16(pkt[42:44], rstFlow.DstPort)
		binary.BigEndian.PutUint32(pkt[44:48], 0) // Seq
		binary.BigEndian.PutUint32(pkt[48:52], 0) // Ack
		pkt[52] = 0x50                            // Data offset=5
		pkt[53] = 0x04                            // Flags = RST
		// Window, Checksum, Urgent = 0
		return pkt
	} else {
		// IPv4 TCP RST
		pkt := make([]byte, 20+20) // IPv4 header + TCP header
		// IPv4 header
		pkt[0] = 0x45 // Version=4, IHL=5
		pkt[1] = 0x00
		binary.BigEndian.PutUint16(pkt[2:4], 40) // Total length
		binary.BigEndian.PutUint16(pkt[4:6], 0)  // ID
		binary.BigEndian.PutUint16(pkt[6:8], 0)  // Flags + FragOffset
		pkt[8] = 64                              // TTL
		pkt[9] = 6                               // Protocol = TCP
		// Checksum = 0 (kernel will fill)
		copy(pkt[12:16], rstFlow.SrcIP[12:16])
		copy(pkt[16:20], rstFlow.DstIP[12:16])
		// TCP header
		binary.BigEndian.PutUint16(pkt[20:22], rstFlow.SrcPort)
		binary.BigEndian.PutUint16(pkt[22:24], rstFlow.DstPort)
		binary.BigEndian.PutUint32(pkt[24:28], 0) // Seq
		binary.BigEndian.PutUint32(pkt[28:32], 0) // Ack
		pkt[32] = 0x50                            // Data offset=5
		pkt[33] = 0x04                            // Flags = RST
		// Window, Checksum, Urgent = 0
		return pkt
	}
}

// buildICMPAdminProhibited builds an ICMP/ICMPv6 admin prohibited packet.
func buildICMPAdminProhibited(flow acl.Flow, srcIP, dstIP netip.Addr, originalPkt []byte) []byte {
	// For simplicity, we don't implement full ICMP error generation here.
	// The kernel will generate ICMP errors if we drop the packet at the socket level.
	// Since we're in userspace TUN, we'd need to craft the ICMP packet.
	// This is a placeholder - in practice, we'd need to implement this properly.
	return nil
}

// decryptDataPacket decrypts a data packet using the peer's active session,
// falling back to the pending session (WireGuard-style handshake confirmation)
// and then the previous session.
// If the pending session decrypts successfully, it is promoted to active and
// OnSessionEstablished is called. Returns nil if decryption fails with both.
func (d *Dispatcher) decryptDataPacket(entry *peer.Entry, sess *session.Session, nonce uint64, payload []byte) []byte {
	// Try the active session first.
	if sess != nil {
		plain, err := sess.Decrypt(nonce, payload)
		if err == nil && plain != nil {
			return plain
		}
	}

	// Fall back to the pending session. If a handshake was initiated by the
	// peer, the new session is pending confirmation. The first data packet
	// that decrypts with it confirms the handshake.
	if pending := entry.GetPendingSession(); pending != nil {
		plain, err := pending.Decrypt(nonce, payload)
		if err == nil && plain != nil {
			// Pending session works -- promote it to active.
			entry.PromotePendingSession()
			if d.OnSessionEstablished != nil {
				d.OnSessionEstablished(entry)
			}
			return plain
		}
	}

	// Packets sent under the session we just replaced may still be in flight.
	if prev := entry.GetPreviousSession(); prev != nil && prev != sess {
		plain, err := prev.Decrypt(nonce, payload)
		if err == nil && plain != nil {
			return plain
		}
	}

	return nil
}

// extractDestIP reads the destination IP from a raw IPv4 or IPv6 packet.
func extractDestIP(pkt []byte) (netip.Addr, bool) {
	if len(pkt) < 1 {
		return netip.Addr{}, false
	}
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom4([4]byte(pkt[16:20])), true
	case 6:
		if len(pkt) < 40 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom16([16]byte(pkt[24:40])), true
	}
	return netip.Addr{}, false
}

// extractSrcIP reads the source IP from a raw IPv4 or IPv6 packet.
func extractSrcIP(pkt []byte) (netip.Addr, bool) {
	if len(pkt) < 1 {
		return netip.Addr{}, false
	}
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom4([4]byte(pkt[12:16])), true
	case 6:
		if len(pkt) < 40 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom16([16]byte(pkt[8:24])), true
	}
	return netip.Addr{}, false
}

// sourceAllowed reports whether a decrypted packet from entry carries a source
// address that peer owns: its VPN address or an address inside one of the
// subnet routes it advertises. Anything else (another peer's address, an
// unparseable packet) is dropped. A subnet route never vouches for an address
// in the mesh or for another peer's address, so advertising a broad route
// does not let a peer speak for others.
func (d *Dispatcher) sourceAllowed(entry *peer.Entry, pkt []byte) bool {
	src, ok := extractSrcIP(pkt)
	if !ok {
		return false
	}
	src = src.Unmap()
	if src == entry.VPNAddr {
		return true
	}
	d.tunMu.RLock()
	t := d.tun
	d.tunMu.RUnlock()
	if t != nil && t.Addr().Masked().Contains(src) {
		return false
	}
	if owner, ok := d.peers.LookupByVPN(src); ok && owner != entry {
		return false
	}
	for _, p := range entry.SubnetRoutes {
		if p.Contains(src) {
			return true
		}
	}
	return false
}

// addrToAddrPort converts a net.Addr to netip.AddrPort.
// Normalizes IPv4-mapped IPv6 addresses to plain IPv4 so map lookups
// match entries stored via netip.MustParseAddrPort("x.x.x.x:p").
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