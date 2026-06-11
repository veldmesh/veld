// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package dns

import (
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"sync"
)

const (
	dnsTypeA    = uint16(1)
	dnsTypeAAAA = uint16(28)
	dnsClassIN  = uint16(1)
	dnsTTL      = byte(30) // short TTL so peer IP changes propagate fast
)

// LookupFn resolves a peer name label (e.g. "server1") to its VPN IPv4 address.
type LookupFn func(name string) (netip.Addr, bool)

// Resolver is a minimal DNS stub that answers A queries for "<label>.<domain>".
// Unknown names or wrong-domain queries get NXDOMAIN. AAAA queries for known
// IPv4-only peers get NOERROR with zero answers. It never forwards queries.
type Resolver struct {
	domain string
	lookup LookupFn

	mu     sync.RWMutex
	static map[string]netip.Addr // extra name→addr entries (e.g. self)

	conn net.PacketConn
	wg   sync.WaitGroup
}

// New creates a Resolver. domain is the suffix (e.g. "veld"); lookup resolves
// peer labels to their VPN IPs.
func New(domain string, lookup LookupFn) *Resolver {
	if domain == "" {
		domain = "veld"
	}
	return &Resolver{
		domain: strings.ToLower(strings.Trim(domain, ".")),
		lookup: lookup,
		static: make(map[string]netip.Addr),
	}
}

// AddStatic registers a name→addr mapping that takes precedence over the lookup
// function. name is the label only (no domain suffix), e.g. "myhost".
func (r *Resolver) AddStatic(name string, addr netip.Addr) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.static[strings.ToLower(name)] = addr
}

// Start opens a UDP listener on listenAddr and begins serving DNS queries.
func (r *Resolver) Start(listenAddr string) error {
	if listenAddr == "" {
		listenAddr = "127.0.0.1:5353"
	}
	conn, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		return err
	}
	r.conn = conn
	r.wg.Add(1)
	go r.serve()
	return nil
}

// Stop closes the listener and waits for the serve goroutine to exit.
func (r *Resolver) Stop() {
	if r.conn != nil {
		r.conn.Close()
	}
	r.wg.Wait()
}

// ListenAddr returns the address the resolver is bound to, or "" if not started.
func (r *Resolver) ListenAddr() string {
	if r.conn == nil {
		return ""
	}
	return r.conn.LocalAddr().String()
}

func (r *Resolver) serve() {
	defer r.wg.Done()
	buf := make([]byte, 512)
	for {
		n, addr, err := r.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		msg := make([]byte, n)
		copy(msg, buf[:n])
		go r.handle(msg, addr)
	}
}

func (r *Resolver) handle(msg []byte, addr net.Addr) {
	if len(msg) < 12 {
		return
	}
	id := binary.BigEndian.Uint16(msg[0:2])
	flags := binary.BigEndian.Uint16(msg[2:4])
	// Only handle standard queries (QR=0, OPCODE=0000).
	if flags&0x8000 != 0 || (flags>>11)&0xF != 0 {
		return
	}
	if binary.BigEndian.Uint16(msg[4:6]) == 0 {
		return // no questions
	}

	qname, qtype, questionEnd, ok := parseQuestion(msg, 12)
	if !ok {
		return
	}

	resp := r.buildResponse(id, msg[12:questionEnd], qname, qtype)
	r.conn.WriteTo(resp, addr) //nolint:errcheck
}

func (r *Resolver) resolve(qname string) (netip.Addr, bool) {
	q := strings.ToLower(strings.TrimSuffix(qname, "."))
	suffix := "." + r.domain
	if !strings.HasSuffix(q, suffix) {
		return netip.Addr{}, false
	}
	label := strings.TrimSuffix(q, suffix)
	if label == "" {
		return netip.Addr{}, false
	}

	r.mu.RLock()
	addr, ok := r.static[label]
	r.mu.RUnlock()
	if ok {
		return addr, true
	}
	return r.lookup(label)
}

func (r *Resolver) buildResponse(id uint16, questionWire []byte, qname string, qtype uint16) []byte {
	ip, found := r.resolve(qname)

	var rcode uint16
	var ancount uint16
	var answer []byte

	if !found {
		rcode = 3 // NXDOMAIN
	} else if qtype == dnsTypeA && ip.Is4() {
		ancount = 1
		a4 := ip.As4()
		answer = buildARecord(a4[:])
	}
	// AAAA on IPv4-only peer → NOERROR, 0 answers (already zero values above).

	// QR=1, AA=1 (authoritative), plus rcode.
	respFlags := uint16(0x8400) | rcode

	buf := make([]byte, 0, 12+len(questionWire)+len(answer))
	buf = appendU16(buf, id)
	buf = appendU16(buf, respFlags)
	buf = appendU16(buf, 1)       // QDCOUNT
	buf = appendU16(buf, ancount) // ANCOUNT
	buf = appendU16(buf, 0)       // NSCOUNT
	buf = appendU16(buf, 0)       // ARCOUNT
	buf = append(buf, questionWire...)
	buf = append(buf, answer...)
	return buf
}

func buildARecord(ip4 []byte) []byte {
	buf := make([]byte, 0, 16)
	buf = append(buf, 0xC0, 0x0C) // pointer to question name at offset 12
	buf = appendU16(buf, dnsTypeA)
	buf = appendU16(buf, dnsClassIN)
	buf = append(buf, 0, 0, 0, dnsTTL) // TTL (4 bytes)
	buf = appendU16(buf, 4)             // RDLENGTH
	buf = append(buf, ip4...)
	return buf
}

// parseQuestion parses a DNS question at offset in msg.
// Returns the qname (with trailing dot), qtype, offset after the question, and ok.
func parseQuestion(msg []byte, offset int) (qname string, qtype uint16, end int, ok bool) {
	var labels []string
	for {
		if offset >= len(msg) {
			return "", 0, 0, false
		}
		n := int(msg[offset])
		offset++
		if n == 0 {
			break
		}
		if n&0xC0 == 0xC0 { // compression pointer not allowed in questions
			return "", 0, 0, false
		}
		if offset+n > len(msg) {
			return "", 0, 0, false
		}
		labels = append(labels, string(msg[offset:offset+n]))
		offset += n
	}
	if offset+4 > len(msg) {
		return "", 0, 0, false
	}
	qtype = binary.BigEndian.Uint16(msg[offset : offset+2])
	offset += 4 // skip qtype (2) + qclass (2)
	return strings.Join(labels, ".") + ".", qtype, offset, true
}

func appendU16(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}
