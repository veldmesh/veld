// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package mdns

import (
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	hashmDNS "github.com/hashicorp/mdns"

	"github.com/veldmesh/veld/internal/crypto"
	"github.com/veldmesh/veld/internal/peer"
)

const (
	serviceType  = "_veld._udp"
	browsePeriod = 30 * time.Second
	queryTimeout = 5 * time.Second
)

// PeerFoundFn is called for each LAN peer discovered via mDNS.
// endpoint is the peer's data-plane UDP address derived from the SRV record.
// It may be called concurrently from the browse goroutine.
type PeerFoundFn func(e *peer.Entry, endpoint netip.AddrPort)

// Discovery advertises this node as a Veld service on the local network
// and browses for other Veld nodes. Peers are surfaced via PeerFoundFn.
type Discovery struct {
	server *hashmDNS.Server
	onPeer PeerFoundFn
	selfID [32]byte

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// New creates a Discovery that immediately begins advertising the local node.
// Call Start to begin the periodic browse loop.
//
// name is the peer name to advertise (e.g. the machine hostname).
// vpnAddr is the VPN IP that peers should use to reach this node.
// dataPort is the UDP port the data plane is listening on.
// tunName is the name of Veld's own tunnel interface ("" if unknown); its
// addresses are never advertised, since peers cannot reach them before a
// session exists.
func New(
	localID *crypto.Identity,
	name string,
	tunName string,
	vpnAddr netip.Addr,
	dataPort uint16,
	onPeer PeerFoundFn,
) (*Discovery, error) {
	ed25519B64 := base64.RawURLEncoding.EncodeToString(localID.Ed25519Public)
	x25519B64 := base64.RawURLEncoding.EncodeToString(localID.X25519Public[:])
	txt := []string{
		"ed25519=" + ed25519B64,
		"x25519=" + x25519B64,
		"vpn=" + vpnAddr.String(),
	}

	ips := advertisedIPv4s(localInterfaces(), tunName, vpnAddr, multicastSource())

	svc, err := hashmDNS.NewMDNSService(name, serviceType, "", "", int(dataPort), ips, txt)
	if err != nil {
		return nil, fmt.Errorf("mdns service: %w", err)
	}

	srv, err := hashmDNS.NewServer(&hashmDNS.Config{Zone: svc})
	if err != nil {
		return nil, fmt.Errorf("mdns server: %w", err)
	}

	var selfID [32]byte
	copy(selfID[:], localID.Ed25519Public)

	return &Discovery{
		server: srv,
		onPeer: onPeer,
		selfID: selfID,
		stopCh: make(chan struct{}),
	}, nil
}

// Start launches the periodic LAN peer browse loop.
// Performs an immediate browse, then repeats every 30 seconds.
func (d *Discovery) Start() {
	d.wg.Add(1)
	go d.browseLoop()
}

// Stop shuts down the mDNS advertisement server and the browse loop.
// Shutting down the server first interrupts any ongoing query, making
// shutdown faster and more reliable on platforms where Query may block.
// A timeout guards against platforms where multicast socket cleanup may
// block indefinitely (e.g., Windows).
func (d *Discovery) Stop() {
	_ = d.server.Shutdown()
	close(d.stopCh)

	// Wait for the browse loop with a timeout to avoid hanging on
	// platforms where multicast socket cleanup may block.
	done := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		// Log and continue; the browse loop will exit when the query
		// timeout fires or the socket is closed by the OS.
		log.Printf("warning: mDNS browse loop did not exit within timeout")
	}
}

func (d *Discovery) browseLoop() {
	defer d.wg.Done()

	// Check for stop before the initial browse.
	select {
	case <-d.stopCh:
		return
	default:
		d.browse()
	}

	t := time.NewTicker(browsePeriod)
	defer t.Stop()

	for {
		select {
		case <-d.stopCh:
			return
		case <-t.C:
			select {
			case <-d.stopCh:
				return
			default:
				d.browse()
			}
		}
	}
}

// browse queries the LAN for Veld peers and hands every discovered entry to
// onPeer. Entry fields are only read after the query has finished; see
// collectEntries for why.
func (d *Discovery) browse() {
	entries := make(chan *hashmDNS.ServiceEntry, 32)
	collected := collectEntries(entries)

	_ = hashmDNS.Query(&hashmDNS.QueryParam{
		Service: serviceType,
		Timeout: queryTimeout,
		Entries: entries,
	})

	// Query has returned, so the library no longer touches the entries;
	// only now is it safe to read their fields.
	close(entries)
	d.handleCollected(<-collected)
}

// collectEntries starts a goroutine that gathers every entry pointer sent on
// entries and delivers the gathered slice once entries has been closed and
// fully drained.
//
// hashicorp/mdns keeps mutating a *ServiceEntry after sending it on the
// query's Entries channel: for the whole duration of the query it writes
// Host/Port/AddrV4/AddrV6/InfoFields on entries it has already handed out,
// as further records for the same name arrive. Reading entry fields while
// Query runs is therefore a data race, so the collector must only collect
// the pointers. Draining the buffered channel concurrently also keeps the
// library's non-blocking sends from dropping entries.
func collectEntries(entries <-chan *hashmDNS.ServiceEntry) <-chan []*hashmDNS.ServiceEntry {
	collected := make(chan []*hashmDNS.ServiceEntry, 1)
	go func() {
		var got []*hashmDNS.ServiceEntry
		for e := range entries {
			got = append(got, e)
		}
		collected <- got
	}()
	return collected
}

// handleCollected parses entries gathered by collectEntries, after the query
// that produced them has finished and the library no longer mutates them.
// hashicorp/mdns can send the same *ServiceEntry pointer more than once, so
// entries are de-duplicated by pointer: onPeer fires once per distinct peer.
func (d *Discovery) handleCollected(entries []*hashmDNS.ServiceEntry) {
	seen := make(map[*hashmDNS.ServiceEntry]struct{}, len(entries))
	for _, e := range entries {
		if _, dup := seen[e]; dup {
			continue
		}
		seen[e] = struct{}{}
		d.handleEntry(e)
	}
}

func (d *Discovery) handleEntry(e *hashmDNS.ServiceEntry) {
	pe, ep, ok := parsePeerEntry(e)
	if !ok || pe.ID == d.selfID {
		return
	}
	if d.onPeer != nil {
		d.onPeer(pe, ep)
	}
}

// parsePeerEntry extracts a peer.Entry and UDP endpoint from an mDNS ServiceEntry.
// Returns (nil, zero, false) if required TXT fields are absent or malformed.
func parsePeerEntry(e *hashmDNS.ServiceEntry) (*peer.Entry, netip.AddrPort, bool) {
	var ed25519B64, x25519B64, vpnStr string
	for _, field := range e.InfoFields {
		if val, ok := strings.CutPrefix(field, "ed25519="); ok {
			ed25519B64 = val
		} else if val, ok := strings.CutPrefix(field, "x25519="); ok {
			x25519B64 = val
		} else if val, ok := strings.CutPrefix(field, "vpn="); ok {
			vpnStr = val
		}
	}
	if ed25519B64 == "" || x25519B64 == "" || vpnStr == "" {
		return nil, netip.AddrPort{}, false
	}

	ed25519Bytes, err := base64.RawURLEncoding.DecodeString(ed25519B64)
	if err != nil || len(ed25519Bytes) != 32 {
		return nil, netip.AddrPort{}, false
	}
	x25519Bytes, err := base64.RawURLEncoding.DecodeString(x25519B64)
	if err != nil || len(x25519Bytes) != 32 {
		return nil, netip.AddrPort{}, false
	}
	vpnAddr, err := netip.ParseAddr(vpnStr)
	if err != nil {
		return nil, netip.AddrPort{}, false
	}

	var id, x25519 [32]byte
	copy(id[:], ed25519Bytes)
	copy(x25519[:], x25519Bytes)

	pe := &peer.Entry{
		ID:        id,
		X25519Pub: x25519,
		VPNAddr:   vpnAddr,
		Name:      e.Name,
	}

	var ep netip.AddrPort
	switch {
	case e.AddrV4 != nil:
		if addr, ok := netip.AddrFromSlice(e.AddrV4.To4()); ok {
			ep = netip.AddrPortFrom(addr, uint16(e.Port))
		}
	case e.AddrV6 != nil:
		if addr, ok := netip.AddrFromSlice(e.AddrV6); ok {
			ep = netip.AddrPortFrom(addr, uint16(e.Port))
		}
	}

	return pe, ep, true
}

// iface is the part of a network interface that address selection looks at.
type iface struct {
	name  string
	flags net.Flags
	addrs []net.Addr
}

func localInterfaces() []iface {
	ifs, err := net.Interfaces()
	if err != nil {
		log.Printf("warning: mDNS: list network interfaces: %v", err)
		return nil
	}
	out := make([]iface, 0, len(ifs))
	for _, i := range ifs {
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		out = append(out, iface{name: i.Name, flags: i.Flags, addrs: addrs})
	}
	return out
}

// multicastSource returns the local address the OS would send mDNS traffic
// from, or the zero Addr if it cannot tell. Connecting a UDP socket sends
// nothing.
func multicastSource() netip.Addr {
	c, err := net.Dial("udp4", "224.0.0.251:5353")
	if err != nil {
		return netip.Addr{}
	}
	defer func() { _ = c.Close() }()
	if a, ok := c.LocalAddr().(*net.UDPAddr); ok {
		return a.AddrPort().Addr().Unmap()
	}
	return netip.Addr{}
}

// advertisedIPv4s picks the LAN addresses to advertise. Interfaces that are
// down, loopback or point-to-point (tunnels), Veld's own tunnel and the VPN
// address are never used. Browsers built on hashicorp/mdns keep only one
// address per host, so if preferred is among the candidates it is the only
// one advertised; otherwise all candidates are. Falls back to 127.0.0.1 if
// there are none.
func advertisedIPv4s(ifs []iface, tunName string, vpnAddr, preferred netip.Addr) []net.IP {
	var ips []net.IP
	for _, i := range ifs {
		if i.flags&net.FlagUp == 0 || i.flags&(net.FlagLoopback|net.FlagPointToPoint) != 0 {
			continue
		}
		if tunName != "" && i.name == tunName {
			continue
		}
		for _, a := range i.addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok || ipnet.IP.IsLoopback() {
				continue
			}
			ip4 := ipnet.IP.To4()
			if ip4 == nil {
				continue
			}
			addr := netip.AddrFrom4([4]byte(ip4))
			if addr == vpnAddr {
				continue
			}
			if addr == preferred {
				return []net.IP{ip4}
			}
			ips = append(ips, ip4)
		}
	}
	if len(ips) == 0 {
		ips = []net.IP{net.IPv4(127, 0, 0, 1)}
	}
	return ips
}
