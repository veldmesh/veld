// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package mdns

import (
	"encoding/base64"
	"fmt"
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
func New(
	localID *crypto.Identity,
	name string,
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

	ips := nonLoopbackIPv4s()

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

// Stop shuts down the browse loop and the mDNS advertisement server.
func (d *Discovery) Stop() {
	close(d.stopCh)
	d.wg.Wait()
	_ = d.server.Shutdown()
}

func (d *Discovery) browseLoop() {
	defer d.wg.Done()
	d.browse()

	t := time.NewTicker(browsePeriod)
	defer t.Stop()

	for {
		select {
		case <-d.stopCh:
			return
		case <-t.C:
			d.browse()
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

// nonLoopbackIPv4s returns all non-loopback IPv4 addresses on this machine.
// Falls back to 127.0.0.1 if none are found.
func nonLoopbackIPv4s() []net.IP {
	addrs, _ := net.InterfaceAddrs()
	var ips []net.IP
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ip4 := ipnet.IP.To4(); ip4 != nil {
				ips = append(ips, ip4)
			}
		}
	}
	if len(ips) == 0 {
		ips = []net.IP{net.IPv4(127, 0, 0, 1)}
	}
	return ips
}
