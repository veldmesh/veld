// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package daemon

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	intconfig "github.com/veldmesh/veld/internal/config"
	"github.com/veldmesh/veld/internal/coord"
	"github.com/veldmesh/veld/internal/crypto"
	"github.com/veldmesh/veld/internal/dataplane"
	"github.com/veldmesh/veld/internal/dns"
	"github.com/veldmesh/veld/internal/handshake"
	"github.com/veldmesh/veld/internal/mdns"
	"github.com/veldmesh/veld/internal/nat"
	"github.com/veldmesh/veld/internal/peer"
	"github.com/veldmesh/veld/internal/relay"
	"github.com/veldmesh/veld/internal/route"
	"github.com/veldmesh/veld/internal/tofu"
	"github.com/veldmesh/veld/internal/tun"
)

// Daemon wires together TUN, UDP conn, peer table, dispatcher, handshake manager,
// optional coord client, optional NAT manager, and IPC server.
type Daemon struct {
	disp      *dataplane.Dispatcher
	hsMgr     *handshake.Manager
	coordCli  *coord.Client
	natMgr    *nat.Manager
	dnsSrv    *dns.Resolver
	mdnsDisco *mdns.Discovery
	routeMgr  route.Manager
	ipcSrv    *IPCServer
	peerTbl   *peer.Table
	localID   *crypto.Identity
	networkID [16]byte

	mu           sync.Mutex
	vpnAddr      netip.Addr
	peerID       string
	coordAddr    string
	relayProxies map[[32]byte]*relay.Proxy // one relay proxy per peer ID
	tunDev       tun.TUN                   // veld's own TUN; nil in coord mode until the coordinator assigns the VPN address
}

// New creates a Daemon from pre-constructed components.
// peerTbl must already be populated. Call Start to begin processing.
func New(
	localID *crypto.Identity,
	networkID [16]byte,
	t tun.TUN,
	conn net.PacketConn,
	peerTbl *peer.Table,
) *Daemon {
	disp := dataplane.New(t, conn, peerTbl)
	hsMgr := handshake.New(localID, networkID, peerTbl, conn)

	disp.OnHandshakeRequired = hsMgr.Initiate
	disp.OnHandshakePacket = hsMgr.HandlePacket
	hsMgr.OnSessionEstablished = disp.FlushHoldQueue

	return &Daemon{
		disp:      disp,
		hsMgr:     hsMgr,
		peerTbl:   peerTbl,
		localID:   localID,
		networkID: networkID,
		tunDev:    t,
	}
}

// NewFromConfig creates a Daemon with real OS TUN and UDP socket.
// Requires CAP_NET_ADMIN on Linux.
func NewFromConfig(cfg *intconfig.Config) (*Daemon, error) {
	localID, err := intconfig.LoadOrGenerate(cfg.Node.IdentityPath)
	if err != nil {
		return nil, fmt.Errorf("load identity: %w", err)
	}

	// Get network ID from either node or coord config
	networkIDStr := cfg.Node.NetworkID
	if networkIDStr == "" {
		networkIDStr = cfg.Coord.NetworkID
	}
	netIDBytes, err := hex.DecodeString(networkIDStr)
	if err != nil || len(netIDBytes) != 16 {
		return nil, fmt.Errorf("invalid network_id: must be 32 hex chars")
	}
	var networkID [16]byte
	copy(networkID[:], netIDBytes)

	// In static mode, use the configured VPN address
	var tunDev tun.TUN
	var vpnPrefix netip.Prefix

	if cfg.Node.VPNAddr != "" {
		var err error
		vpnPrefix, err = netip.ParsePrefix(cfg.Node.VPNAddr)
		if err != nil {
			return nil, fmt.Errorf("invalid vpn_addr: %w", err)
		}
	}

	// If running in static mode (no coord), create TUN now
	if cfg.Coord.Addr == "" {
		if vpnPrefix.IsValid() {
			mtu := cfg.Node.MTU
			if mtu == 0 {
				mtu = 1420
			}
			ifaceName := cfg.Node.IfaceName
			if ifaceName == "" {
				ifaceName = "tun0"
			}

			var err error
			tunDev, err = tun.CreateTUN(ifaceName, vpnPrefix, mtu)
			if err != nil {
				return nil, fmt.Errorf("create tun: %w", err)
			}
		}
	}

	// Listen on UDP
	conn, err := net.ListenPacket("udp", cfg.Node.ListenAddr)
	if err != nil {
		if tunDev != nil {
			_ = tunDev.Close()
		}
		return nil, fmt.Errorf("listen %s: %w", cfg.Node.ListenAddr, err)
	}

	peerTbl, err := buildPeerTable(cfg.Peers)
	if err != nil {
		if tunDev != nil {
			_ = tunDev.Close()
		}
		_ = conn.Close()
		return nil, fmt.Errorf("build peer table: %w", err)
	}

	d := New(localID, networkID, tunDev, conn, peerTbl)
	d.routeMgr = route.New()

	// If this node advertises subnet routes, enable IP forwarding on Linux.
	if len(cfg.Node.SubnetRoutes) > 0 {
		if err := route.EnableIPForward(); err != nil {
			log.Printf("warning: enable ip_forward: %v", err)
		}
	}

	// In static mode, install OS routes for any subnet routes declared in the
	// static peer config. These are installed once at startup; they're removed by Stop().
	if cfg.Coord.Addr == "" {
		for _, e := range peerTbl.List() {
			for _, pfx := range e.SubnetRoutes {
				if err := d.routeMgr.Add(pfx, e.VPNAddr); err != nil {
					log.Printf("warning: add route %s via %s: %v", pfx, e.VPNAddr, err)
				}
			}
		}
	}

	// Wire up TOFU key pinning. The store lives next to the identity file.
	tofuPath := filepath.Join(filepath.Dir(cfg.Node.IdentityPath), "tofu.json")
	tofuStore, err := tofu.New(tofuPath)
	if err != nil {
		if tunDev != nil {
			_ = tunDev.Close()
		}
		_ = conn.Close()
		return nil, fmt.Errorf("load TOFU store: %w", err)
	}
	d.hsMgr.TOFUCheck = tofuStore.Check

	// Wire up coord client and NAT manager if configured.
	if cfg.Coord.Addr != "" {
		d.mu.Lock()
		d.coordAddr = cfg.Coord.Addr
		d.mu.Unlock()

		coordCfg := coord.Config{
			ServerAddr:   cfg.Coord.Addr,
			NetworkID:    cfg.Coord.NetworkID,
			Token:        cfg.Coord.Token,
			Identity:     localID,
			LocalName:    "host",
			Endpoint:     cfg.Node.ListenAddr,
			SubnetRoutes: cfg.Node.SubnetRoutes,
			PeerTable:    peerTbl,
			TLSInsecure:  cfg.Coord.TLSInsecure,
		}
		d.coordCli = coord.New(coordCfg)

		// Extract the data-plane UDP port for NAT candidate gathering.
		localPort := uint16(0)
		if laddr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
			localPort = uint16(laddr.Port)
		}

		d.natMgr = nat.New(conn, localPort, cfg.Coord.STUNServer, localID)
		d.disp.OnNATProbePacket = d.natMgr.HandleProbe

		// When NAT discovers a path, update the peer table and kick handshake.
		d.natMgr.OnEndpointDiscovered = func(peerID [32]byte, ep netip.AddrPort) {
			peerTbl.UpdateEndpoint(peerID, ep)
			if e, ok := peerTbl.LookupByID(peerID); ok {
				d.hsMgr.Initiate(e)
			}
		}

		// Relay fallback: if hole punching times out (e.g. symmetric NATs),
		// open a Noise IK-encrypted channel through a volunteer relay peer
		// and re-point the data plane through a local loopback proxy. The
		// P2P-first model is unchanged — the relay is only a fallback, and
		// traffic still never transits the coord server.
		if cfg.Coord.RelayAddr != "" {
			relayKeyBytes, err := base64.StdEncoding.DecodeString(cfg.Coord.RelayX25519)
			if err != nil || len(relayKeyBytes) != 32 {
				log.Printf("warning: invalid coord.relay_x25519, relay fallback disabled")
			} else {
				var relayKey [32]byte
				copy(relayKey[:], relayKeyBytes)

				// The proxy injects datagrams into the daemon's own data-plane
				// socket. If the socket binds to a specific interface address,
				// target that; otherwise loopback reaches a wildcard bind.
				dataIP := net.IPv4(127, 0, 0, 1)
				if laddr, ok := conn.LocalAddr().(*net.UDPAddr); ok && len(laddr.IP) > 0 && !laddr.IP.IsUnspecified() {
					dataIP = laddr.IP
				}
				dataTarget := &net.UDPAddr{IP: dataIP, Port: int(localPort)}

				d.natMgr.OnPunchTimeout = func(peerID [32]byte) {
					peerEntry, ok := peerTbl.LookupByID(peerID)
					if !ok {
						return
					}
					dialCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
					defer cancel()
					rc, err := relay.Dial(dialCtx, cfg.Coord.RelayAddr, relayKey, localID, peerEntry.X25519Pub)
					if err != nil {
						log.Printf("warning: relay dial for peer %x: %v", peerID[:8], err)
						return
					}
					proxy, err := relay.NewProxy(rc, dataTarget)
					if err != nil {
						_ = rc.Close()
						log.Printf("warning: relay proxy for peer %x: %v", peerID[:8], err)
						return
					}
					// Keep one proxy per peer: a previous fallback (or a
					// re-punch that timed out again) is replaced and closed.
					d.mu.Lock()
					if d.relayProxies == nil {
						d.relayProxies = make(map[[32]byte]*relay.Proxy)
					}
					old := d.relayProxies[peerID]
					d.relayProxies[peerID] = proxy
					d.mu.Unlock()
					if old != nil {
						_ = old.Close()
					}

					peerTbl.UpdateEndpoint(peerID, proxy.LocalAddr())
					if e, ok := peerTbl.LookupByID(peerID); ok {
						d.hsMgr.Initiate(e)
					}
				}
			}
		}

		d.coordCli.OnPeerAdded = func(e *peer.Entry) {
			// Install OS routes for any subnets this peer advertises.
			for _, pfx := range e.SubnetRoutes {
				if err := d.routeMgr.Add(pfx, e.VPNAddr); err != nil {
					log.Printf("warning: add route %s via %s: %v", pfx, e.VPNAddr, err)
				}
			}
			// Try handshake immediately if the peer advertised an endpoint.
			if e.GetEndpoint().IsValid() {
				d.hsMgr.Initiate(e)
			}
			// Always start NAT negotiation for a confirmed path.
			toPeerID := hex.EncodeToString(e.ID[:])
			sendFn := func(payload []byte) error {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				return d.coordCli.SendSignal(ctx, toPeerID, payload)
			}
			d.natMgr.Start(context.Background(), e, sendFn)
		}

		d.coordCli.OnPeerRemoved = func(id [32]byte) {
			// Remove OS routes that were installed for this peer's subnets.
			if e, ok := peerTbl.LookupByID(id); ok {
				for _, pfx := range e.SubnetRoutes {
					if err := d.routeMgr.Remove(pfx); err != nil {
						log.Printf("warning: remove route %s: %v", pfx, err)
					}
				}
			}
			// Tear down any relay proxy held for the departing peer.
			d.mu.Lock()
			proxy := d.relayProxies[id]
			delete(d.relayProxies, id)
			d.mu.Unlock()
			if proxy != nil {
				_ = proxy.Close()
			}
		}

		d.coordCli.OnSignal = d.natMgr.DeliverSignal

		// When the coordinator assigns a VPN address, create the TUN and install the mesh route.
		d.coordCli.OnVPNAddrAssigned = func(vpnAddr netip.Addr, networkCIDR string) {
			d.mu.Lock()
			// If we already have a TUN, nothing to do.
			if d.tunDev != nil {
				d.mu.Unlock()
				return
			}
			d.mu.Unlock()

			// Determine the network prefix for the TUN and mesh route.
			var prefix netip.Prefix
			if networkCIDR != "" {
				netCIDR, err := netip.ParsePrefix(networkCIDR)
				if err != nil {
					log.Printf("warning: invalid network_cidr from coord %q: %v; falling back to /24", networkCIDR, err)
					prefix = netip.PrefixFrom(vpnAddr, 24)
				} else {
					// Replace the host portion with this node's assigned VPN address.
					prefix = netip.PrefixFrom(vpnAddr, netCIDR.Bits())
				}
			} else {
				log.Printf("warning: coordinator did not provide network_cidr; assuming /24")
				prefix = netip.PrefixFrom(vpnAddr, 24)
			}

			mtu := cfg.Node.MTU
			if mtu == 0 {
				mtu = 1420
			}
			ifaceName := cfg.Node.IfaceName
			if ifaceName == "" {
				ifaceName = "tun0"
			}

			tunDev, err := tun.CreateTUN(ifaceName, prefix, mtu)
			if err != nil {
				log.Printf("warning: failed to create TUN in coord mode: %v (data plane disabled)", err)
				return
			}

			d.mu.Lock()
			d.tunDev = tunDev
			d.mu.Unlock()

			// Wire the new TUN into the dispatcher.
			d.disp.SetTUN(tunDev)

			// Install the mesh route for the network prefix via the TUN address.
			if err := d.routeMgr.Add(prefix, vpnAddr); err != nil {
				log.Printf("warning: add mesh route %s via %s: %v", prefix, vpnAddr, err)
			}

			// Update IPC status now that we have a VPN address.
			d.updateIPCStatus()
		}
	}

	// Wire up IPC server
	socketPath := cfg.Daemon.SocketPath
	if socketPath == "" {
		socketPath = intconfig.DefaultSocketPath()
	}
	d.ipcSrv = NewIPCServer(socketPath, func() {
		d.Stop()
	})

	// Wire up DNS stub resolver if enabled.
	if cfg.DNS.Enabled {
		lookup := func(name string) (netip.Addr, bool) {
			if e, ok := peerTbl.LookupByName(name); ok {
				return e.VPNAddr, true
			}
			return netip.Addr{}, false
		}
		d.dnsSrv = dns.New(cfg.DNS.Domain, lookup)
		if err := d.dnsSrv.Start(cfg.DNS.ListenAddr); err != nil {
			log.Printf("warning: DNS resolver failed to start: %v", err)
			d.dnsSrv = nil
		}
	}

	// Wire up mDNS LAN discovery if enabled and we have a VPN address.
	// In coord mode, mDNS can only start after VPN address is assigned.
	// We wire it up lazily in OnVPNAddrAssigned if needed, but for now
	// it's only available in static mode.
	if cfg.MDNS.Enabled && vpnPrefix.IsValid() {
		mdnsName := cfg.MDNS.Name
		if mdnsName == "" {
			if h, err := os.Hostname(); err == nil {
				mdnsName = h
			} else {
				mdnsName = "veld"
			}
		}

		var dataPort uint16
		if laddr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
			dataPort = uint16(laddr.Port)
		}

		disc, err := mdns.New(localID, mdnsName, vpnPrefix.Addr(), dataPort,
			func(e *peer.Entry, ep netip.AddrPort) {
				if ep.IsValid() {
					e.SetEndpoint(ep)
				}
				peerTbl.Upsert(e)
				d.hsMgr.Initiate(e)
			})
		if err != nil {
			log.Printf("warning: mDNS discovery failed to initialize: %v", err)
		} else {
			d.mdnsDisco = disc
		}
	}

	return d, nil
}

func buildPeerTable(peerCfgs []intconfig.PeerConfig) (*peer.Table, error) {
	tbl := peer.New()
	for _, pc := range peerCfgs {
		ed25519Bytes, err := base64.StdEncoding.DecodeString(pc.Ed25519Public)
		if err != nil || len(ed25519Bytes) != 32 {
			return nil, fmt.Errorf("peer %q: invalid ed25519_public: %v", pc.Name, err)
		}
		x25519Bytes, err := base64.StdEncoding.DecodeString(pc.X25519Public)
		if err != nil || len(x25519Bytes) != 32 {
			return nil, fmt.Errorf("peer %q: invalid x25519_public: %v", pc.Name, err)
		}
		vpnAddr, err := netip.ParseAddr(pc.VPNAddr)
		if err != nil {
			return nil, fmt.Errorf("peer %q: invalid vpn_addr: %w", pc.Name, err)
		}

		var id, x25519 [32]byte
		copy(id[:], ed25519Bytes)
		copy(x25519[:], x25519Bytes)

		var routes []netip.Prefix
		for _, r := range pc.SubnetRoutes {
			pfx, err := netip.ParsePrefix(r)
			if err != nil {
				return nil, fmt.Errorf("peer %q: invalid subnet_route %q: %w", pc.Name, r, err)
			}
			routes = append(routes, pfx)
		}

		e := &peer.Entry{ID: id, X25519Pub: x25519, VPNAddr: vpnAddr, Name: pc.Name, SubnetRoutes: routes}
		if pc.Endpoint != "" {
			ep, err := netip.ParseAddrPort(pc.Endpoint)
			if err != nil {
				return nil, fmt.Errorf("peer %q: invalid endpoint: %w", pc.Name, err)
			}
			e.SetEndpoint(ep)
		}
		tbl.Upsert(e)
	}
	return tbl, nil
}

// selfInterface returns the name of veld's own TUN interface, or "" while
// no TUN exists (coord mode until the coordinator assigns the VPN address).
func (d *Daemon) selfInterface() string {
	d.mu.Lock()
	t := d.tunDev
	d.mu.Unlock()
	if t == nil {
		return ""
	}
	return t.Name()
}

// Start launches the dispatcher, coord client, mDNS discovery, and IPC server goroutines.
func (d *Daemon) Start() {
	d.disp.Start()
	if d.coordCli != nil {
		d.coordCli.Start()
	}
	if d.mdnsDisco != nil {
		d.mdnsDisco.Start()
	}
	if d.ipcSrv != nil {
		if err := d.ipcSrv.Start(); err != nil {
			log.Printf("ipc server: %v", err)
		} else {
			d.updateIPCStatus()
		}
	}
}

// Stop signals all components to exit.
func (d *Daemon) Stop() {
	d.disp.Stop()
	d.mu.Lock()
	proxies := d.relayProxies
	d.relayProxies = nil
	// Close our TUN if we created one.
	if d.tunDev != nil {
		_ = d.tunDev.Close()
		d.tunDev = nil
	}
	d.mu.Unlock()
	for _, p := range proxies {
		_ = p.Close()
	}
	if d.coordCli != nil {
		d.coordCli.Stop()
	}
	if d.dnsSrv != nil {
		d.dnsSrv.Stop()
	}
	if d.mdnsDisco != nil {
		d.mdnsDisco.Stop()
	}
	if d.routeMgr != nil {
		_ = d.routeMgr.Close()
	}
	if d.ipcSrv != nil {
		d.ipcSrv.Stop()
	}
}

// Wait blocks until all components have exited.
func (d *Daemon) Wait() {
	d.disp.Wait()
	if d.coordCli != nil {
		d.coordCli.Wait()
	}
}

// updateIPCStatus builds and sends the current status to the IPC server.
func (d *Daemon) updateIPCStatus() {
	if d.ipcSrv == nil {
		return
	}

	d.mu.Lock()
	vpnAddr := d.vpnAddr
	peerID := d.peerID
	coordAddr := d.coordAddr
	d.mu.Unlock()

	// If coord is running, get the assigned VPN address
	if d.coordCli != nil {
		vpnAddr = d.coordCli.VPNAddr()
		peerID = d.coordCli.PeerID()
	}

	peers := peerTableSnapshot(d.peerTbl)
	if peers == nil {
		peers = []PeerStatus{}
	}

	st := StatusResponse{
		Running:   true,
		VPNAddr:   vpnAddr.String(),
		PeerID:    peerID,
		NetworkID: hex.EncodeToString(d.networkID[:]),
		CoordAddr: coordAddr,
		Peers:     peers,
	}
	d.ipcSrv.UpdateStatus(st)
}
