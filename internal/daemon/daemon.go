// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package daemon

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
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

	mu        sync.Mutex
	vpnAddr   netip.Addr
	peerID    string
	coordAddr string
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
			tunDev.Close()
		}
		return nil, fmt.Errorf("listen %s: %w", cfg.Node.ListenAddr, err)
	}

	peerTbl, err := buildPeerTable(cfg.Peers)
	if err != nil {
		if tunDev != nil {
			tunDev.Close()
		}
		conn.Close()
		return nil, fmt.Errorf("build peer table: %w", err)
	}

	d := New(localID, networkID, tunDev, conn, peerTbl)
	d.routeMgr = route.New()

	// If this node advertises subnet routes, enable IP forwarding on Linux.
	if len(cfg.Node.SubnetRoutes) > 0 {
		if err := route.EnableIPForward(); err != nil {
			fmt.Printf("warning: enable ip_forward: %v\n", err)
		}
	}

	// In static mode, install OS routes for any subnet routes declared in the
	// static peer config. These are installed once at startup; they're removed by Stop().
	if cfg.Coord.Addr == "" {
		for _, e := range peerTbl.List() {
			for _, pfx := range e.SubnetRoutes {
				if err := d.routeMgr.Add(pfx, e.VPNAddr); err != nil {
					fmt.Printf("warning: add route %s via %s: %v\n", pfx, e.VPNAddr, err)
				}
			}
		}
	}

	// Wire up TOFU key pinning. The store lives next to the identity file.
	tofuPath := filepath.Join(filepath.Dir(cfg.Node.IdentityPath), "tofu.json")
	tofuStore, err := tofu.New(tofuPath)
	if err != nil {
		if tunDev != nil {
			tunDev.Close()
		}
		conn.Close()
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

		d.coordCli.OnPeerAdded = func(e *peer.Entry) {
			// Install OS routes for any subnets this peer advertises.
			for _, pfx := range e.SubnetRoutes {
				if err := d.routeMgr.Add(pfx, e.VPNAddr); err != nil {
					fmt.Printf("warning: add route %s via %s: %v\n", pfx, e.VPNAddr, err)
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
						fmt.Printf("warning: remove route %s: %v\n", pfx, err)
					}
				}
			}
		}

		d.coordCli.OnSignal = d.natMgr.DeliverSignal
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
			fmt.Printf("warning: DNS resolver failed to start: %v\n", err)
			d.dnsSrv = nil
		}
	}

	// Wire up mDNS LAN discovery if enabled and we have a VPN address.
	// Only available in static mode (coord assigns the VPN address dynamically).
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
			fmt.Printf("warning: mDNS discovery failed to initialize: %v\n", err)
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
		d.ipcSrv.Start()
		d.updateIPCStatus()
	}
}

// Stop signals all components to exit.
func (d *Daemon) Stop() {
	d.disp.Stop()
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
		d.routeMgr.Close()
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
