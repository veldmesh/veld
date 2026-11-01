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
	"strings"
	"sync"
	"time"

	"github.com/veldmesh/veld/internal/coexist"
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

var createTUN = tun.CreateTUN

type Daemon struct {
	disp             *dataplane.Dispatcher
	hsMgr            *handshake.Manager
	coordCli         *coord.Client
	natMgr           *nat.Manager
	dnsSrv           *dns.Resolver
	mdnsDisco        *mdns.Discovery
	routeMgr         route.Manager
	restoreIPForward func() error
	ipcSrv           *IPCServer
	peerTbl          *peer.Table
	localID          *crypto.Identity
	networkID        [16]byte

	mu           sync.Mutex
	vpnAddr      netip.Addr
	peerID       string
	coordAddr    string
	relayProxies map[[32]byte]*relay.Proxy
	tunDev       tun.TUN
}

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
	disp.OnRekeyRequired = hsMgr.Initiate
	disp.OnHandshakePacket = hsMgr.HandlePacket
	hsMgr.OnSessionEstablished = disp.FlushHoldQueue
	disp.OnSessionEstablished = disp.FlushHoldQueue

	return &Daemon{
		disp:      disp,
		hsMgr:     hsMgr,
		peerTbl:   peerTbl,
		localID:   localID,
		networkID: networkID,
		tunDev:    t,
	}
}

const legacyIfaceName = "tun0"

func resolveIfaceName(printf coexist.Printf, configured string) string {
	switch configured {
	case "":
		return tun.DefaultIfaceName()
	case legacyIfaceName:
		_, _ = printf("veld: config node.iface_name %q is the legacy default; using the platform default %q instead (a dedicated name avoids clashing with OpenVPN's tun0)\n", legacyIfaceName, tun.DefaultIfaceName())
		return tun.DefaultIfaceName()
	default:
		return configured
	}
}

func resolveTunMTU(cfg *intconfig.Config) int {
	if cfg.Node.MTU != 0 {
		return cfg.Node.MTU
	}
	return 1420
}

func NewFromConfig(cfg *intconfig.Config) (*Daemon, error) {
	localID, err := intconfig.LoadOrGenerate(cfg.Node.IdentityPath)
	if err != nil {
		return nil, fmt.Errorf("load identity: %w", err)
	}

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

	var tunDev tun.TUN
	var vpnPrefix netip.Prefix

	if cfg.Node.VPNAddr != "" {
		var err error
		vpnPrefix, err = netip.ParsePrefix(cfg.Node.VPNAddr)
		if err != nil {
			return nil, fmt.Errorf("invalid vpn_addr: %w", err)
		}
	}

	if cfg.Coord.Addr == "" {
		if vpnPrefix.IsValid() {
			ifaceName := resolveIfaceName(fmt.Printf, cfg.Node.IfaceName)
			tunDev, err = createTUN(ifaceName, vpnPrefix, resolveTunMTU(cfg), cfg.Node.Userspace)
			if err != nil {
				return nil, fmt.Errorf("create tun: %w", err)
			}
		}
	}

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
	userspace := cfg.Node.Userspace

	if !userspace {
		d.routeMgr = route.New()
		coexist.Report(fmt.Printf, d.selfInterface(), vpnPrefix)

		if len(cfg.Node.SubnetRoutes) > 0 {
			restore, err := route.EnableIPForward()
			if err != nil {
				fmt.Printf("warning: enable ip_forward: %v\n", err)
			} else {
				fmt.Printf("enabled IPv4 forwarding for subnet routes %v (restored on exit)\n", cfg.Node.SubnetRoutes)
				d.restoreIPForward = restore
			}
		}
	}

	if cfg.Coord.Addr == "" && !userspace {
		for _, e := range peerTbl.List() {
			d.addPeerRoutes(e)
		}
	}

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

	replayPath := filepath.Join(filepath.Dir(cfg.Node.IdentityPath), "handshake-replay.json")
	if err := d.hsMgr.UseReplayState(replayPath); err != nil {
		if tunDev != nil {
			_ = tunDev.Close()
		}
		_ = conn.Close()
		return nil, fmt.Errorf("load handshake replay state: %w", err)
	}

	if cfg.Coord.Addr != "" {
		d.mu.Lock()
		d.coordAddr = cfg.Coord.Addr
		d.mu.Unlock()

		hostname, _ := os.Hostname()
		coordCfg := coord.Config{
			ServerAddr:   cfg.Coord.Addr,
			NetworkID:    cfg.Coord.NetworkID,
			Token:        cfg.Coord.Token,
			Identity:     localID,
			LocalName:    advertisedPeerName(cfg.MDNS.Name, hostname),
			Endpoint:     advertisedEndpoint(cfg.Node.ListenAddr),
			SubnetRoutes: cfg.Node.SubnetRoutes,
			PeerTable:    peerTbl,
			TLSInsecure:  cfg.Coord.TLSInsecure,
		}
		d.coordCli = coord.New(coordCfg)

		localPort := uint16(0)
		if laddr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
			localPort = uint16(laddr.Port)
		}

		d.natMgr = nat.New(conn, localPort, cfg.Coord.STUNServer, localID, peerTbl)
		d.disp.OnNATProbePacket = d.natMgr.HandleProbe

		d.natMgr.OnEndpointDiscovered = func(peerID [32]byte, ep netip.AddrPort) {
			peerTbl.UpdateEndpoint(peerID, ep)
			if e, ok := peerTbl.LookupByID(peerID); ok {
				d.hsMgr.Initiate(e)
			}
		}

		if cfg.Coord.RelayAddr != "" {
			relayKeyBytes, err := base64.StdEncoding.DecodeString(cfg.Coord.RelayX25519)
			if err != nil || len(relayKeyBytes) != 32 {
				fmt.Printf("warning: invalid coord.relay_x25519, relay fallback disabled\n")
			} else {
				var relayKey [32]byte
				copy(relayKey[:], relayKeyBytes)

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
						fmt.Printf("warning: relay dial for peer %x: %v\n", peerID[:8], err)
						return
					}
					proxy, err := relay.NewProxy(rc, dataTarget)
					if err != nil {
						_ = rc.Close()
						fmt.Printf("warning: relay proxy for peer %x: %v\n", peerID[:8], err)
						return
					}
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
			if !userspace {
				d.addPeerRoutes(e)
			}
			if e.GetEndpoint().IsValid() {
				d.hsMgr.Initiate(e)
			}
			toPeerID := hex.EncodeToString(e.ID[:])
			sendFn := func(payload []byte) error {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				return d.coordCli.SendSignal(ctx, toPeerID, payload)
			}
			d.natMgr.Start(context.Background(), e, sendFn)
		}

		d.coordCli.OnPeerRemoved = func(id [32]byte) {
			if !userspace {
				if e, ok := peerTbl.LookupByID(id); ok {
					for _, pfx := range e.SubnetRoutes {
						if err := d.routeMgr.Remove(pfx); err != nil {
							fmt.Printf("warning: remove route %s: %v\n", pfx, err)
						}
					}
				}
			}
			d.mu.Lock()
			proxy := d.relayProxies[id]
			delete(d.relayProxies, id)
			d.mu.Unlock()
			if proxy != nil {
				_ = proxy.Close()
			}
			d.hsMgr.OnPeerRemoved(id)
		}

		d.coordCli.OnSignal = d.natMgr.DeliverSignal

		d.coordCli.OnVPNAddrAssigned = d.onVPNAddrAssigned(cfg, conn, userspace)
	}

	socketPath := cfg.Daemon.SocketPath
	if socketPath == "" {
		socketPath = intconfig.DefaultSocketPath()
	}
	d.ipcSrv = NewIPCServer(socketPath, func() {
		d.Stop()
	})

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

	if vpnPrefix.IsValid() && !userspace {
		disc, err := d.newMDNSDiscovery(cfg, conn, vpnPrefix.Addr())
		if err != nil {
			fmt.Printf("warning: mDNS discovery failed to initialize: %v\n", err)
		} else if disc != nil {
			d.mdnsDisco = disc
		}
	}

	return d, nil
}

func (d *Daemon) newMDNSDiscovery(cfg *intconfig.Config, conn net.PacketConn, vpnAddr netip.Addr) (*mdns.Discovery, error) {
	if !cfg.MDNS.Enabled {
		return nil, nil
	}

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

	coordMode := cfg.Coord.Addr != ""
	return mdns.New(d.localID, mdnsName, vpnAddr, dataPort,
		func(e *peer.Entry, ep netip.AddrPort) { d.onMDNSPeer(e, ep, coordMode) })
}

func (d *Daemon) onVPNAddrAssigned(cfg *intconfig.Config, conn net.PacketConn, userspace bool) func(vpnAddr netip.Addr, networkCIDR string) {
	return func(vpnAddr netip.Addr, networkCIDR string) {
		d.mu.Lock()
		existing := d.tunDev
		oldDisco := d.mdnsDisco
		d.mu.Unlock()
		if existing != nil && existing.Addr().Addr() == vpnAddr {
			return
		}

		prefix := deriveMeshPrefix(vpnAddr, networkCIDR)

		ifaceName := resolveIfaceName(fmt.Printf, cfg.Node.IfaceName)
		newTun, err := createTUN(ifaceName, prefix, resolveTunMTU(cfg), userspace)
		if err != nil {
			log.Printf("warning: failed to create TUN in coord mode: %v (data plane disabled)", err)
			if existing != nil {
				d.mu.Lock()
				d.vpnAddr = existing.Addr().Addr()
				d.mu.Unlock()
			}
			d.updateIPCStatus()
			return
		}

		d.disp.SetTUN(newTun)

		if existing != nil {
			log.Printf("coord re-assigned VPN address %s (was %s); recreating TUN",
				vpnAddr, existing.Addr().Addr())
			_ = existing.Close()
		}
		if oldDisco != nil {
			oldDisco.Stop()
			d.mu.Lock()
			d.mdnsDisco = nil
			d.mu.Unlock()
		}

		d.mu.Lock()
		d.tunDev = newTun
		d.mu.Unlock()

		if !userspace {
			if disc, err := d.newMDNSDiscovery(cfg, conn, vpnAddr); err != nil {
				log.Printf("warning: mDNS discovery failed to initialize: %v", err)
			} else if disc != nil {
				d.mu.Lock()
				d.mdnsDisco = disc
				d.mu.Unlock()
				disc.Start()
			}
		}

		d.updateIPCStatus()
	}
}

func (d *Daemon) onMDNSPeer(e *peer.Entry, ep netip.AddrPort, coordMode bool) {
	if known, ok := d.peerTbl.LookupByID(e.ID); ok {
		if known.X25519Pub != e.X25519Pub || !ep.IsValid() {
			return
		}
		if !known.GetEndpoint().IsValid() {
			d.peerTbl.UpdateEndpoint(known.ID, ep)
		}
		d.hsMgr.Initiate(known)
		return
	}
	if coordMode {
		return
	}
	if ep.IsValid() {
		e.SetEndpoint(ep)
	}
	if !d.peerTbl.Upsert(e) {
		return
	}
	d.hsMgr.Initiate(e)
}

func advertisedEndpoint(listenAddr string) string {
	ep, err := netip.ParseAddrPort(listenAddr)
	if err != nil || ep.Port() == 0 || ep.Addr().IsUnspecified() {
		return ""
	}
	return listenAddr
}

const peerNameMaxLen = 63

func advertisedPeerName(configured, hostname string) string {
	name := configured
	if name == "" {
		name = hostname
	}
	var b strings.Builder
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'A' && c <= 'Z':
			b.WriteByte(c + ('a' - 'A'))
		case (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'):
			b.WriteByte(c)
		default:
			b.WriteByte('-')
		}
	}
	s := strings.Trim(b.String(), "-")
	if len(s) > peerNameMaxLen {
		s = strings.TrimRight(s[:peerNameMaxLen], "-")
	}
	if s == "" {
		return "node"
	}
	return s
}

func (d *Daemon) addPeerRoutes(e *peer.Entry) {
	var mesh netip.Prefix
	d.mu.Lock()
	if d.tunDev != nil {
		mesh = d.tunDev.Addr()
	}
	d.mu.Unlock()
	for _, pfx := range e.SubnetRoutes {
		if err := route.CheckPeerRoute(pfx, mesh); err != nil {
			fmt.Printf("warning: ignoring subnet route from %s: %v\n", e.VPNAddr, err)
			continue
		}
		d.logRouteCollisions(pfx)
		if err := d.routeMgr.Add(pfx, e.VPNAddr); err != nil {
			fmt.Printf("warning: add route %s via %s: %v\n", pfx, e.VPNAddr, err)
		}
	}
}

func deriveMeshPrefix(vpnAddr netip.Addr, networkCIDR string) netip.Prefix {
	if networkCIDR == "" {
		log.Printf("warning: coordinator did not provide network_cidr; assuming /24")
		return netip.PrefixFrom(vpnAddr, 24)
	}
	netCIDR, err := netip.ParsePrefix(networkCIDR)
	if err != nil {
		log.Printf("warning: invalid network_cidr from coord %q: %v; falling back to /24", networkCIDR, err)
		return netip.PrefixFrom(vpnAddr, 24)
	}
	return netip.PrefixFrom(vpnAddr, netCIDR.Bits())
}

func (d *Daemon) selfInterface() string {
	d.mu.Lock()
	t := d.tunDev
	d.mu.Unlock()
	if t == nil {
		return ""
	}
	return t.Name()
}

func (d *Daemon) logRouteCollisions(pfx netip.Prefix) {
	for _, c := range coexist.CheckRoute(pfx, d.selfInterface()) {
		fmt.Printf("%s\n", c)
	}
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
			if ep, err := netip.ParseAddrPort(pc.Endpoint); err == nil {
				e.SetEndpoint(ep)
			}
		}
		if !tbl.Upsert(e) {
			return nil, fmt.Errorf("peer %q: vpn_addr %s is already used by another peer", pc.Name, vpnAddr)
		}
	}
	return tbl, nil
}

func (d *Daemon) Start() {
	d.disp.Start()
	if d.coordCli != nil {
		d.coordCli.Start()
	}
	if disc := d.mdnsDiscovery(); disc != nil {
		disc.Start()
	}
	if d.ipcSrv != nil {
		if err := d.ipcSrv.Start(); err != nil {
			log.Printf("ipc server: %v", err)
		} else {
			d.updateIPCStatus()
		}
	}
}

func (d *Daemon) Stop() {
	d.disp.Stop()
	d.mu.Lock()
	proxies := d.relayProxies
	d.relayProxies = nil
	d.tunDev = nil
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
	if disc := d.mdnsDiscovery(); disc != nil {
		disc.Stop()
	}
	if d.routeMgr != nil {
		_ = d.routeMgr.Close()
	}
	if d.restoreIPForward != nil {
		_ = d.restoreIPForward()
	}
	if d.ipcSrv != nil {
		d.ipcSrv.Stop()
	}
}

func (d *Daemon) mdnsDiscovery() *mdns.Discovery {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.mdnsDisco
}

func (d *Daemon) Wait() {
	d.disp.Wait()
	if d.coordCli != nil {
		d.coordCli.Wait()
	}
}

func (d *Daemon) updateIPCStatus() {
	if d.ipcSrv == nil {
		return
	}

	d.mu.Lock()
	vpnAddr := d.vpnAddr
	peerID := d.peerID
	coordAddr := d.coordAddr
	tun := d.tunDev
	d.mu.Unlock()

	if tun != nil {
		vpnAddr = tun.Addr().Addr()
	} else if d.coordCli != nil {
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
