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

// createTUN is the function used to create a TUN device. It is a package-level
// variable so tests can inject a failing implementation.
var createTUN = tun.CreateTUN

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
	// restoreIPForward puts IP forwarding back as it was before startup.
	restoreIPForward func() error
	ipcSrv           *IPCServer
	peerTbl          *peer.Table
	localID          *crypto.Identity
	networkID        [16]byte

	mu              sync.Mutex
	vpnAddr         netip.Addr
	peerID          string
	coordAddr       string
	relayProxies    map[[32]byte]*relay.Proxy // one relay proxy per peer ID
	tunDev          tun.TUN                   // veld's own TUN; nil in coord mode until the coordinator assigns the VPN address
	tofuMismatchLog map[string]time.Time      // last log time per VPN address for TOFU mismatch rate limiting
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

// legacyIfaceName is the interface name older veld versions baked into every
// new config and used as the create-time default. It is kept only to
// recognize such configs: a TUN named "tun0" cannot be created next to an
// OpenVPN-based VPN anyway (TUNSETIFF fails with EEXIST), so the stored
// value always migrates to the platform default.
const legacyIfaceName = "tun0"

// resolveIfaceName maps node.iface_name to the TUN name to create. The
// empty string means "platform default" (tun.DefaultIfaceName: "veld0" on
// Linux, "Veld" on Windows, "utun" on macOS). The legacy default "tun0"
// maps to the platform default too, with a one-line notice — veld can no
// longer honor a literal tun0 request, an accepted trade-off because that
// name breaks next to OpenVPN. Any other value is honored verbatim.
// Shared by static and coord mode so the default lives in exactly one place.
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

// resolveTunMTU returns the configured MTU or the 1420 default.
func resolveTunMTU(cfg *intconfig.Config) int {
	if cfg.Node.MTU != 0 {
		return cfg.Node.MTU
	}
	return 1420
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
			ifaceName := resolveIfaceName(fmt.Printf, cfg.Node.IfaceName)
			tunDev, err = createTUN(ifaceName, vpnPrefix, resolveTunMTU(cfg))
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

	// Commercial VPN coexistence: detect VPN tunnels and routing conflicts
	// at startup and log actionable guidance (kill switches, split tunneling,
	// CIDR overlaps). Detection never blocks startup.
	coexist.Report(fmt.Printf, d.selfInterface(), vpnPrefix)

	// If this node advertises subnet routes, enable IP forwarding on Linux.
	if len(cfg.Node.SubnetRoutes) > 0 {
		restore, err := route.EnableIPForward()
		if err != nil {
			fmt.Printf("warning: enable ip_forward: %v\n", err)
		} else {
			fmt.Printf("enabled IPv4 forwarding for subnet routes %v (restored on exit)\n", cfg.Node.SubnetRoutes)
			d.restoreIPForward = restore
		}
	}

	// In static mode, install OS routes for any subnet routes declared in the
	// static peer config. These are installed once at startup; they're removed by Stop().
	if cfg.Coord.Addr == "" {
		for _, e := range peerTbl.List() {
			d.addPeerRoutes(e)
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

	// Wire up TOFU mismatch logging with rate limiting (one log per address per 10 minutes).
	d.hsMgr.OnTOFUMismatch = func(vpnAddr string, fingerprint [32]byte) {
		d.logTOFUMismatch(vpnAddr)
	}

	// Handshake replay state lives there too, so a restart keeps rejecting
	// Inits it has already seen.
	replayPath := filepath.Join(filepath.Dir(cfg.Node.IdentityPath), "handshake-replay.json")
	if err := d.hsMgr.UseReplayState(replayPath); err != nil {
		if tunDev != nil {
			_ = tunDev.Close()
		}
		_ = conn.Close()
		return nil, fmt.Errorf("load handshake replay state: %w", err)
	}

	// Wire up coord client and NAT manager if configured.
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

		// Extract the data-plane UDP port for NAT candidate gathering.
		localPort := uint16(0)
		if laddr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
			localPort = uint16(laddr.Port)
		}

		d.natMgr = nat.New(conn, localPort, cfg.Coord.STUNServer, localID, peerTbl)
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
				fmt.Printf("warning: invalid coord.relay_x25519, relay fallback disabled\n")
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
					// Keep one proxy per peer: a previous fallback (or a
					// re-punch that timed out again) is replaced and closed.

					peerTbl.UpdateEndpoint(peerID, proxy.LocalAddr())
					if e, ok := peerTbl.LookupByID(peerID); ok {
						d.hsMgr.Initiate(e)
					}
				}
			}
		}

		d.coordCli.OnPeerAdded = func(e *peer.Entry) {
			// Install OS routes for any subnets this peer advertises.
			d.addPeerRoutes(e)
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
			// Tear down any relay proxy held for the departing peer.
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

		// When the coordinator assigns a VPN address, create the TUN so the
		// data plane comes up. Extracted for direct testability.
		d.coordCli.OnVPNAddrAssigned = d.onVPNAddrAssigned(cfg, conn)
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
	// mDNS needs a VPN address; in coord mode the address arrives after
	// registration, so discovery is wired there instead (see
	// onVPNAddrAssigned).
	if vpnPrefix.IsValid() {
		disc, err := d.newMDNSDiscovery(cfg, conn, vpnPrefix.Addr())
		if err != nil {
			fmt.Printf("warning: mDNS discovery failed to initialize: %v\n", err)
		} else if disc != nil {
			d.mdnsDisco = disc
		}
	}

	return d, nil
}

// newMDNSDiscovery builds the mDNS discovery service advertising vpnAddr and
// the data-plane UDP port, wired to upsert discovered LAN peers and initiate
// a handshake with them. Returns (nil, nil) if mDNS is disabled in cfg.
// Shared by the static-mode setup in NewFromConfig and the coord-mode
// onVPNAddrAssigned callback, since both need to build the same service once
// a VPN address is known.
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

// onVPNAddrAssigned returns the callback invoked when the coordinator
// assigns this daemon a VPN address. It derives the network prefix from the
// server-provided network CIDR (falling back to /24 with a warning), creates
// the TUN, wires it into the dispatcher, and (if enabled) starts mDNS LAN
// discovery advertising the assigned address. A re-registration that assigns
// a different address replaces the TUN and the mDNS advertisement; the same
// address is a no-op. TUN creation failure is non-fatal: the daemon keeps
// running without a data plane and still reports the assigned address in
// its status.
func (d *Daemon) onVPNAddrAssigned(cfg *intconfig.Config, conn net.PacketConn) func(vpnAddr netip.Addr, networkCIDR string) {
	return func(vpnAddr netip.Addr, networkCIDR string) {
		// Same address and TUN already up: nothing to do.
		d.mu.Lock()
		existing := d.tunDev
		oldDisco := d.mdnsDisco
		d.mu.Unlock()
		if existing != nil && existing.Addr().Addr() == vpnAddr {
			return
		}

		prefix := deriveMeshPrefix(vpnAddr, networkCIDR)

		// Create the new TUN first. If creation fails, keep the old TUN
		// running (the old address keeps working until the next re-registration).
		ifaceName := resolveIfaceName(fmt.Printf, cfg.Node.IfaceName)
		newTun, err := createTUN(ifaceName, prefix, resolveTunMTU(cfg))
		if err != nil {
			log.Printf("warning: failed to create TUN in coord mode: %v (data plane disabled)", err)
			if existing != nil {
				// Address change failed: the old TUN is still running with
				// the old address. Report that address instead of the new
				// coordinator-assigned one to avoid IPC status discrepancy.
				d.mu.Lock()
				d.vpnAddr = existing.Addr().Addr()
				d.mu.Unlock()
			}
			d.updateIPCStatus()
			return
		}

		// Wire the new TUN into the dispatcher before closing the old one.
		d.disp.SetTUN(newTun)

		if existing != nil {
			// Address changed on re-registration: drop the old TUN.
			log.Printf("coord re-assigned VPN address %s (was %s); recreating TUN",
				vpnAddr, existing.Addr().Addr())
			_ = existing.Close()
		}
		if oldDisco != nil {
			// The old advertisement names a stale VPN address; drop it so
			// the replacement below advertises the new one instead.
			oldDisco.Stop()
			d.mu.Lock()
			d.mdnsDisco = nil
			d.mu.Unlock()
		}

		d.mu.Lock()
		d.tunDev = newTun
		d.mu.Unlock()

		// Now that we have a VPN address, start mDNS LAN discovery: it was
		// not wired at construction time since coord mode has no address
		// until registration completes.
		if disc, err := d.newMDNSDiscovery(cfg, conn, vpnAddr); err != nil {
			log.Printf("warning: mDNS discovery failed to initialize: %v", err)
		} else if disc != nil {
			d.mu.Lock()
			d.mdnsDisco = disc
			d.mu.Unlock()
			disc.Start()
		}

		// Update IPC status now that we have a VPN address.
		d.updateIPCStatus()
	}
}

// onMDNSPeer handles a peer advertised on the LAN. mDNS records are
// unauthenticated, so they never change a known peer's identity, address or
// name: for a peer already known (from the coordinator or static config) with
// the same keys they only suggest an endpoint to try, and the handshake proves
// it. With a coordinator, the coordinator decides membership and unknown LAN
// peers are ignored. In LAN-only mode unknown peers are added, subject to the
// peer table's rule that an address or name belongs to its first owner (and
// to TOFU pinning on handshake).
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

// advertisedEndpoint returns the endpoint to register with the coordinator
// for listenAddr: the address itself when peers could dial it, or "" for a
// wildcard address (0.0.0.0:51820) or port 0, which tell a peer nothing. The
// coordinator rejects those, and NAT traversal finds the real endpoint.
func advertisedEndpoint(listenAddr string) string {
	ep, err := netip.ParseAddrPort(listenAddr)
	if err != nil || ep.Port() == 0 || ep.Addr().IsUnspecified() {
		return ""
	}
	return listenAddr
}

// peerNameMaxLen is the longest peer name the coord server accepts (a DNS label).
const peerNameMaxLen = 63

// advertisedPeerName returns the name this node registers with the coord.
// The configured name wins, then the hostname. The result is lowercased, every
// character other than a letter or digit becomes '-', leading and trailing
// hyphens are trimmed and the result is cut to a DNS label. "node" is used
// when nothing usable is left.
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

// addPeerRoutes installs OS routes for the subnets e advertises, skipping
// any that route.CheckPeerRoute refuses (default routes, the mesh itself).
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

// deriveMeshPrefix returns the prefix to configure on the TUN: the
// network CIDR from the server with this node's assigned address, or a
// /24 fallback (with a warning) when the server did not send one.
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

// selfInterface returns the name of veld's own TUN interface, or "" while
// no TUN exists (coord mode until the coordinator assigns the VPN address).
// Coexistence checks must resolve the name through this getter at check
// time, never capture it once at startup: in coord mode a startup capture
// would pin the pre-TUN empty string and make later checks misattribute
// veld's own routes to a commercial VPN.
func (d *Daemon) selfInterface() string {
	d.mu.Lock()
	t := d.tunDev
	d.mu.Unlock()
	if t == nil {
		return ""
	}
	return t.Name()
}

// logRouteCollisions warns when a route Veldmesh is about to install
// overlaps a route on another interface (e.g. a commercial VPN's). Veldmesh's
// own TUN routes are excluded via selfInterface, resolved at check time so
// a TUN created after startup (coord mode) is recognized.
func (d *Daemon) logRouteCollisions(pfx netip.Prefix) {
	for _, c := range coexist.CheckRoute(pfx, d.selfInterface()) {
		fmt.Printf("%s\n", c)
	}
}

// logTOFUMismatch logs a TOFU fingerprint mismatch for the given VPN address,
// rate-limited to once per 10 minutes per address.
func (d *Daemon) logTOFUMismatch(vpnAddr string) {
	d.mu.Lock()
	if d.tofuMismatchLog == nil {
		d.tofuMismatchLog = make(map[string]time.Time)
	}
	now := time.Now()
	if last, ok := d.tofuMismatchLog[vpnAddr]; ok && now.Sub(last) < 10*time.Minute {
		d.mu.Unlock()
		return
	}
	d.tofuMismatchLog[vpnAddr] = now
	d.mu.Unlock()

	log.Printf("tofu: dropped handshake for %s: it is pinned to a different key. If that node was replaced or reinstalled, run \"veld tofu forget %s\" on this node.", vpnAddr, vpnAddr)
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
