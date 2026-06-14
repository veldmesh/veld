// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: BUSL-1.1
package coord

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/netip"
	"sync"
	"time"

	"crypto/tls"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	coordv1 "github.com/veldmesh/veld/gen/veld/coord/v1"
	"github.com/veldmesh/veld/internal/crypto"
	"github.com/veldmesh/veld/internal/peer"
)

const (
	retryMin = 2 * time.Second
	retryMax = 60 * time.Second
)

// Config configures the coord client.
type Config struct {
	ServerAddr   string           // gRPC address, e.g. "coord.example.com:50051"
	NetworkID    string           // UUID of the network to join
	Token        string           // auth token
	Identity     *crypto.Identity // local Ed25519/X25519 identity
	LocalName    string           // peer name to register (typically hostname)
	Endpoint     string           // UDP endpoint to advertise, e.g. "1.2.3.4:51820"
	SubnetRoutes []string         // CIDR prefixes to advertise (e.g. "192.168.1.0/24")
	PeerTable    *peer.Table      // peer table kept in sync with coord server events
	TLSInsecure  bool             // disable TLS cert verification (testing only)
}

// Client maintains a live connection to the coord server, registers the local
// daemon, and keeps the peer table in sync with Join/Leave/EndpointUpdate events.
// Reconnects automatically with exponential backoff on transient errors.
type Client struct {
	cfg Config

	mu      sync.Mutex
	vpnAddr netip.Addr
	peerID  string

	gcMu sync.Mutex
	gc   coordv1.CoordClient // set when connected; nil when not

	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Callbacks invoked on peer table changes. Set before calling Start.
	OnPeerAdded   func(e *peer.Entry)
	OnPeerRemoved func(id [32]byte)
	// OnSignal is called when an opaque signal arrives addressed to this peer.
	OnSignal func(fromPeerID string, payload []byte)
	// OnRouteUpdate is called when a peer's advertised subnet routes change.
	// routes is the new set of prefixes (empty slice means peer removed all routes).
	OnRouteUpdate func(peerID [32]byte, routes []netip.Prefix)
}

// New creates a Client. Call Start to connect.
func New(cfg Config) *Client {
	return &Client{cfg: cfg}
}

// VPNAddr returns the VPN address assigned by the coord server after a successful
// registration. Returns the zero value until Start has completed a registration.
func (c *Client) VPNAddr() netip.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.vpnAddr
}

// PeerID returns the hex-encoded peer ID assigned by the coord server.
// Returns "" until Start has completed a registration.
func (c *Client) PeerID() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.peerID
}

// Start connects to the coord server and begins maintaining the peer table.
// Returns immediately; all work runs in a background goroutine.
func (c *Client) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	c.wg.Add(1)
	go c.run(ctx)
}

// Stop cancels the background goroutine and sends Leave to the coord server.
// Call Wait to block until the goroutine has exited.
func (c *Client) Stop() {
	if c.cancel != nil {
		c.cancel()
	}
}

// Wait blocks until the background goroutine has exited.
func (c *Client) Wait() {
	c.wg.Wait()
}

// SendSignal sends an opaque signal to another peer via the coord server.
// Returns immediately with an error if not yet connected.
func (c *Client) SendSignal(ctx context.Context, toPeerID string, payload []byte) error {
	c.gcMu.Lock()
	gc := c.gc
	c.gcMu.Unlock()
	if gc == nil {
		return errors.New("coord client not connected")
	}
	c.mu.Lock()
	fromPeerID := c.peerID
	token := c.cfg.Token
	c.mu.Unlock()
	_, err := gc.SendSignal(ctx, &coordv1.SendSignalRequest{
		Token:      token,
		FromPeerId: fromPeerID,
		ToPeerId:   toPeerID,
		Payload:    payload,
	})
	return err
}

func (c *Client) run(ctx context.Context) {
	defer c.wg.Done()

	opts := []grpc.DialOption{}
	if c.cfg.TLSInsecure {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{})))
	}

	grpcConn, err := grpc.NewClient(c.cfg.ServerAddr, opts...)
	if err != nil {
		return
	}
	defer func() { _ = grpcConn.Close() }()
	gc := coordv1.NewCoordClient(grpcConn)

	c.gcMu.Lock()
	c.gc = gc
	c.gcMu.Unlock()
	defer func() {
		c.gcMu.Lock()
		c.gc = nil
		c.gcMu.Unlock()
	}()

	backoff := retryMin
	for ctx.Err() == nil {
		if err := c.registerAndWatch(ctx, gc); err == nil {
			break // nil means ctx was cancelled — normal shutdown
		}
		// Transient error: wait then retry.
		select {
		case <-ctx.Done():
		case <-time.After(backoff):
		}
		if backoff < retryMax {
			backoff *= 2
			if backoff > retryMax {
				backoff = retryMax
			}
		}
	}

	c.sendLeave(gc)
}

// registerAndWatch runs one registration+watch cycle.
// Returns nil if ctx was cancelled (clean stop), non-nil for transient errors.
func (c *Client) registerAndWatch(ctx context.Context, gc coordv1.CoordClient) error {
	ed25519B64 := base64.StdEncoding.EncodeToString(c.cfg.Identity.Ed25519Public)
	x25519B64 := base64.StdEncoding.EncodeToString(c.cfg.Identity.X25519Public[:])

	resp, err := gc.Register(ctx, &coordv1.RegisterRequest{
		NetworkId:     c.cfg.NetworkID,
		Token:         c.cfg.Token,
		Name:          c.cfg.LocalName,
		Ed25519Public: ed25519B64,
		X25519Public:  x25519B64,
		Endpoint:      c.cfg.Endpoint,
		SubnetRoutes:  c.cfg.SubnetRoutes,
	})
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return err
	}

	vpnAddr, err := netip.ParseAddr(resp.VpnAddr)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.vpnAddr = vpnAddr
	c.peerID = resp.PeerId
	c.mu.Unlock()

	// Stream peer events (and signals addressed to us) until ctx is cancelled.
	// The server sends a synthetic JOIN snapshot of current peers at stream
	// start, so no separate ListPeers call is needed.
	stream, err := gc.Watch(ctx, &coordv1.WatchRequest{
		NetworkId: c.cfg.NetworkID,
		Token:     c.cfg.Token,
		PeerId:    resp.PeerId,
	})
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return err
	}

	myID := resp.PeerId
	for {
		ev, err := stream.Recv()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		c.handleEvent(ev, myID)
	}
}

func (c *Client) handleEvent(ev *coordv1.PeerEvent, myID string) {
	if ev.Type == coordv1.EventType_SIGNAL {
		if ev.Signal != nil && c.OnSignal != nil {
			c.OnSignal(ev.Signal.FromPeerId, ev.Signal.Payload)
		}
		return
	}
	if ev.Peer == nil || ev.Peer.Id == myID {
		return
	}
	switch ev.Type {
	case coordv1.EventType_JOIN:
		entry := peerFromProto(ev.Peer)
		if entry == nil {
			return
		}
		c.cfg.PeerTable.Upsert(entry)
		if c.OnPeerAdded != nil {
			c.OnPeerAdded(entry)
		}

	case coordv1.EventType_ENDPOINT_UPDATE:
		if ev.Peer.Endpoint == "" {
			return
		}
		ep, err := netip.ParseAddrPort(ev.Peer.Endpoint)
		if err != nil {
			return
		}
		id, ok := hexToID(ev.Peer.Id)
		if !ok {
			return
		}
		c.cfg.PeerTable.UpdateEndpoint(id, ep)

	case coordv1.EventType_LEAVE:
		id, ok := hexToID(ev.Peer.Id)
		if !ok {
			return
		}
		c.cfg.PeerTable.Remove(id)
		if c.OnPeerRemoved != nil {
			c.OnPeerRemoved(id)
		}

	case coordv1.EventType_ROUTE_UPDATE:
		id, ok := hexToID(ev.Peer.Id)
		if !ok {
			return
		}
		var routes []netip.Prefix
		for _, r := range ev.Peer.SubnetRoutes {
			if pfx, err := netip.ParsePrefix(r); err == nil {
				routes = append(routes, pfx)
			}
		}
		if c.OnRouteUpdate != nil {
			c.OnRouteUpdate(id, routes)
		}
	}
}

func (c *Client) sendLeave(gc coordv1.CoordClient) {
	c.mu.Lock()
	pid := c.peerID
	c.mu.Unlock()
	if pid == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = gc.Leave(ctx, &coordv1.LeaveRequest{
		Token:  c.cfg.Token,
		PeerId: pid,
	})
}

// peerFromProto converts a proto Peer to a peer.Entry.
// Returns nil if required fields are missing or malformed (e.g. non-32-byte keys).
func peerFromProto(p *coordv1.Peer) *peer.Entry {
	ed25519Bytes, err := base64.StdEncoding.DecodeString(p.Ed25519Public)
	if err != nil || len(ed25519Bytes) != 32 {
		return nil
	}
	x25519Bytes, err := base64.StdEncoding.DecodeString(p.X25519Public)
	if err != nil || len(x25519Bytes) != 32 {
		return nil
	}
	vpnAddr, err := netip.ParseAddr(p.VpnAddr)
	if err != nil {
		return nil
	}

	var id, x25519 [32]byte
	copy(id[:], ed25519Bytes)
	copy(x25519[:], x25519Bytes)

	var routes []netip.Prefix
	for _, r := range p.SubnetRoutes {
		if pfx, err := netip.ParsePrefix(r); err == nil {
			routes = append(routes, pfx)
		}
	}

	e := &peer.Entry{ID: id, X25519Pub: x25519, VPNAddr: vpnAddr, Name: p.Name, SubnetRoutes: routes}
	if p.Endpoint != "" {
		if ep, err := netip.ParseAddrPort(p.Endpoint); err == nil {
			e.SetEndpoint(ep)
		}
	}
	return e
}

// hexToID decodes a 64-hex-char (32-byte) peer ID.
func hexToID(s string) ([32]byte, bool) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return [32]byte{}, false
	}
	var id [32]byte
	copy(id[:], b)
	return id, true
}
