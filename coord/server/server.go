// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"net/netip"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	coordv1 "github.com/veldmesh/veld/gen/veld/coord/v1"
	coordcore "github.com/veldmesh/veld/coord/core"
)

// Server implements coordv1.CoordServer.
type Server struct {
	coordv1.UnimplementedCoordServer
	registry *Registry
	bus      *Bus
	enforcer coordcore.PlanEnforcer
	accounts coordcore.AccountStore
	audit    coordcore.AuditLogger
	subnet   coordcore.SubnetPolicy
	hooks    coordcore.LifecycleHooks
}

// New wires all components together. The registry must already be opened.
func New(
	registry *Registry,
	bus *Bus,
	enforcer coordcore.PlanEnforcer,
	accounts coordcore.AccountStore,
	audit coordcore.AuditLogger,
	subnet coordcore.SubnetPolicy,
	hooks coordcore.LifecycleHooks,
) *Server {
	return &Server{
		registry: registry,
		bus:      bus,
		enforcer: enforcer,
		accounts: accounts,
		audit:    audit,
		subnet:   subnet,
		hooks:    hooks,
	}
}

// Register assigns a VPN IP and records the peer.
func (s *Server) Register(ctx context.Context, req *coordv1.RegisterRequest) (*coordv1.RegisterResponse, error) {
	// Resolve token → account
	acc, err := s.accounts.Resolve(ctx, req.Token)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "invalid token")
	}

	// Ask the enforcer for the limit (-1 = unlimited) so we can enforce it
	// atomically inside the registry write transaction.
	machineLimit := s.enforcer.MachineLimitFor(ctx, req.NetworkId)

	// Decode base64 Ed25519 public key → use as peer ID (hex)
	ed25519Bytes, err := base64.StdEncoding.DecodeString(req.Ed25519Public)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid ed25519_public")
	}
	peerID := hex.EncodeToString(ed25519Bytes)

	// Validate and policy-check each advertised subnet route.
	var parsedRoutes []netip.Prefix
	for _, r := range req.SubnetRoutes {
		prefix, err := netip.ParsePrefix(r)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid subnet_route %q: %v", r, err)
		}
		if err := s.subnet.Allow(ctx, req.NetworkId, prefix); err != nil {
			return nil, status.Errorf(codes.PermissionDenied, "subnet route %q not permitted: %v", r, err)
		}
		parsedRoutes = append(parsedRoutes, prefix)
	}

	rec := peerRecord{
		ID:            peerID,
		Name:          req.Name,
		Ed25519Public: req.Ed25519Public,
		X25519Public:  req.X25519Public,
		Endpoint:      req.Endpoint,
		SubnetRoutes:  req.SubnetRoutes,
		RegisteredAt:  time.Now().Unix(),
		LastSeen:      time.Now().Unix(),
	}

	vpnAddr, err := s.registry.RegisterPeer(rec, req.NetworkId, machineLimit)
	if err != nil {
		if err == ErrMachineLimit {
			_ = s.audit.Log(ctx, coordcore.AuditEvent{
				Kind:      coordcore.AuditRegistrationRejected,
				AccountID: acc.ID,
				NetworkID: req.NetworkId,
				Detail:    "machine limit reached",
				At:        time.Now(),
			})
			return nil, status.Errorf(codes.ResourceExhausted, "machine limit reached")
		}
		return nil, status.Errorf(codes.Internal, "register peer: %v", err)
	}

	_ = s.accounts.RecordActivity(ctx, acc.ID)
	_ = s.audit.Log(ctx, coordcore.AuditEvent{
		Kind:      coordcore.AuditPeerRegistered,
		AccountID: acc.ID,
		NetworkID: req.NetworkId,
		PeerID:    peerID,
		At:        time.Now(),
	})

	// Fire lifecycle hooks for each advertised subnet.
	net, _, _ := s.registry.GetNetwork(req.NetworkId)
	peer := coordcore.Peer{ID: peerID, Name: req.Name, VPNAddr: vpnAddr, NetworkID: req.NetworkId}
	s.hooks.OnPeerRegistered(ctx, peer, net)
	for _, pfx := range parsedRoutes {
		s.hooks.OnSubnetRouteAdvertised(ctx, peer, pfx)
	}

	// Publish JOIN event to all watchers in this network.
	s.bus.Publish(req.NetworkId, &coordv1.PeerEvent{
		Type: coordv1.EventType_JOIN,
		Peer: &coordv1.Peer{
			Id:            peerID,
			Name:          req.Name,
			VpnAddr:       vpnAddr.String(),
			Ed25519Public: req.Ed25519Public,
			X25519Public:  req.X25519Public,
			Endpoint:      req.Endpoint,
			SubnetRoutes:  req.SubnetRoutes,
		},
	})

	return &coordv1.RegisterResponse{
		VpnAddr:   vpnAddr.String(),
		PeerId:    peerID,
		NetworkId: req.NetworkId,
	}, nil
}

// ListPeers returns all peers in the network.
func (s *Server) ListPeers(ctx context.Context, req *coordv1.ListPeersRequest) (*coordv1.ListPeersResponse, error) {
	if _, err := s.accounts.Resolve(ctx, req.Token); err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "invalid token")
	}

	peers, err := s.registry.ListPeers(req.NetworkId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list peers: %v", err)
	}

	var out []*coordv1.Peer
	for _, p := range peers {
		out = append(out, &coordv1.Peer{
			Id:            p.ID,
			Name:          p.Name,
			VpnAddr:       p.VPNAddr,
			Ed25519Public: p.Ed25519Public,
			X25519Public:  p.X25519Public,
			Endpoint:      p.Endpoint,
			SubnetRoutes:  p.SubnetRoutes,
		})
	}
	return &coordv1.ListPeersResponse{Peers: out}, nil
}

// Watch streams PeerEvents and signals for the network until the client disconnects.
// If req.PeerId is set, signals addressed to that peer are also delivered.
func (s *Server) Watch(req *coordv1.WatchRequest, stream coordv1.Coord_WatchServer) error {
	ctx := stream.Context()
	if _, err := s.accounts.Resolve(ctx, req.Token); err != nil {
		return status.Errorf(codes.Unauthenticated, "invalid token")
	}

	// Subscribe before snapshotting so we cannot miss a JOIN that arrives
	// between the snapshot and the first Recv on the stream.
	ch := s.bus.Subscribe(req.NetworkId)
	defer s.bus.Unsubscribe(req.NetworkId, ch)

	// Subscribe to peer-to-peer signals if the caller identified itself.
	var sigCh <-chan signalMsg
	if req.PeerId != "" {
		sc := s.bus.SubscribeSignals(req.PeerId)
		sigCh = sc
		defer s.bus.UnsubscribeSignals(req.PeerId, sc)
	}

	// Send the current peer list as synthetic JOIN events. Any peer that
	// registered before our bus subscription is in this snapshot; any peer
	// that registered after is already queued in ch. Duplicates are
	// idempotent on the client (Upsert). This closes the ListPeers→Watch
	// race without requiring a separate RPC from the client.
	if peers, err := s.registry.ListPeers(req.NetworkId); err == nil {
		for _, p := range peers {
			if p.ID == req.PeerId {
				continue
			}
			ev := &coordv1.PeerEvent{
				Type: coordv1.EventType_JOIN,
				Peer: &coordv1.Peer{
					Id:            p.ID,
					Name:          p.Name,
					VpnAddr:       p.VPNAddr,
					Ed25519Public: p.Ed25519Public,
					X25519Public:  p.X25519Public,
					Endpoint:      p.Endpoint,
					SubnetRoutes:  p.SubnetRoutes,
				},
			}
			if err := stream.Send(ev); err != nil {
				return err
			}
		}
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-ch:
			if !ok {
				return nil
			}
			if err := stream.Send(ev); err != nil {
				return err
			}
		case sig, ok := <-sigCh:
			if !ok {
				return nil
			}
			ev := &coordv1.PeerEvent{
				Type: coordv1.EventType_SIGNAL,
				Signal: &coordv1.SignalEvent{
					FromPeerId: sig.FromPeerID,
					Payload:    sig.Payload,
				},
			}
			if err := stream.Send(ev); err != nil {
				return err
			}
		}
	}
}

// SendSignal relays an opaque signal from one peer to another.
func (s *Server) SendSignal(ctx context.Context, req *coordv1.SendSignalRequest) (*coordv1.SendSignalResponse, error) {
	if _, err := s.accounts.Resolve(ctx, req.Token); err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "invalid token")
	}
	s.bus.SendSignal(req.FromPeerId, req.ToPeerId, req.Payload)
	return &coordv1.SendSignalResponse{}, nil
}

// Leave removes a peer from the registry.
func (s *Server) Leave(ctx context.Context, req *coordv1.LeaveRequest) (*coordv1.LeaveResponse, error) {
	acc, err := s.accounts.Resolve(ctx, req.Token)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "invalid token")
	}

	removed, err := s.registry.RemovePeer(req.PeerId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "peer not found")
	}

	vpnAddr, _ := netip.ParseAddr(removed.VPNAddr)
	net, _, _ := s.registry.GetNetwork(removed.NetworkID)
	peer := coordcore.Peer{ID: removed.ID, Name: removed.Name, VPNAddr: vpnAddr, NetworkID: removed.NetworkID}
	s.hooks.OnPeerLeft(ctx, peer, net)

	_ = s.audit.Log(ctx, coordcore.AuditEvent{
		Kind:      coordcore.AuditPeerLeft,
		AccountID: acc.ID,
		NetworkID: removed.NetworkID,
		PeerID:    removed.ID,
		At:        time.Now(),
	})

	s.bus.Publish(removed.NetworkID, &coordv1.PeerEvent{
		Type: coordv1.EventType_LEAVE,
		Peer: &coordv1.Peer{Id: removed.ID, Name: removed.Name},
	})

	return &coordv1.LeaveResponse{}, nil
}
