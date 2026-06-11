// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
// Hand-generated placeholder. Run "make proto" to regenerate from coord.proto.
// Uses github.com/golang/protobuf v1 API + ProtoReflect bridge for gRPC compatibility.

package coordv1

import (
	proto1 "github.com/golang/protobuf/proto"
)

// EventType is the type of a peer event.
type EventType int32

const (
	EventType_JOIN            EventType = 0
	EventType_LEAVE           EventType = 1
	EventType_ENDPOINT_UPDATE EventType = 2
	EventType_ROUTE_UPDATE    EventType = 3
	EventType_SIGNAL          EventType = 4 // peer-to-peer opaque signal (ICE candidates etc.)
)

var EventType_name = map[int32]string{
	0: "JOIN",
	1: "LEAVE",
	2: "ENDPOINT_UPDATE",
	3: "ROUTE_UPDATE",
	4: "SIGNAL",
}

var EventType_value = map[string]int32{
	"JOIN":            0,
	"LEAVE":           1,
	"ENDPOINT_UPDATE": 2,
	"ROUTE_UPDATE":    3,
	"SIGNAL":          4,
}

func (e EventType) String() string {
	if name, ok := EventType_name[int32(e)]; ok {
		return name
	}
	return "UNKNOWN"
}

// Peer represents a registered node in a network.
type Peer struct {
	Id            string   `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Name          string   `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	VpnAddr       string   `protobuf:"bytes,3,opt,name=vpn_addr,json=vpnAddr,proto3" json:"vpn_addr,omitempty"`
	Ed25519Public string   `protobuf:"bytes,4,opt,name=ed25519_public,json=ed25519Public,proto3" json:"ed25519_public,omitempty"`
	X25519Public  string   `protobuf:"bytes,5,opt,name=x25519_public,json=x25519Public,proto3" json:"x25519_public,omitempty"`
	Endpoint      string   `protobuf:"bytes,6,opt,name=endpoint,proto3" json:"endpoint,omitempty"`
	SubnetRoutes  []string `protobuf:"bytes,7,rep,name=subnet_routes,json=subnetRoutes,proto3" json:"subnet_routes,omitempty"`
}

func (x *Peer) Reset()         { *x = Peer{} }
func (x *Peer) String() string { return "" }
func (x *Peer) ProtoMessage()  {}

func (x *Peer) GetId() string              { return x.Id }
func (x *Peer) GetName() string            { return x.Name }
func (x *Peer) GetVpnAddr() string         { return x.VpnAddr }
func (x *Peer) GetEd25519Public() string   { return x.Ed25519Public }
func (x *Peer) GetX25519Public() string    { return x.X25519Public }
func (x *Peer) GetEndpoint() string        { return x.Endpoint }
func (x *Peer) GetSubnetRoutes() []string  { return x.SubnetRoutes }

// RegisterRequest is sent by a daemon to join a network.
type RegisterRequest struct {
	NetworkId     string   `protobuf:"bytes,1,opt,name=network_id,json=networkId,proto3" json:"network_id,omitempty"`
	Token         string   `protobuf:"bytes,2,opt,name=token,proto3" json:"token,omitempty"`
	Name          string   `protobuf:"bytes,3,opt,name=name,proto3" json:"name,omitempty"`
	Ed25519Public string   `protobuf:"bytes,4,opt,name=ed25519_public,json=ed25519Public,proto3" json:"ed25519_public,omitempty"`
	X25519Public  string   `protobuf:"bytes,5,opt,name=x25519_public,json=x25519Public,proto3" json:"x25519_public,omitempty"`
	Endpoint      string   `protobuf:"bytes,6,opt,name=endpoint,proto3" json:"endpoint,omitempty"`
	SubnetRoutes  []string `protobuf:"bytes,7,rep,name=subnet_routes,json=subnetRoutes,proto3" json:"subnet_routes,omitempty"`
}

func (x *RegisterRequest) Reset()         { *x = RegisterRequest{} }
func (x *RegisterRequest) String() string { return "" }
func (x *RegisterRequest) ProtoMessage()  {}

func (x *RegisterRequest) GetNetworkId() string     { return x.NetworkId }
func (x *RegisterRequest) GetToken() string         { return x.Token }
func (x *RegisterRequest) GetName() string          { return x.Name }
func (x *RegisterRequest) GetEd25519Public() string { return x.Ed25519Public }
func (x *RegisterRequest) GetX25519Public() string  { return x.X25519Public }
func (x *RegisterRequest) GetEndpoint() string      { return x.Endpoint }
func (x *RegisterRequest) GetSubnetRoutes() []string { return x.SubnetRoutes }

// RegisterResponse is returned after successful registration.
type RegisterResponse struct {
	VpnAddr   string `protobuf:"bytes,1,opt,name=vpn_addr,json=vpnAddr,proto3" json:"vpn_addr,omitempty"`
	PeerId    string `protobuf:"bytes,2,opt,name=peer_id,json=peerId,proto3" json:"peer_id,omitempty"`
	NetworkId string `protobuf:"bytes,3,opt,name=network_id,json=networkId,proto3" json:"network_id,omitempty"`
}

func (x *RegisterResponse) Reset()         { *x = RegisterResponse{} }
func (x *RegisterResponse) String() string { return "" }
func (x *RegisterResponse) ProtoMessage()  {}

func (x *RegisterResponse) GetVpnAddr() string   { return x.VpnAddr }
func (x *RegisterResponse) GetPeerId() string    { return x.PeerId }
func (x *RegisterResponse) GetNetworkId() string { return x.NetworkId }

type ListPeersRequest struct {
	NetworkId string `protobuf:"bytes,1,opt,name=network_id,json=networkId,proto3" json:"network_id,omitempty"`
	Token     string `protobuf:"bytes,2,opt,name=token,proto3" json:"token,omitempty"`
}

func (x *ListPeersRequest) Reset()         { *x = ListPeersRequest{} }
func (x *ListPeersRequest) String() string { return "" }
func (x *ListPeersRequest) ProtoMessage()  {}

func (x *ListPeersRequest) GetNetworkId() string { return x.NetworkId }
func (x *ListPeersRequest) GetToken() string     { return x.Token }

type ListPeersResponse struct {
	Peers []*Peer `protobuf:"bytes,1,rep,name=peers,proto3" json:"peers,omitempty"`
}

func (x *ListPeersResponse) Reset()         { *x = ListPeersResponse{} }
func (x *ListPeersResponse) String() string { return "" }
func (x *ListPeersResponse) ProtoMessage()  {}

func (x *ListPeersResponse) GetPeers() []*Peer { return x.Peers }

type WatchRequest struct {
	NetworkId string `protobuf:"bytes,1,opt,name=network_id,json=networkId,proto3" json:"network_id,omitempty"`
	Token     string `protobuf:"bytes,2,opt,name=token,proto3" json:"token,omitempty"`
	PeerId    string `protobuf:"bytes,3,opt,name=peer_id,json=peerId,proto3" json:"peer_id,omitempty"`
}

func (x *WatchRequest) Reset()         { *x = WatchRequest{} }
func (x *WatchRequest) String() string { return "" }
func (x *WatchRequest) ProtoMessage()  {}

func (x *WatchRequest) GetNetworkId() string { return x.NetworkId }
func (x *WatchRequest) GetToken() string     { return x.Token }
func (x *WatchRequest) GetPeerId() string    { return x.PeerId }

// SignalEvent carries an opaque peer-to-peer signal payload (e.g. NAT candidates).
// The payload is encrypted for the recipient — the coord server cannot read it.
type SignalEvent struct {
	FromPeerId string `protobuf:"bytes,1,opt,name=from_peer_id,json=fromPeerId,proto3" json:"from_peer_id,omitempty"`
	Payload    []byte `protobuf:"bytes,2,opt,name=payload,proto3" json:"payload,omitempty"`
}

func (x *SignalEvent) Reset()         { *x = SignalEvent{} }
func (x *SignalEvent) String() string { return "" }
func (x *SignalEvent) ProtoMessage()  {}

func (x *SignalEvent) GetFromPeerId() string { return x.FromPeerId }
func (x *SignalEvent) GetPayload() []byte    { return x.Payload }

type PeerEvent struct {
	Type   EventType    `protobuf:"varint,1,opt,name=type,proto3,enum=veld.coord.v1.EventType" json:"type,omitempty"`
	Peer   *Peer        `protobuf:"bytes,2,opt,name=peer,proto3" json:"peer,omitempty"`
	Signal *SignalEvent `protobuf:"bytes,3,opt,name=signal,proto3" json:"signal,omitempty"`
}

func (x *PeerEvent) Reset()         { *x = PeerEvent{} }
func (x *PeerEvent) String() string { return "" }
func (x *PeerEvent) ProtoMessage()  {}

func (x *PeerEvent) GetType() EventType    { return x.Type }
func (x *PeerEvent) GetPeer() *Peer        { return x.Peer }
func (x *PeerEvent) GetSignal() *SignalEvent { return x.Signal }

type SendSignalRequest struct {
	Token      string `protobuf:"bytes,1,opt,name=token,proto3" json:"token,omitempty"`
	FromPeerId string `protobuf:"bytes,2,opt,name=from_peer_id,json=fromPeerId,proto3" json:"from_peer_id,omitempty"`
	ToPeerId   string `protobuf:"bytes,3,opt,name=to_peer_id,json=toPeerId,proto3" json:"to_peer_id,omitempty"`
	Payload    []byte `protobuf:"bytes,4,opt,name=payload,proto3" json:"payload,omitempty"`
}

func (x *SendSignalRequest) Reset()         { *x = SendSignalRequest{} }
func (x *SendSignalRequest) String() string { return "" }
func (x *SendSignalRequest) ProtoMessage()  {}

func (x *SendSignalRequest) GetToken() string      { return x.Token }
func (x *SendSignalRequest) GetFromPeerId() string { return x.FromPeerId }
func (x *SendSignalRequest) GetToPeerId() string   { return x.ToPeerId }
func (x *SendSignalRequest) GetPayload() []byte    { return x.Payload }

type SendSignalResponse struct{}

func (x *SendSignalResponse) Reset()         { *x = SendSignalResponse{} }
func (x *SendSignalResponse) String() string { return "" }
func (x *SendSignalResponse) ProtoMessage()  {}

type LeaveRequest struct {
	Token  string `protobuf:"bytes,1,opt,name=token,proto3" json:"token,omitempty"`
	PeerId string `protobuf:"bytes,2,opt,name=peer_id,json=peerId,proto3" json:"peer_id,omitempty"`
}

func (x *LeaveRequest) Reset()         { *x = LeaveRequest{} }
func (x *LeaveRequest) String() string { return "" }
func (x *LeaveRequest) ProtoMessage()  {}

func (x *LeaveRequest) GetToken() string  { return x.Token }
func (x *LeaveRequest) GetPeerId() string { return x.PeerId }

type LeaveResponse struct{}

func (x *LeaveResponse) Reset()         { *x = LeaveResponse{} }
func (x *LeaveResponse) String() string { return "" }
func (x *LeaveResponse) ProtoMessage()  {}

func init() {
	proto1.RegisterType((*Peer)(nil), "veld.coord.v1.Peer")
	proto1.RegisterType((*RegisterRequest)(nil), "veld.coord.v1.RegisterRequest")
	proto1.RegisterType((*RegisterResponse)(nil), "veld.coord.v1.RegisterResponse")
	proto1.RegisterType((*ListPeersRequest)(nil), "veld.coord.v1.ListPeersRequest")
	proto1.RegisterType((*ListPeersResponse)(nil), "veld.coord.v1.ListPeersResponse")
	proto1.RegisterType((*WatchRequest)(nil), "veld.coord.v1.WatchRequest")
	proto1.RegisterType((*SignalEvent)(nil), "veld.coord.v1.SignalEvent")
	proto1.RegisterType((*PeerEvent)(nil), "veld.coord.v1.PeerEvent")
	proto1.RegisterType((*SendSignalRequest)(nil), "veld.coord.v1.SendSignalRequest")
	proto1.RegisterType((*SendSignalResponse)(nil), "veld.coord.v1.SendSignalResponse")
	proto1.RegisterType((*LeaveRequest)(nil), "veld.coord.v1.LeaveRequest")
	proto1.RegisterType((*LeaveResponse)(nil), "veld.coord.v1.LeaveResponse")
	proto1.RegisterEnum("veld.coord.v1.EventType", EventType_name, EventType_value)
}
