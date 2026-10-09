// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package coordv1

import (
	"testing"

	"github.com/golang/protobuf/proto"
)

func TestMessageTypes_Instantiate(t *testing.T) {
	req := &RegisterRequest{
		Name:          "node-1",
		NetworkId:     "net-abc",
		Token:         "token-abc",
		Ed25519Public: "base64key==",
		X25519Public:  "base64key2==",
	}
	if req.GetName() != "node-1" {
		t.Errorf("GetName: got %q, want %q", req.GetName(), "node-1")
	}
	if req.GetToken() != "token-abc" {
		t.Errorf("GetToken: got %q", req.GetToken())
	}
	if req.GetNetworkId() != "net-abc" {
		t.Errorf("GetNetworkId: got %q", req.GetNetworkId())
	}

	resp := &RegisterResponse{VpnAddr: "10.100.0.1", PeerId: "abc123", NetworkId: "net-abc"}
	if resp.GetVpnAddr() != "10.100.0.1" {
		t.Errorf("GetVpnAddr: got %q", resp.GetVpnAddr())
	}
	if resp.GetPeerId() != "abc123" {
		t.Errorf("GetPeerId: got %q", resp.GetPeerId())
	}

	peer := &Peer{Id: "peer-id", Name: "peer-b", VpnAddr: "10.0.0.2"}
	if peer.GetName() != "peer-b" {
		t.Errorf("Peer.GetName: got %q", peer.GetName())
	}
	if peer.GetId() != "peer-id" {
		t.Errorf("Peer.GetId: got %q", peer.GetId())
	}

	ev := &PeerEvent{Type: EventType_JOIN, Peer: peer}
	if ev.Type != EventType_JOIN {
		t.Errorf("EventType: got %v", ev.Type)
	}

	sig := &SendSignalRequest{Token: "tok", FromPeerId: "a", ToPeerId: "b", Payload: []byte("opaque")}
	if len(sig.Payload) != 6 {
		t.Errorf("Payload length: got %d, len(sig.Payload), want 6", len(sig.Payload))
	}

	_ = &ListPeersRequest{NetworkId: "net", Token: "t"}
	_ = &ListPeersResponse{Peers: []*Peer{peer}}
	_ = &WatchRequest{NetworkId: "net", Token: "t"}
	_ = &SendSignalResponse{}
	_ = &LeaveRequest{Token: "t", PeerId: "p"}
	_ = &LeaveResponse{}
}

func TestEventType_Values(t *testing.T) {
	cases := []struct {
		e    EventType
		want string
	}{
		{EventType_JOIN, "JOIN"},
		{EventType_LEAVE, "LEAVE"},
		{EventType_ENDPOINT_UPDATE, "ENDPOINT_UPDATE"},
		{EventType_ROUTE_UPDATE, "ROUTE_UPDATE"},
	}
	for _, tc := range cases {
		if tc.e.String() != tc.want {
			t.Errorf("EventType(%d).String(): got %q, want %q", int32(tc.e), tc.e.String(), tc.want)
		}
	}
}

func TestServiceDesc(t *testing.T) {
	if Coord_ServiceDesc.ServiceName != "veld.coord.v1.Coord" {
		t.Errorf("ServiceName: got %q", Coord_ServiceDesc.ServiceName)
	}
	if len(Coord_ServiceDesc.Methods) != 4 {
		t.Errorf("Methods: got %d, want 4", len(Coord_ServiceDesc.Methods))
	}
	if len(Coord_ServiceDesc.Streams) != 1 {
		t.Errorf("Streams: got %d, want 1", len(Coord_ServiceDesc.Streams))
	}
	if Coord_ServiceDesc.Streams[0].StreamName != "Watch" {
		t.Errorf("Stream name: got %q, want Watch", Coord_ServiceDesc.Streams[0].StreamName)
	}
	if !Coord_ServiceDesc.Streams[0].ServerStreams {
		t.Error("Watch should be server-streaming")
	}
}

func TestReset(t *testing.T) {
	r := &RegisterRequest{Name: "before"}
	r.Reset()
	if r.Name != "" {
		t.Errorf("Reset: Name should be empty after reset, got %q", r.Name)
	}
}

// TestRegisterRequest_WireRoundTrip locks the on-wire encoding of the
// Register proof-of-possession fields (timestamp_unix = 8, signature = 9):
// both must survive a protobuf marshal/unmarshal round trip, and messages
// from pre-signature clients (which never set them) must decode to the
// zero values.
func TestRegisterRequest_WireRoundTrip(t *testing.T) {
	signed := &RegisterRequest{
		NetworkId:     "net-wire",
		Token:         "tok",
		Name:          "wire-peer",
		Ed25519Public: "rU3j0Q9yJdBhpIS4Iac2BSGFciXqSm0CVBkNJGyzXBk=",
		X25519Public:  "bEc9LidcTNF4gJpA2tJvJlIaSafqiIMmqtTIKYtEqzU=",
		Endpoint:      "203.0.113.7:51820",
		SubnetRoutes:  []string{"10.42.0.0/24", "192.168.1.0/24"},
		TimestampUnix: 1735689600,
		Signature:     []byte{9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
	}
	wire, err := proto.Marshal(signed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var decoded RegisterRequest
	if err := proto.Unmarshal(wire, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if decoded.TimestampUnix != signed.TimestampUnix {
		t.Errorf("TimestampUnix: got %d, want %d", decoded.TimestampUnix, signed.TimestampUnix)
	}
	if string(decoded.Signature) != string(signed.Signature) {
		t.Errorf("Signature: got %x, want %x", decoded.Signature, signed.Signature)
	}
	if decoded.NetworkId != signed.NetworkId || decoded.Ed25519Public != signed.Ed25519Public ||
		decoded.X25519Public != signed.X25519Public || decoded.Endpoint != signed.Endpoint {
		t.Errorf("legacy fields changed: %+v", &decoded)
	}
	if len(decoded.SubnetRoutes) != 2 || decoded.SubnetRoutes[0] != signed.SubnetRoutes[0] {
		t.Errorf("SubnetRoutes: got %v, want %v", decoded.SubnetRoutes, signed.SubnetRoutes)
	}

	// A pre-signature client sends no fields 8/9: they decode to zero.
	legacy := &RegisterRequest{NetworkId: "net-wire", Token: "tok", Name: "old"}
	wire, err = proto.Marshal(legacy)
	if err != nil {
		t.Fatalf("Marshal legacy: %v", err)
	}
	var legacyDecoded RegisterRequest
	if err := proto.Unmarshal(wire, &legacyDecoded); err != nil {
		t.Fatalf("Unmarshal legacy: %v", err)
	}
	if legacyDecoded.TimestampUnix != 0 || len(legacyDecoded.Signature) != 0 {
		t.Errorf("legacy message decoded with signature fields set: %+v", &legacyDecoded)
	}
}
