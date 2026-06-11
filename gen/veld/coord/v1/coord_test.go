// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package coordv1

import (
	"testing"
)

func TestMessageTypes_Instantiate(t *testing.T) {
	req := &RegisterRequest{
		Name:         "node-1",
		NetworkId:    "net-abc",
		Token:        "token-abc",
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
		t.Errorf("Payload length: got %d", len(sig.Payload))
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
			t.Errorf("EventType(%d).String(): got %q, want %q", int(tc.e), tc.e.String(), tc.want)
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
