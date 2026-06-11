// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
// Hand-generated placeholder. Run "make proto" to regenerate from coord.proto.

package coordv1

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// CoordClient is the client API for the Coord service.
type CoordClient interface {
	Register(ctx context.Context, in *RegisterRequest, opts ...grpc.CallOption) (*RegisterResponse, error)
	ListPeers(ctx context.Context, in *ListPeersRequest, opts ...grpc.CallOption) (*ListPeersResponse, error)
	Watch(ctx context.Context, in *WatchRequest, opts ...grpc.CallOption) (Coord_WatchClient, error)
	SendSignal(ctx context.Context, in *SendSignalRequest, opts ...grpc.CallOption) (*SendSignalResponse, error)
	Leave(ctx context.Context, in *LeaveRequest, opts ...grpc.CallOption) (*LeaveResponse, error)
}

type coordClient struct {
	cc grpc.ClientConnInterface
}

func NewCoordClient(cc grpc.ClientConnInterface) CoordClient {
	return &coordClient{cc}
}

func (c *coordClient) Register(ctx context.Context, in *RegisterRequest, opts ...grpc.CallOption) (*RegisterResponse, error) {
	out := new(RegisterResponse)
	if err := c.cc.Invoke(ctx, "/veld.coord.v1.Coord/Register", in, out, opts...); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *coordClient) ListPeers(ctx context.Context, in *ListPeersRequest, opts ...grpc.CallOption) (*ListPeersResponse, error) {
	out := new(ListPeersResponse)
	if err := c.cc.Invoke(ctx, "/veld.coord.v1.Coord/ListPeers", in, out, opts...); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *coordClient) Watch(ctx context.Context, in *WatchRequest, opts ...grpc.CallOption) (Coord_WatchClient, error) {
	stream, err := c.cc.NewStream(ctx, &Coord_ServiceDesc.Streams[0], "/veld.coord.v1.Coord/Watch", opts...)
	if err != nil {
		return nil, err
	}
	x := &coordWatchClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

// Coord_WatchClient is the client-side streaming interface for Watch.
type Coord_WatchClient interface {
	Recv() (*PeerEvent, error)
	grpc.ClientStream
}

type coordWatchClient struct {
	grpc.ClientStream
}

func (x *coordWatchClient) Recv() (*PeerEvent, error) {
	m := new(PeerEvent)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *coordClient) SendSignal(ctx context.Context, in *SendSignalRequest, opts ...grpc.CallOption) (*SendSignalResponse, error) {
	out := new(SendSignalResponse)
	if err := c.cc.Invoke(ctx, "/veld.coord.v1.Coord/SendSignal", in, out, opts...); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *coordClient) Leave(ctx context.Context, in *LeaveRequest, opts ...grpc.CallOption) (*LeaveResponse, error) {
	out := new(LeaveResponse)
	if err := c.cc.Invoke(ctx, "/veld.coord.v1.Coord/Leave", in, out, opts...); err != nil {
		return nil, err
	}
	return out, nil
}

// CoordServer is the server API for the Coord service.
// Embed UnimplementedCoordServer for forward compatibility.
type CoordServer interface {
	Register(context.Context, *RegisterRequest) (*RegisterResponse, error)
	ListPeers(context.Context, *ListPeersRequest) (*ListPeersResponse, error)
	Watch(*WatchRequest, Coord_WatchServer) error
	SendSignal(context.Context, *SendSignalRequest) (*SendSignalResponse, error)
	Leave(context.Context, *LeaveRequest) (*LeaveResponse, error)
	mustEmbedUnimplementedCoordServer()
}

// UnimplementedCoordServer satisfies CoordServer and returns Unimplemented for all methods.
type UnimplementedCoordServer struct{}

func (UnimplementedCoordServer) Register(context.Context, *RegisterRequest) (*RegisterResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Register not implemented")
}
func (UnimplementedCoordServer) ListPeers(context.Context, *ListPeersRequest) (*ListPeersResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListPeers not implemented")
}
func (UnimplementedCoordServer) Watch(*WatchRequest, Coord_WatchServer) error {
	return status.Errorf(codes.Unimplemented, "method Watch not implemented")
}
func (UnimplementedCoordServer) SendSignal(context.Context, *SendSignalRequest) (*SendSignalResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SendSignal not implemented")
}
func (UnimplementedCoordServer) Leave(context.Context, *LeaveRequest) (*LeaveResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Leave not implemented")
}
func (UnimplementedCoordServer) mustEmbedUnimplementedCoordServer() {}

// UnsafeCoordServer allows forward-only compatibility.
type UnsafeCoordServer interface {
	mustEmbedUnimplementedCoordServer()
}

// Coord_WatchServer is the server-side streaming interface for Watch.
type Coord_WatchServer interface {
	Send(*PeerEvent) error
	grpc.ServerStream
}

type coordWatchServer struct {
	grpc.ServerStream
}

func (x *coordWatchServer) Send(m *PeerEvent) error {
	return x.ServerStream.SendMsg(m)
}

// RegisterCoordServer registers srv with the gRPC server s.
func RegisterCoordServer(s grpc.ServiceRegistrar, srv CoordServer) {
	s.RegisterService(&Coord_ServiceDesc, srv)
}

func _Coord_Register_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RegisterRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CoordServer).Register(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/veld.coord.v1.Coord/Register"}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CoordServer).Register(ctx, req.(*RegisterRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Coord_ListPeers_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListPeersRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CoordServer).ListPeers(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/veld.coord.v1.Coord/ListPeers"}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CoordServer).ListPeers(ctx, req.(*ListPeersRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Coord_Watch_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(WatchRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(CoordServer).Watch(m, &coordWatchServer{stream})
}

func _Coord_SendSignal_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SendSignalRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CoordServer).SendSignal(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/veld.coord.v1.Coord/SendSignal"}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CoordServer).SendSignal(ctx, req.(*SendSignalRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Coord_Leave_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(LeaveRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CoordServer).Leave(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/veld.coord.v1.Coord/Leave"}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CoordServer).Leave(ctx, req.(*LeaveRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// Coord_ServiceDesc is the grpc.ServiceDesc for Coord service.
var Coord_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "veld.coord.v1.Coord",
	HandlerType: (*CoordServer)(nil),
	Methods: []grpc.MethodDesc{
		{MethodName: "Register", Handler: _Coord_Register_Handler},
		{MethodName: "ListPeers", Handler: _Coord_ListPeers_Handler},
		{MethodName: "SendSignal", Handler: _Coord_SendSignal_Handler},
		{MethodName: "Leave", Handler: _Coord_Leave_Handler},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "Watch",
			Handler:       _Coord_Watch_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "veld/coord/v1/coord.proto",
}
