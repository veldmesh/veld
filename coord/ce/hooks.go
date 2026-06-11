// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: BUSL-1.1
package ce

import (
	"context"
	"net/netip"

	coordcore "github.com/veldmesh/veld/coord/core"
)

// NoopHooks implements LifecycleHooks with no-ops. Used by CE coord server.
type NoopHooks struct{}

func NewNoopHooks() *NoopHooks { return &NoopHooks{} }

func (h *NoopHooks) OnPeerRegistered(_ context.Context, _ coordcore.Peer, _ coordcore.Network) {}
func (h *NoopHooks) OnPeerLeft(_ context.Context, _ coordcore.Peer, _ coordcore.Network)       {}
func (h *NoopHooks) OnNetworkCreated(_ context.Context, _ coordcore.Network, _ coordcore.Account) {
}
func (h *NoopHooks) OnSubnetRouteAdvertised(_ context.Context, _ coordcore.Peer, _ netip.Prefix) {
}
