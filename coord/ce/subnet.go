// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: BUSL-1.1
package ce

import (
	"context"
	"net/netip"

	coordcore "github.com/veldmesh/veld/coord/core"
)

// RejectSubnetPolicy always returns ErrSubnetNotAvailable. Used by CE coord server.
type RejectSubnetPolicy struct{}

func NewRejectSubnetPolicy() *RejectSubnetPolicy { return &RejectSubnetPolicy{} }

func (p *RejectSubnetPolicy) Allow(_ context.Context, _ string, _ netip.Prefix) error {
	return coordcore.ErrSubnetNotAvailable
}
