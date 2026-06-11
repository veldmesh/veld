// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: BUSL-1.1
package ce

import (
	"context"
	"fmt"

	coordcore "github.com/veldmesh/veld/coord/core"
)

// Limits for the free tier.
const (
	FreeMachineLimit = 5
	FreeNetworkLimit = 1
)

// FreeEnforcer implements PlanEnforcer for the Community Edition (Free tier only).
type FreeEnforcer struct{}

func NewFreeEnforcer() *FreeEnforcer { return &FreeEnforcer{} }

func (e *FreeEnforcer) CanRegisterMachine(_ context.Context, _ string, currentCount int) error {
	if currentCount >= FreeMachineLimit {
		return fmt.Errorf("%w (free tier: max %d)", coordcore.ErrMachineLimitReached, FreeMachineLimit)
	}
	return nil
}

func (e *FreeEnforcer) CanAddNetwork(_ context.Context, _ string, currentCount int) error {
	if currentCount >= FreeNetworkLimit {
		return fmt.Errorf("%w (free tier: max %d)", coordcore.ErrNetworkLimitReached, FreeNetworkLimit)
	}
	return nil
}

func (e *FreeEnforcer) CanUseSubnetRouting(_ context.Context, _ string) error {
	return coordcore.ErrSubnetNotAvailable
}

func (e *FreeEnforcer) MachineLimitFor(_ context.Context, _ string) int {
	return FreeMachineLimit
}
