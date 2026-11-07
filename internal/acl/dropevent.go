// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package acl

import (
	"encoding/hex"

	"github.com/veldmesh/veld/internal/daemon/ipctypes"
)

// ToIPC converts an internal DropEvent to an IPC DropEvent.
func (e DropEvent) ToIPC() ipctypes.DropEvent {
	return ipctypes.DropEvent{
		Time:    e.Time,
		PeerID:  hex.EncodeToString(e.PeerID[:]),
		Proto:   e.Proto.String(),
		Port:    e.Port,
		RuleIdx: e.RuleIdx,
	}
}

// ToIPCBatch converts a slice of internal DropEvents to IPC DropEvents.
func ToIPCBatch(events []DropEvent) []ipctypes.DropEvent {
	result := make([]ipctypes.DropEvent, len(events))
	for i, e := range events {
		result[i] = e.ToIPC()
	}
	return result
}
