// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: BUSL-1.1
package ce

import (
	"context"

	coordcore "github.com/veldmesh/veld/coord/core"
)

// NoopAuditLogger discards all audit events. Used by CE coord server.
type NoopAuditLogger struct{}

func NewNoopAuditLogger() *NoopAuditLogger { return &NoopAuditLogger{} }

func (l *NoopAuditLogger) Log(_ context.Context, _ coordcore.AuditEvent) error { return nil }
