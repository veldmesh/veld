// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: BUSL-1.1
package coord

import (
	"testing"
	"time"
)

// TestJitterBackoff verifies that jitterBackoff returns a value in [0, backoff)
// and that repeated calls produce varied results (not always the same value).
func TestJitterBackoff(t *testing.T) {
	backoff := 10 * time.Second

	seen := make(map[time.Duration]bool)
	for i := 0; i < 100; i++ {
		j := jitterBackoff(backoff)
		if j < 0 {
			t.Fatalf("jitter %d is negative: %v", i, j)
		}
		if j >= backoff {
			t.Fatalf("jitter %d >= backoff: %v >= %v", i, j, backoff)
		}
		seen[j] = true
	}

	// With full jitter over [0, 10s), 100 samples should produce many
	// distinct values (at least 50). A constant or narrow distribution
	// would indicate the jitter is not being applied.
	if len(seen) < 50 {
		t.Errorf("expected at least 50 distinct jitter values, got %d", len(seen))
	}

	// Zero backoff should always yield zero.
	if j := jitterBackoff(0); j != 0 {
		t.Errorf("jitterBackoff(0) = %v, want 0", j)
	}
}
