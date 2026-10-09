// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
//go:build windows

package tun

import (
	"errors"
	"strings"
	"testing"
)

// TestTunCreateError_WintunHint covers the pure error-message helper; the
// driver-dependent path (needs Administrator + wintun.dll) is exercised
// opportunistically in tun_windows_test.go.
func TestTunCreateError_WintunHint(t *testing.T) {
	cause := errors.New(`Error creating wintun adapter: LoadLibraryEx("wintun.dll") failed: The specified module could not be found.`)

	err := tunCreateError("veld0", cause)

	if !errors.Is(err, cause) {
		t.Error("errors.Is(wrapped, cause) = false, want true")
	}
	msg := err.Error()
	for _, want := range []string{
		"tun create veld0",
		"(hint: wintun.dll not found next to veld-daemon.exe",
		"https://www.wintun.net/",
		"or use the release zip",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("tunCreateError message = %q, missing %q", msg, want)
		}
	}
}
