// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package route

import (
	"net/netip"
	"testing"
)

func TestCheckPeerRoute(t *testing.T) {
	mesh := netip.MustParsePrefix("100.64.0.5/24")
	cases := []struct {
		pfx string
		ok  bool
	}{
		{"192.168.1.0/24", true},
		{"10.0.0.0/8", true},
		{"fd12:3456::/48", true},
		{"0.0.0.0/0", false},
		{"0.0.0.0/1", false},
		{"128.0.0.0/1", false},
		{"::/0", false},
		{"8000::/1", false},
		{"100.64.0.0/24", false},   // the mesh
		{"100.64.0.0/16", false},   // contains the mesh
		{"100.64.0.128/25", false}, // inside the mesh
		{"127.0.0.0/8", false},
		{"169.254.0.0/16", false},
		{"224.0.0.0/8", false},
		{"fe80::/64", false},
		{"::ffff:192.168.1.0/120", false},
	}
	for _, tc := range cases {
		err := CheckPeerRoute(netip.MustParsePrefix(tc.pfx), mesh)
		if (err == nil) != tc.ok {
			t.Errorf("CheckPeerRoute(%s) = %v, want ok=%v", tc.pfx, err, tc.ok)
		}
	}
	if err := CheckPeerRoute(netip.MustParsePrefix("100.64.0.0/24"), netip.Prefix{}); err != nil {
		t.Errorf("unknown mesh: %v", err)
	}
}
