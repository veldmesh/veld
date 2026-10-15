// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT

package coexist_test

import (
	"net/netip"
	"testing"

	"github.com/veldmesh/veld/internal/coexist"
)

func TestParseNetstatDstDefault(t *testing.T) {
	cases := []struct {
		in      string
		ipv6    bool
		want    netip.Prefix
		wantErr bool
	}{
		{"default", false, netip.MustParsePrefix("0.0.0.0/0"), false},
		{"default", true, netip.MustParsePrefix("::/0"), false},
		{"10.100.0.0/24", false, netip.MustParsePrefix("10.100.0.0/24"), false},
		{"fd00::/8", true, netip.MustParsePrefix("fd00::/8"), false},
		{"127/8", false, netip.MustParsePrefix("127.0.0.0/8"), false},
		{"10.100.0.1", false, netip.MustParsePrefix("10.100.0.1/32"), false},
		{"fd00::1", true, netip.MustParsePrefix("fd00::1/128"), false},
		{"invalid", false, netip.Prefix{}, true},
	}

	for _, tc := range cases {
		got, err := coexist.ParseNetstatDst(tc.in, tc.ipv6)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseNetstatDst(%q, %v) expected error, got %v", tc.in, tc.ipv6, got)
			}
		} else {
			if err != nil {
				t.Errorf("parseNetstatDst(%q, %v) unexpected error: %v", tc.in, tc.ipv6, err)
			}
			if got != tc.want {
				t.Errorf("parseNetstatDst(%q, %v) = %v, want %v", tc.in, tc.ipv6, got, tc.want)
			}
		}
	}
}
