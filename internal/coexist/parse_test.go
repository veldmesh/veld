// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT

package coexist_test

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/veldmesh/veld/internal/coexist"
)

func TestParseDarwinNetstat(t *testing.T) {
	// Sample from gather_darwin.go comments (mixed-case flags: UGSc, UGcI, UHLWIi)
	input := `Routing tables

Internet:
Destination        Gateway            Flags        Netif Expire
default            192.168.1.1        UGSc           en0
10.100.0/24        10.100.0.1         UGSc          utun0
127                127.0.0.1          UCS            lo0

Internet6:
Destination        Gateway            Flags         Netif Expire
default            fe80::1%en0         UGcI           en0
fd00::/8           fd00::1             UGcI          utun0
`

	routes, err := coexist.ParseDarwinNetstatForTest(input)
	if err != nil {
		t.Fatalf("parseDarwinNetstat returned error: %v", err)
	}

	fmt.Printf("GOT %d routes:\n", len(routes))
	for _, r := range routes {
		fmt.Printf("  %s gw=%s iface=%s\n", r.Dst, r.Gw, r.Iface)
	}

	// Expected: 5 routes (3 IPv4 + 2 IPv6)
	if len(routes) != 5 {
		t.Fatalf("expected 5 routes, got %d", len(routes))
	}

	// Verify IPv4 default route
	found := false
	for _, r := range routes {
		if r.Dst == netip.MustParsePrefix("0.0.0.0/0") && r.Iface == "en0" {
			found = true
			if r.Gw != netip.MustParseAddr("192.168.1.1") {
				t.Errorf("IPv4 default route gateway: expected 192.168.1.1, got %s", r.Gw)
			}
			break
		}
	}
	if !found {
		t.Error("IPv4 default route (UGSc) not found")
	}

	// Verify 10.100.0/24 route
	found = false
	for _, r := range routes {
		if r.Dst == netip.MustParsePrefix("10.100.0.0/24") && r.Iface == "utun0" {
			found = true
			if r.Gw != netip.MustParseAddr("10.100.0.1") {
				t.Errorf("10.100.0/24 gateway: expected 10.100.0.1, got %s", r.Gw)
			}
			break
		}
	}
	if !found {
		t.Error("10.100.0/24 route (UGSc) not found")
	}

	// Verify 127/8 host route
	found = false
	for _, r := range routes {
		if r.Dst == netip.MustParsePrefix("127.0.0.0/8") && r.Iface == "lo0" {
			found = true
			if r.Gw != netip.MustParseAddr("127.0.0.1") {
				t.Errorf("127/8 gateway: expected 127.0.0.1, got %s", r.Gw)
			}
			break
		}
	}
	if !found {
		t.Error("127/8 route (UCS) not found")
	}

	// Verify IPv6 default route
	found = false
	for _, r := range routes {
		if r.Dst == netip.MustParsePrefix("::/0") && r.Iface == "en0" {
			found = true
			// fe80::1%en0 -> gateway should be fe80::1 (zone stripped)
			if r.Gw != netip.MustParseAddr("fe80::1") {
				t.Errorf("IPv6 default route gateway: expected fe80::1, got %s", r.Gw)
			}
			break
		}
	}
	if !found {
		t.Error("IPv6 default route (UGcI) not found")
	}

	// Verify fd00::/8 route
	found = false
	for _, r := range routes {
		if r.Dst == netip.MustParsePrefix("fd00::/8") && r.Iface == "utun0" {
			found = true
			if r.Gw != netip.MustParseAddr("fd00::1") {
				t.Errorf("fd00::/8 gateway: expected fd00::1, got %s", r.Gw)
			}
			break
		}
	}
	if !found {
		t.Error("fd00::/8 route (UGcI) not found")
	}
}

func TestParseNetshRoutes(t *testing.T) {
	// Real netsh output format (IPv4 example)
	input := `Publish  Type       Met   Prefix                    Idx   Gateway/Interface Name
-------  --------   ----  ------------------------  ---   ------------------------
   No    System     256   0.0.0.0/0                  14   192.168.1.1
   No    System     256   10.100.0.0/24              14   Ethernet
   No    System     256   127.0.0.0/8                 1   Loopback Pseudo-Interface 1
`

	routes, err := coexist.ParseNetshRoutesForTest(input)
	if err != nil {
		t.Fatalf("ParseNetshRoutesForTest returned error: %v", err)
	}

	fmt.Printf("GOT %d routes:\n", len(routes))
	for _, r := range routes {
		fmt.Printf("  %s gw=%s iface=%s metric=%d\n", r.Dst, r.Gw, r.Iface, r.Metric)
	}

	// Expect 3 routes
	if len(routes) != 3 {
		t.Fatalf("expected 3 routes, got %d", len(routes))
	}

	// Verify default route (gateway is IP)
	found := false
	for _, r := range routes {
		if r.Dst == netip.MustParsePrefix("0.0.0.0/0") {
			found = true
			if r.Gw != netip.MustParseAddr("192.168.1.1") {
				t.Errorf("default route gateway: expected 192.168.1.1, got %s", r.Gw)
			}
			if r.Iface != "if14" {
				t.Errorf("default route iface: expected if14, got %s", r.Iface)
			}
			if r.Metric != 256 {
				t.Errorf("default route metric: expected 256, got %d", r.Metric)
			}
			break
		}
	}
	if !found {
		t.Error("default route (0.0.0.0/0) not found")
	}

	// Verify 10.100.0.0/24 route (gateway is interface name)
	found = false
	for _, r := range routes {
		if r.Dst == netip.MustParsePrefix("10.100.0.0/24") {
			found = true
			if r.Gw.IsValid() {
				t.Errorf("10.100.0.0/24 route: expected no gateway (interface name), got %s", r.Gw)
			}
			if r.Iface != "if14" {
				t.Errorf("10.100.0.0/24 iface: expected if14, got %s", r.Iface)
			}
			break
		}
	}
	if !found {
		t.Error("10.100.0.0/24 route not found")
	}

	// Verify 127.0.0.0/8 route
	found = false
	for _, r := range routes {
		if r.Dst == netip.MustParsePrefix("127.0.0.0/8") {
			found = true
			if r.Iface != "if1" {
				t.Errorf("127.0.0.0/8 iface: expected if1, got %s", r.Iface)
			}
			break
		}
	}
	if !found {
		t.Error("127.0.0.0/8 route not found")
	}
}

func TestParseNetshRoutesIPv6(t *testing.T) {
	// Real netsh output format (IPv6 example)
	input := `Publish  Type       Met   Prefix                    Idx   Gateway/Interface Name
-------  --------   ----  ------------------------  ---   ------------------------
   No    System     256   ::/0                       14   fe80::1
   No    System     256   fd00::/8                   14   Ethernet
`

	routes, err := coexist.ParseNetshRoutesForTest(input)
	if err != nil {
		t.Fatalf("ParseNetshRoutesForTest returned error: %v", err)
	}

	if len(routes) != 2 {
		t.Fatalf("expected 2 routes, got %d", len(routes))
	}

	found := false
	for _, r := range routes {
		if r.Dst == netip.MustParsePrefix("::/0") {
			found = true
			if r.Gw != netip.MustParseAddr("fe80::1") {
				t.Errorf("IPv6 default route gateway: expected fe80::1, got %s", r.Gw)
			}
			break
		}
	}
	if !found {
		t.Error("IPv6 default route (::/0) not found")
	}
}

func TestParseNetshInterfaces(t *testing.T) {
	// Real netsh output format for `netsh interface ipv4 show interfaces`
	input := `Idx     Met         MTU          State                Name
---  ----------  ----------  ------------  -------------------------
  1          75  4294967295  connected       Loopback Pseudo-Interface 1
 14          25        1500  connected       Ethernet
 22          50        1500  connected       Wintun
`

	m := coexist.ParseNetshInterfacesForTest(input)

	if len(m) != 3 {
		t.Fatalf("expected 3 interfaces, got %d", len(m))
	}

	if m["1"] != "Loopback Pseudo-Interface 1" {
		t.Errorf("ifIndex 1: expected 'Loopback Pseudo-Interface 1', got %q", m["1"])
	}
	if m["14"] != "Ethernet" {
		t.Errorf("ifIndex 14: expected 'Ethernet', got %q", m["14"])
	}
	if m["22"] != "Wintun" {
		t.Errorf("ifIndex 22: expected 'Wintun', got %q", m["22"])
	}
}

func TestParseNetshInterfacesEmpty(t *testing.T) {
	// Empty output (no data rows)
	input := `Idx     Met         MTU          State                Name
---  ----------  ----------  ------------  -------------------------
`

	m := coexist.ParseNetshInterfacesForTest(input)
	if len(m) != 0 {
		t.Fatalf("expected 0 interfaces, got %d", len(m))
	}
}
