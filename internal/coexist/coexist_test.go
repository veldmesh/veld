// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package coexist_test

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/veldmesh/veld/internal/coexist"
)

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }
func addr(s string) netip.Addr  { return netip.MustParseAddr(s) }

// --- DetectVPNs ---

func TestDetectVPNsWithNoVPNs(t *testing.T) {
	s := coexist.Snapshot{
		Links: []coexist.Link{
			{Name: "lo", Kind: "loopback"},
			{Name: "eth0", Kind: "device", Addrs: []netip.Prefix{pfx("192.168.1.10/24")}},
		},
		Routes: []coexist.RouteEntry{
			{Dst: pfx("0.0.0.0/0"), Gw: addr("192.168.1.1"), Iface: "eth0"},
			{Dst: pfx("192.168.1.0/24"), Iface: "eth0"},
		},
	}
	if got := coexist.DetectVPNs(s, ""); len(got) != 0 {
		t.Errorf("expected no findings, got %+v", got)
	}
}

func TestDetectVPNExcludesSelfInterface(t *testing.T) {
	s := coexist.Snapshot{
		Links: []coexist.Link{
			{Name: "veld0", Kind: "tun", Addrs: []netip.Prefix{pfx("10.100.0.1/24")}},
			{Name: "eth0", Kind: "device"},
		},
	}
	if got := coexist.DetectVPNs(s, "veld0"); len(got) != 0 {
		t.Errorf("own TUN must be ignored, got %+v", got)
	}
	if got := coexist.DetectVPNs(s, "eth0"); len(got) != 1 {
		t.Errorf("veld0 without self-exclusion should be reported, got %+v", got)
	}
}

func TestDetectNordVPN(t *testing.T) {
	s := coexist.Snapshot{
		Links: []coexist.Link{
			{Name: "nordlynx", Kind: "wireguard", Addrs: []netip.Prefix{pfx("10.8.1.2/32")}},
			{Name: "eth0", Kind: "device"},
		},
		Routes: []coexist.RouteEntry{
			{Dst: pfx("0.0.0.0/0"), Gw: addr("10.8.0.1"), Iface: "nordlynx"},
		},
	}
	vpns := coexist.DetectVPNs(s, "veld0")
	if len(vpns) != 1 {
		t.Fatalf("expected 1 finding, got %+v", vpns)
	}
	v := vpns[0]
	if v.Name != "NordVPN" {
		t.Errorf("Name = %q, want NordVPN", v.Name)
	}
	if v.Iface != "nordlynx" {
		t.Errorf("Iface = %q, want nordlynx", v.Iface)
	}
	if !v.FullTunnel {
		t.Errorf("default route via nordlynx must set FullTunnel")
	}
	if v.Advice == "" {
		t.Errorf("Advice must be non-empty and actionable")
	}
}

func TestDetectMullvadProtonSurfshark(t *testing.T) {
	s := coexist.Snapshot{
		Links: []coexist.Link{
			{Name: "mullvad-daemon-0", Kind: "tun"},
			{Name: "proton0", Kind: "tun"},
			{Name: "surfshark-wg0", Kind: "wireguard"},
		},
	}
	vpns := coexist.DetectVPNs(s, "veld0")
	if len(vpns) != 3 {
		t.Fatalf("expected 3 findings, got %+v", vpns)
	}
	want := map[string]bool{"Mullvad": false, "ProtonVPN": false, "Surfshark": false}
	for _, v := range vpns {
		if _, ok := want[v.Name]; !ok {
			t.Errorf("unexpected provider %q", v.Name)
		}
		want[v.Name] = true
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("provider %s not detected", name)
		}
	}
}

func TestDetectTailscaleByInterface(t *testing.T) {
	s := coexist.Snapshot{
		Links:  []coexist.Link{{Name: "tailscale0", Kind: "wireguard"}},
		Routes: []coexist.RouteEntry{{Dst: pfx("100.64.0.0/10"), Iface: "tailscale0"}},
	}
	vpns := coexist.DetectVPNs(s, "")
	if len(vpns) != 1 || vpns[0].Name != "Tailscale" {
		t.Fatalf("expected Tailscale, got %+v", vpns)
	}
}

func TestDetectTailscaleByCGNATRouteOnly(t *testing.T) {
	// No matching link entry (e.g. link enumeration missed it), but the
	// CGNAT route identifies Tailscale regardless.
	s := coexist.Snapshot{
		Routes: []coexist.RouteEntry{{Dst: pfx("100.64.0.0/10"), Iface: "tailscale0"}},
	}
	vpns := coexist.DetectVPNs(s, "")
	if len(vpns) != 1 || vpns[0].Name != "Tailscale" {
		t.Fatalf("expected Tailscale via CGNAT route, got %+v", vpns)
	}
}

func TestDetectGenericTunnel(t *testing.T) {
	cases := []struct {
		name string
		kind string
	}{
		{"tun0", "tun"},
		{"tap0", "tap"},
		{"utun3", ""}, // macOS: kind unavailable
		{"wg0", "wireguard"},
		{"tun12", ""},
	}
	for _, tc := range cases {
		s := coexist.Snapshot{Links: []coexist.Link{{Name: tc.name, Kind: tc.kind}}}
		vpns := coexist.DetectVPNs(s, "veld0")
		if len(vpns) != 1 {
			t.Errorf("%s: expected generic tunnel finding, got %+v", tc.name, vpns)
			continue
		}
		if vpns[0].Name == "" || vpns[0].Advice == "" {
			t.Errorf("%s: finding needs a name and advice, got %+v", tc.name, vpns[0])
		}
	}
}

func TestDetectFullTunnelViaGenericTUN(t *testing.T) {
	s := coexist.Snapshot{
		Links:  []coexist.Link{{Name: "tun0", Kind: "tun"}},
		Routes: []coexist.RouteEntry{{Dst: pfx("0.0.0.0/0"), Iface: "tun0"}},
	}
	vpns := coexist.DetectVPNs(s, "veld0")
	if len(vpns) != 1 || !vpns[0].FullTunnel {
		t.Fatalf("expected full-tunnel finding on tun0, got %+v", vpns)
	}
}

func TestDetectVPNsNoFullTunnelForPhysicalDefault(t *testing.T) {
	// A default route through a physical interface must not be reported as
	// a full-tunnel VPN even when other VPN interfaces exist.
	s := coexist.Snapshot{
		Links: []coexist.Link{
			{Name: "nordlynx", Kind: "wireguard"},
			{Name: "eth0", Kind: "device"},
		},
		Routes: []coexist.RouteEntry{{Dst: pfx("0.0.0.0/0"), Gw: addr("192.168.1.1"), Iface: "eth0"}},
	}
	vpns := coexist.DetectVPNs(s, "")
	if len(vpns) != 1 || vpns[0].FullTunnel {
		t.Fatalf("default via eth0 is not a VPN full tunnel, got %+v", vpns)
	}
}

// wg-quick, Mullvad, NordLynx and Tailscale install their routes in
// dedicated policy-routing tables (wg-quick's default: 51820), not in the
// main table. The analysis must consider such routes for both full-tunnel
// detection and CIDR collision checks.
func TestNonMainTableRoutesDriveAnalysis(t *testing.T) {
	s := coexist.Snapshot{
		Links: []coexist.Link{{Name: "wg0", Kind: "wireguard"}},
		Routes: []coexist.RouteEntry{
			{Dst: pfx("0.0.0.0/0"), Iface: "wg0", Table: 51820},
			{Dst: pfx("10.100.0.0/24"), Iface: "wg0", Table: 51820},
		},
	}

	vpns := coexist.DetectVPNs(s, "veld0")
	if len(vpns) != 1 || !vpns[0].FullTunnel {
		t.Fatalf("default route in table 51820 must be a full-tunnel finding, got %+v", vpns)
	}

	cs := coexist.FindCollisions(s, "veld0", pfx("10.100.0.0/24"))
	if len(cs) != 1 || cs[0].Kind != coexist.CollisionEqual {
		t.Fatalf("mesh-prefix claim in table 51820 must be an equal collision, got %+v", cs)
	}
	if cs[0].Iface != "wg0" {
		t.Errorf("collision must name the owning interface, got %+v", cs[0])
	}
}

// --- FindCollisions ---

func TestFindCollisionsEqual(t *testing.T) {
	s := coexist.Snapshot{
		Routes: []coexist.RouteEntry{{Dst: pfx("10.100.0.0/24"), Iface: "nordlynx"}},
	}
	cs := coexist.FindCollisions(s, "veld0", pfx("10.100.0.0/24"))
	if len(cs) != 1 {
		t.Fatalf("expected 1 collision, got %+v", cs)
	}
	if cs[0].Kind != coexist.CollisionEqual {
		t.Errorf("Kind = %v, want CollisionEqual", cs[0].Kind)
	}
	if cs[0].Iface != "nordlynx" || cs[0].Route != pfx("10.100.0.0/24") {
		t.Errorf("bad collision detail: %+v", cs[0])
	}
	if cs[0].Advice == "" {
		t.Errorf("Advice must be non-empty")
	}
}

func TestFindCollisionsBroader(t *testing.T) {
	s := coexist.Snapshot{
		Routes: []coexist.RouteEntry{{Dst: pfx("10.0.0.0/8"), Iface: "tun0"}},
	}
	cs := coexist.FindCollisions(s, "veld0", pfx("10.100.0.0/24"))
	if len(cs) != 1 || cs[0].Kind != coexist.CollisionBroader {
		t.Fatalf("expected broader collision, got %+v", cs)
	}
}

func TestFindCollisionsInside(t *testing.T) {
	s := coexist.Snapshot{
		Routes: []coexist.RouteEntry{{Dst: pfx("10.100.0.128/25"), Iface: "tun0"}},
	}
	cs := coexist.FindCollisions(s, "veld0", pfx("10.100.0.0/24"))
	if len(cs) != 1 || cs[0].Kind != coexist.CollisionInside {
		t.Fatalf("expected inside collision, got %+v", cs)
	}
}

func TestFindCollisionsIPv6(t *testing.T) {
	s := coexist.Snapshot{
		Routes: []coexist.RouteEntry{{Dst: pfx("fd00:dead:beef::/64"), Iface: "tun0"}},
	}
	cs := coexist.FindCollisions(s, "veld0", pfx("fd00::/8"))
	if len(cs) != 1 || cs[0].Kind != coexist.CollisionInside {
		t.Fatalf("expected IPv6 inside collision, got %+v", cs)
	}
}

func TestFindCollisionsSkipsSelfAndDefault(t *testing.T) {
	s := coexist.Snapshot{
		Routes: []coexist.RouteEntry{
			{Dst: pfx("10.100.0.0/24"), Iface: "veld0"}, // our own route
			{Dst: pfx("0.0.0.0/0"), Iface: "eth0"},      // default route
			{Dst: pfx("0.0.0.0/0"), Iface: "tun0"},      // VPN default route
		},
	}
	if cs := coexist.FindCollisions(s, "veld0", pfx("10.100.0.0/24")); len(cs) != 0 {
		t.Errorf("own routes and default routes must be skipped, got %+v", cs)
	}
}

// The local table (255) holds a host route for every assigned address. An
// address inside the mesh range is an assignment, not a routing decision an
// operator could change — it must not be reported as a collision.
func TestFindCollisionsSkipsLocalTable(t *testing.T) {
	s := coexist.Snapshot{
		Routes: []coexist.RouteEntry{
			{Dst: pfx("10.100.0.7/32"), Iface: "eth0", Table: 255},
			{Dst: pfx("192.168.1.0/24"), Iface: "eth0", Table: 254},
		},
	}
	if cs := coexist.FindCollisions(s, "veld0", pfx("10.100.0.0/24")); len(cs) != 0 {
		t.Errorf("local-table host routes must not be reported as collisions, got %+v", cs)
	}
}

func TestFindCollisionsNoneWhenDisjoint(t *testing.T) {
	s := coexist.Snapshot{
		Routes: []coexist.RouteEntry{
			{Dst: pfx("192.168.1.0/24"), Iface: "eth0"},
			{Dst: pfx("10.8.0.0/16"), Iface: "tun0"},
		},
	}
	if cs := coexist.FindCollisions(s, "veld0", pfx("10.100.0.0/24"), pfx("172.16.0.0/24")); len(cs) != 0 {
		t.Errorf("expected no collisions, got %+v", cs)
	}
}

func TestFindCollisionsMultiplePrefixes(t *testing.T) {
	s := coexist.Snapshot{
		Routes: []coexist.RouteEntry{
			{Dst: pfx("10.100.0.0/24"), Iface: "tun0"},    // equal to mesh 1
			{Dst: pfx("192.168.1.128/25"), Iface: "eth1"}, // inside mesh 2
		},
	}
	cs := coexist.FindCollisions(s, "veld0", pfx("10.100.0.0/24"), pfx("192.168.1.0/24"))
	if len(cs) != 2 {
		t.Fatalf("expected 2 collisions, got %+v", cs)
	}
	if cs[0].Kind != coexist.CollisionEqual || cs[1].Kind != coexist.CollisionInside {
		t.Errorf("unexpected kinds: %+v", cs)
	}
}

// --- SuggestAlternative ---

func TestSuggestAlternativeAvoidsRoutes(t *testing.T) {
	// 10.0.0.0/8 covers every 10.x candidate, so the suggestion must land
	// outside it.
	s := coexist.Snapshot{
		Routes: []coexist.RouteEntry{
			{Dst: pfx("10.0.0.0/8"), Iface: "tun0"},
			{Dst: pfx("0.0.0.0/0"), Iface: "eth0"},
		},
	}
	got, ok := coexist.SuggestAlternative(pfx("10.100.0.0/24"), s)
	if !ok {
		t.Fatal("expected a suggestion")
	}
	for _, r := range s.Routes {
		if r.Dst == got || (r.Dst != netip.MustParsePrefix("0.0.0.0/0") && r.Dst.Overlaps(got)) {
			t.Errorf("suggestion %s overlaps existing route %s", got, r.Dst)
		}
	}
	if got.Bits() != 24 {
		t.Errorf("suggestion should keep prefix size, got %s", got)
	}
}

func TestSuggestAlternativeDiffersFromBad(t *testing.T) {
	s := coexist.Snapshot{Routes: []coexist.RouteEntry{{Dst: pfx("10.100.0.128/25"), Iface: "tun0"}}}
	got, ok := coexist.SuggestAlternative(pfx("10.100.0.0/24"), s)
	if !ok {
		t.Fatal("expected a suggestion")
	}
	if got == pfx("10.100.0.0/24") {
		t.Errorf("suggestion must differ from the colliding prefix")
	}
	if got.Overlaps(pfx("10.100.0.0/24")) {
		t.Errorf("suggestion %s overlaps the colliding prefix", got)
	}
}

func TestSuggestAlternative16Bits(t *testing.T) {
	s := coexist.Snapshot{Routes: []coexist.RouteEntry{{Dst: pfx("10.0.0.0/8"), Iface: "tun0"}}}
	got, ok := coexist.SuggestAlternative(pfx("10.100.0.0/16"), s)
	if !ok {
		t.Fatal("expected a /16 suggestion")
	}
	if got.Bits() != 16 {
		t.Errorf("want /16 suggestion, got %s", got)
	}
	if pfx("10.0.0.0/8").Overlaps(got) {
		t.Errorf("suggestion %s overlaps 10.0.0.0/8", got)
	}
}

// Candidates are generated for every RFC 1918-feasible size, not just /24
// and /16 — mesh CIDRs can use any prefix length.
func TestSuggestAlternativeAnyPrefixSize(t *testing.T) {
	s := coexist.Snapshot{Routes: []coexist.RouteEntry{{Dst: pfx("10.100.0.0/20"), Iface: "tun0"}}}
	got, ok := coexist.SuggestAlternative(pfx("10.100.0.0/20"), s)
	if !ok {
		t.Fatal("expected a /20 suggestion")
	}
	if got.Bits() != 20 {
		t.Errorf("want /20 suggestion, got %s", got)
	}
	if got.Overlaps(pfx("10.100.0.0/20")) {
		t.Errorf("suggestion %s overlaps the colliding prefix", got)
	}
}

// /12 is broader than the natural masks of the anchor addresses: candidates
// must be re-masked, not copied verbatim.
func TestSuggestAlternativeAcrossAnchorBoundaries(t *testing.T) {
	s := coexist.Snapshot{
		Routes: []coexist.RouteEntry{{Dst: pfx("10.96.0.0/12"), Iface: "tun0"}}, // 10.96.0.0–10.111.255.255
	}
	got, ok := coexist.SuggestAlternative(pfx("10.100.0.0/12"), s)
	if !ok {
		t.Fatal("expected a /12 suggestion")
	}
	if got.Bits() != 12 {
		t.Errorf("want /12 suggestion, got %s", got)
	}
	for _, r := range s.Routes {
		if r.Dst.Overlaps(got) {
			t.Errorf("suggestion %s overlaps existing route %s", got, r.Dst)
		}
	}
	if got.Overlaps(pfx("10.100.0.0/12")) {
		t.Errorf("suggestion %s overlaps the colliding prefix", got)
	}
}

// An IPv6 mesh CIDR must not be "fixed" with an IPv4 suggestion.
func TestSuggestAlternativeNoIPv4SuggestionForIPv6(t *testing.T) {
	if _, ok := coexist.SuggestAlternative(pfx("fd00::/8"), coexist.Snapshot{}); ok {
		t.Error("no suggestion expected for an IPv6 prefix")
	}
}

// No suggestion exists for sizes no RFC 1918 block can host: 10.0.0.0/8 is
// the only fully private /8, and it is the contested prefix itself.
func TestSuggestAlternativeNoSuggestionOutsidePrivateSpace(t *testing.T) {
	s := coexist.Snapshot{Routes: []coexist.RouteEntry{{Dst: pfx("10.0.0.0/8"), Iface: "tun0"}}}
	if _, ok := coexist.SuggestAlternative(pfx("10.0.0.0/8"), s); ok {
		t.Error("no private-space /8 replacement exists besides 10.0.0.0/8 itself")
	}
}

// --- Report ---

func TestReportLogsVPNAndCollisionGuidance(t *testing.T) {
	s := coexist.Snapshot{
		Links: []coexist.Link{
			{Name: "nordlynx", Kind: "wireguard"},
			{Name: "veld0", Kind: "tun"},
		},
		Routes: []coexist.RouteEntry{
			{Dst: pfx("0.0.0.0/0"), Iface: "nordlynx"},
			{Dst: pfx("10.100.0.128/25"), Iface: "nordlynx"},
		},
	}
	var b strings.Builder
	printf := func(format string, args ...any) (int, error) { return fmt.Fprintf(&b, format, args...) }
	coexist.ReportSnapshot(printf, s, "veld0", pfx("10.100.0.0/24"))

	out := b.String()
	for _, want := range []string{"NordVPN", "nordlynx", "full-tunnel", "10.100.0.128/25", "10.100.0.0/24"} {
		if !strings.Contains(out, want) {
			t.Errorf("log output missing %q:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "consider") && !strings.Contains(out, "instead") {
		t.Errorf("log output should suggest an alternative CIDR:\n%s", out)
	}
}

func TestReportSkipsSelfAndSuggestsNothingWithoutVPNPrefix(t *testing.T) {
	s := coexist.Snapshot{
		Links: []coexist.Link{{Name: "veld0", Kind: "tun"}},
	}
	var b strings.Builder
	printf := func(format string, args ...any) (int, error) { return fmt.Fprintf(&b, format, args...) }
	coexist.ReportSnapshot(printf, s, "veld0", netip.Prefix{})
	if out := b.String(); out != "" {
		t.Errorf("expected no output, got:\n%s", out)
	}
}

func TestReportEqualCollisionExplainsReplaceAndMetric(t *testing.T) {
	s := coexist.Snapshot{
		Routes: []coexist.RouteEntry{{Dst: pfx("10.100.0.0/24"), Iface: "nordlynx"}},
	}
	var b strings.Builder
	printf := func(format string, args ...any) (int, error) { return fmt.Fprintf(&b, format, args...) }
	coexist.ReportSnapshot(printf, s, "veld0", pfx("10.100.0.0/24"))

	out := b.String()
	if !strings.Contains(out, "10.100.0.0/24") {
		t.Errorf("missing colliding prefix in output:\n%s", out)
	}
	if !strings.Contains(out, "replacing") {
		t.Errorf("equal-collision guidance should explain the replace-on-conflict install:\n%s", out)
	}
	if !strings.Contains(out, "metric") {
		t.Errorf("equal-collision guidance should mention the IPv4 metric advantage:\n%s", out)
	}
}
