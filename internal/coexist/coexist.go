// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT

// Package coexist detects conditions that break commercial VPN + Veldmesh
// coexistence and produces actionable guidance for the operator.
//
// Veldmesh deliberately installs only routes for its own mesh CIDRs — no
// default route, no exit node. Conflicts with a commercial VPN therefore
// come from the VPN's side: kill switches blocking Veldmesh's UDP, or
// routes that claim (parts of) the mesh CIDR. The analysis in this package
// inspects a host network snapshot and reports:
//
//   - known commercial VPN tunnels and full-tunnel defaults, with
//     provider-specific fix instructions (split tunneling, kill switch),
//   - routing-table overlaps with Veldmesh prefixes, classified by how the
//     kernel's longest-prefix-match will resolve them,
//   - replacement CIDR suggestions when the mesh CIDR itself is contested.
package coexist

import (
	"fmt"
	"net/netip"
	"regexp"
)

// Printf is the signature of fmt.Printf-style logging functions.
type Printf func(format string, args ...any) (n int, err error)

// Link describes one network interface observed on the host.
type Link struct {
	Name  string         // kernel interface name, e.g. "eth0", "nordlynx"
	Kind  string         // link type if known: "tun", "wireguard", "device", ...
	Addrs []netip.Prefix // addresses assigned to the interface
}

// RouteEntry describes one route observed in the host routing table.
type RouteEntry struct {
	Dst    netip.Prefix // destination; 0.0.0.0/0 or ::/0 for default routes
	Gw     netip.Addr   // gateway; zero if directly connected
	Iface  string       // egress interface name; "" if unknown
	Metric int
}

// Snapshot is a point-in-time view of the host's links and routes.
type Snapshot struct {
	Links  []Link
	Routes []RouteEntry
}

// VPN is a VPN provider or unattributed tunnel observed on the host.
type VPN struct {
	Name       string // provider name, or generic description for unattributed tunnels
	Iface      string
	FullTunnel bool   // the default route points through this interface
	Advice     string // actionable fix when Veldmesh traffic is blocked
}

// CollisionKind classifies how an existing route overlaps a Veldmesh prefix.
type CollisionKind int

const (
	// CollisionEqual: another interface holds a route for the identical prefix.
	// The kernel breaks the tie by metric; Veldmesh installs metric-0 routes,
	// which win, but a VPN that reinstalls its route later can flip the table.
	CollisionEqual CollisionKind = iota
	// CollisionInside: a more-specific route is carved out of the mesh prefix.
	// Those destinations follow the other route and never reach the mesh.
	CollisionInside
	// CollisionBroader: a broader route covers the whole mesh prefix. The
	// kernel's longest-prefix match still prefers Veldmesh's more-specific
	// route, so this is informational.
	CollisionBroader
)

// Collision is an overlap between a Veldmesh prefix and an existing route.
type Collision struct {
	Mesh   netip.Prefix
	Route  netip.Prefix
	Iface  string
	Kind   CollisionKind
	Advice string
}

// String renders the collision as a single log line. The distinction matters:
// broader overlaps are informational (longest-prefix match keeps the mesh
// working), the others are actionable conflicts.
func (c Collision) String() string {
	if c.Kind == CollisionBroader {
		return fmt.Sprintf("veld: coexist: mesh prefix %s: %s", c.Mesh, c.Advice)
	}
	return fmt.Sprintf("veld: coexist: mesh prefix %s conflicts with %s via %s: %s", c.Mesh, c.Route, c.Iface, c.Advice)
}

// vpnPattern matches a commercial VPN by interface name.
type vpnPattern struct {
	name   string
	re     *regexp.Regexp
	advice string
}

// Known commercial VPN interfaces, keyed by their Linux/macOS naming. Named
// TUNs are reliable signals (NordLynx, mullvad); providers that use generic
// "tun0" names are caught by the generic tunnel heuristic instead.
var vpnPatterns = []vpnPattern{
	{
		name:   "NordVPN",
		re:     regexp.MustCompile(`(?i)^(nordlynx|nordtun|nordwg|nordvpn)`),
		advice: "if the NordVPN kill switch blocks Veldmesh's UDP peer traffic, add veld to NordVPN's split tunneling or disable the kill switch, then restart veld",
	},
	{
		name:   "Mullvad",
		re:     regexp.MustCompile(`(?i)^mullvad`),
		advice: "if Mullvad's tunnel or kill switch captures or blocks Veldmesh traffic, exclude veld in Mullvad's settings or disable the kill switch, then restart veld",
	},
	{
		name:   "ProtonVPN",
		re:     regexp.MustCompile(`(?i)^proton`),
		advice: "if ProtonVPN's kill switch blocks Veldmesh's UDP peer traffic, add veld to ProtonVPN's split tunneling or disable the kill switch, then restart veld",
	},
	{
		name:   "ExpressVPN",
		re:     regexp.MustCompile(`(?i)^(expressvpn|express|tunex)`),
		advice: "if ExpressVPN's Network Lock blocks Veldmesh's UDP peer traffic, disable Network Lock or add veld to split tunneling, then restart veld",
	},
	{
		name:   "Surfshark",
		re:     regexp.MustCompile(`(?i)^surfshark`),
		advice: "if Surfshark's kill switch blocks Veldmesh's UDP peer traffic, add veld to Surfshark's split tunneling or disable the kill switch, then restart veld",
	},
	{
		name:   "Tailscale",
		re:     regexp.MustCompile(`(?i)^tailscale`),
		advice: "Tailscale is a mesh, not a kill-switch VPN — keep the Veldmesh mesh CIDR outside Tailscale's 100.64.0.0/10 CGNAT range to avoid route conflicts",
	},
	{
		name:   "ZeroTier",
		re:     regexp.MustCompile(`(?i)^(zerotier|zt[0-9a-z]{8})`),
		advice: "ZeroTier managed routes may overlap Veldmesh prefixes; keep the two networks on disjoint CIDRs",
	},
}

// genericTunnelRe matches interface names that usually belong to VPN tunnels
// (including self-hosted WireGuard and OpenVPN's tun/tap devices).
var genericTunnelRe = regexp.MustCompile(`(?i)^(tun|tap|utun|wg)[0-9]*$`)

// tunKinds are link kinds that mark an interface as a virtual tunnel even
// when its name gives no hint.
var tunKinds = map[string]bool{
	"tun":       true,
	"tap":       true,
	"wireguard": true,
}

// cgnatPrefix is the RFC 6598 carrier-grade NAT block claimed by Tailscale.
var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")

// DetectVPNs returns commercial VPNs and VPN-like tunnels visible in the
// snapshot. selfIface (Veldmesh's own TUN, if any) is never reported.
func DetectVPNs(s Snapshot, selfIface string) []VPN {
	var vpns []VPN
	seen := map[string]bool{}

	add := func(v VPN) {
		if selfIface != "" && v.Iface == selfIface {
			return
		}
		if seen[v.Iface] {
			return
		}
		seen[v.Iface] = true
		vpns = append(vpns, v)
	}

	for _, l := range s.Links {
		if l.Name == "" || l.Name == "lo" || l.Name == "lo0" {
			continue
		}
		if p := matchProvider(l.Name); p != nil {
			add(VPN{Name: p.name, Iface: l.Name, Advice: p.advice})
			continue
		}
		if genericTunnelRe.MatchString(l.Name) || tunKinds[l.Kind] {
			add(VPN{
				Name:   "VPN tunnel",
				Iface:  l.Name,
				Advice: "a VPN tunnel interface is active; if its provider has a kill switch, Veldmesh's UDP peer traffic may be blocked — exclude veld from the VPN (split tunneling) or disable the kill switch, then restart veld",
			})
		}
	}

	// Tailscale is also identifiable by its CGNAT route claim, even when
	// link enumeration missed the interface.
	if !containsVPN(vpns, "Tailscale") {
		for _, r := range s.Routes {
			if r.Dst == cgnatPrefix {
				add(VPN{
					Name:   "Tailscale",
					Iface:  r.Iface,
					Advice: "route 100.64.0.0/10 (Tailscale's CGNAT range) is installed — keep the Veldmesh mesh CIDR outside it to avoid route conflicts",
				})
				break
			}
		}
	}

	// Full-tunnel detection: a default route through a VPN tunnel means all
	// of Veldmesh's peer UDP traffic traverses (or dies inside) the VPN.
	for _, r := range s.Routes {
		if !isDefault(r.Dst) || r.Iface == "" {
			continue
		}
		for i := range vpns {
			if vpns[i].Iface == r.Iface {
				vpns[i].FullTunnel = true
			}
		}
	}

	return vpns
}

// matchProvider returns the pattern for a known VPN provider, or nil.
func matchProvider(iface string) *vpnPattern {
	for i := range vpnPatterns {
		if vpnPatterns[i].re.MatchString(iface) {
			return &vpnPatterns[i]
		}
	}
	return nil
}

// containsVPN reports whether a VPN with the given provider name was found.
func containsVPN(vpns []VPN, name string) bool {
	for _, v := range vpns {
		if v.Name == name {
			return true
		}
	}
	return false
}

// FindCollisions checks the given Veldmesh prefixes against routes in the
// snapshot held by other interfaces. Default routes and routes on
// selfIface (Veldmesh's own TUN) are never conflicts.
func FindCollisions(s Snapshot, selfIface string, prefixes ...netip.Prefix) []Collision {
	var cs []Collision
	for _, p := range prefixes {
		p = p.Masked()
		if !p.IsValid() {
			continue
		}
		for _, r := range s.Routes {
			if (selfIface != "" && r.Iface == selfIface) || isDefault(r.Dst) || !p.Overlaps(r.Dst) {
				continue
			}
			switch {
			case p.Bits() == r.Dst.Bits():
				cs = append(cs, Collision{
					Mesh:   p,
					Route:  r.Dst,
					Iface:  r.Iface,
					Kind:   CollisionEqual,
					Advice: fmt.Sprintf("route %s via %s is an exact conflict; Veldmesh installs its route with metric 0 (highest priority), so veld wins ties — but if the VPN reinstalls the route later, traffic to %s breaks; prefer moving one side to a different CIDR", r.Dst, r.Iface, p),
				})
			case r.Dst.Bits() < p.Bits():
				cs = append(cs, Collision{
					Mesh:   p,
					Route:  r.Dst,
					Iface:  r.Iface,
					Kind:   CollisionBroader,
					Advice: fmt.Sprintf("route %s via %s covers %s, but Veldmesh's more-specific route takes precedence via longest-prefix match — no action needed", r.Dst, r.Iface, p),
				})
			default:
				cs = append(cs, Collision{
					Mesh:   p,
					Route:  r.Dst,
					Iface:  r.Iface,
					Kind:   CollisionInside,
					Advice: fmt.Sprintf("route %s via %s is more specific than %s — traffic to %s follows the other route and never reaches the mesh; change the mesh CIDR or remove the other route", r.Dst, r.Iface, p, r.Dst),
				})
			}
		}
	}
	return cs
}

// altCandidates are suggested replacement CIDRs for a contested mesh
// prefix, tried in order. 100.64.0.0/10 is deliberately absent: it belongs
// to Tailscale's CGNAT range.
var altCandidates = map[int][]netip.Prefix{
	24: {
		netip.MustParsePrefix("10.100.0.0/24"),
		netip.MustParsePrefix("10.109.0.0/24"),
		netip.MustParsePrefix("10.110.0.0/24"),
		netip.MustParsePrefix("10.200.0.0/24"),
		netip.MustParsePrefix("172.16.100.0/24"),
		netip.MustParsePrefix("172.20.100.0/24"),
		netip.MustParsePrefix("172.30.100.0/24"),
	},
	16: {
		netip.MustParsePrefix("10.100.0.0/16"),
		netip.MustParsePrefix("10.110.0.0/16"),
		netip.MustParsePrefix("10.200.0.0/16"),
		netip.MustParsePrefix("172.16.0.0/16"),
		netip.MustParsePrefix("172.20.0.0/16"),
		netip.MustParsePrefix("172.30.0.0/16"),
	},
}

// SuggestAlternative returns a private CIDR of the same size as bad that
// overlaps nothing in the snapshot's routing table (including bad itself).
// ok is false when no candidate of that prefix size fits.
func SuggestAlternative(bad netip.Prefix, s Snapshot) (netip.Prefix, bool) {
	bad = bad.Masked()
	if !bad.IsValid() {
		return netip.Prefix{}, false
	}
	for _, cand := range altCandidates[bad.Bits()] {
		if cand == bad || cand.Overlaps(bad) {
			continue
		}
		conflict := false
		for _, r := range s.Routes {
			if !isDefault(r.Dst) && r.Dst.Overlaps(cand) {
				conflict = true
				break
			}
		}
		if !conflict {
			return cand, true
		}
	}
	return netip.Prefix{}, false
}

// ReportSnapshot logs coexistence findings for the given snapshot via
// printf. vpnPrefix is the mesh VPN CIDR — the only prefix the operator can
// freely change, so it gets replacement suggestions; pass an invalid prefix
// when the CIDR is assigned by the coord server. prefixes are additional
// Veldmesh prefixes to check (e.g. peer subnet routes).
func ReportSnapshot(printf Printf, s Snapshot, selfIface string, vpnPrefix netip.Prefix, prefixes ...netip.Prefix) {
	for _, v := range DetectVPNs(s, selfIface) {
		if v.FullTunnel {
			_, _ = printf("veld: coexist: %s detected (interface %s; full-tunnel — the default route passes through it, so Veldmesh peer UDP is tunneled and direct connections may fail): %s\n", v.Name, v.Iface, v.Advice)
		} else {
			_, _ = printf("veld: coexist: %s detected (interface %s): %s\n", v.Name, v.Iface, v.Advice)
		}
	}

	all := prefixes
	if vpnPrefix.IsValid() {
		all = append([]netip.Prefix{vpnPrefix.Masked()}, all...)
	}
	for _, c := range FindCollisions(s, selfIface, all...) {
		line := c.String()
		if c.Kind != CollisionBroader && c.Mesh == vpnPrefix.Masked() {
			if alt, ok := SuggestAlternative(c.Mesh, s); ok {
				line += fmt.Sprintf("; consider using %s instead", alt)
			}
		}
		_, _ = printf("%s\n", line)
	}
}

// Report gathers a fresh snapshot and logs VPN detection plus collision
// warnings. It never fails hard: gathering errors are logged and analysis is
// skipped, because coexistence guidance must not block the daemon from
// starting.
func Report(printf Printf, selfIface string, vpnPrefix netip.Prefix, prefixes ...netip.Prefix) {
	s, err := Observe()
	if err != nil {
		_, _ = printf("veld: coexist: could not inspect host network state: %v\n", err)
		return
	}
	ReportSnapshot(printf, s, selfIface, vpnPrefix, prefixes...)
}

// CheckRoute gathers a fresh snapshot and returns collisions for a single
// Veldmesh prefix. Returns nil when gathering fails: a failed check must not
// block the route installation itself.
func CheckRoute(pfx netip.Prefix, selfIface string) []Collision {
	s, err := Observe()
	if err != nil {
		return nil
	}
	return FindCollisions(s, selfIface, pfx)
}

// isDefault reports whether dst is the IPv4 or IPv6 default route.
func isDefault(dst netip.Prefix) bool {
	return dst == netip.MustParsePrefix("0.0.0.0/0") || dst == netip.MustParsePrefix("::/0")
}
