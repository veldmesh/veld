# Coexisting with other VPNs

Veldmesh is designed to run next to other VPNs, and the conflicts to watch
for differ by VPN category:

- **Commercial VPNs** (NordVPN, Mullvad, ProtonVPN, ExpressVPN, Surfshark,
  ...) tunnel all traffic through a provider and enforce a kill switch. The
  coexistence issue is the kill switch: it can silently drop Veldmesh's UDP
  peer traffic. No route veld installs can fix the VPN's firewall.
- **Mesh VPNs** (Tailscale, ZeroTier, ...) connect devices directly and
  leave the default route alone. The coexistence issue is CIDR overlap:
  both networks claim private address space, and overlapping routes make
  destinations unreachable for one side or the other.

This page explains what veld does automatically, what its log lines mean,
and the one thing only the VPN's side can fix.

## What veld does automatically

**Route installation.** Veldmesh never claims a default route or CGNAT
range — it installs only the routes for its mesh CIDR and the subnets its
peers advertise. On Linux, routes are installed with `ip route replace`
semantics (netlink `RTM_NEWROUTE` with `NLM_F_REPLACE`):

- **Replace on conflict.** If a VPN already installed a route for the same
  prefix (VPN connected first), veld's `Add` takes the prefix over instead
  of failing with "file exists" — and if the VPN displaces veld's route
  later (veld connected first), the next veld start or peer rejoin claims
  it back. This is what makes the install order-independent.
- **Explicit default metric.** Veldmesh requests metric 0 — the metric the
  kernel would use anyway for an unqualified route add, made explicit.
  It is not a coexistence advantage; the replace-on-conflict above is the
  sole order-independence mechanism. (On IPv6 the kernel raises metric 0
  to 1024, `IP6_RT_PRIO_USER`, on install.)

**Platform support for route management.** Subnet route installation,
replacement, and removal are implemented only on Linux (via netlink).
On macOS, Windows, and other Unix systems the route manager is a no-op:
Veldmesh still performs coexistence detection (VPN presence, CIDR
collisions, full-tunnel warnings) and logs actionable guidance, but it
does not install or manage routes. Operators on those platforms must
configure routes manually or rely on the VPN's own routing.

**Route gathering is per-platform.** Linux reads all routing tables via
netlink; macOS parses `netstat -rn`; Windows parses
`netsh interface ip show route` (and the IPv6 equivalent); other Unix
systems (the BSDs, Solaris) parse `netstat -rn` with best-effort interface
matching. On every platform the daemon sees enough of the routing table to
warn about CIDR collisions with other networks. Route metrics are exposed
on Linux (via netlink) and Windows (via netsh); on macOS and other Unix
systems `netstat` does not expose metrics, so collision findings on those
platforms omit the metric.

**Startup detection.** When the daemon starts it inspects the host's
interfaces and routing tables — all of them, not just the main table,
because wg-quick, Mullvad, NordLynx and Tailscale install their routes in
dedicated policy-routing tables — and logs actionable guidance. For every
route veld is about to install, it also checks for conflicts at install
time.

## Reading the log lines

| Log line | Meaning | What to do |
|---|---|---|
| `veld: coexist: NordVPN detected (interface nordlynx): ...` | A known provider's tunnel is up. | Nothing, unless peers fail to connect — then follow the advice (add veld to the VPN's split tunneling, or disable its kill switch, and restart veld). |
| `... full-tunnel — the default route passes through it ...` | All traffic, including veld's UDP hole-punching, is routed through the VPN. Direct peer connections may fail; relay fallback (if configured) usually still works. | Enable split tunneling for veld in the VPN, or configure a relay. |
| `veld: coexist: mesh prefix 10.100.0.0/24: route 10.0.0.0/8 via tun0 covers ... but Veldmesh's more-specific route takes precedence` | A broader route covers the mesh prefix. Informational: longest-prefix match keeps mesh traffic on veld's route. | Nothing. |
| `... conflicts with 10.100.0.0/24 via tun0: ... exact conflict; Veldmesh installs its route by replacing any same-prefix route ...` | Another interface claims the exact same prefix. Each side's (re)install claims the prefix in turn. | Prefer moving one side to a different CIDR; the log suggests one (`consider using 10.109.0.0/24 instead`). |
| `... conflicts with 10.100.0.128/25 via tun0: ... more specific ... never reaches the mesh` | A more-specific route carves destinations out of the mesh. Those destinations will not work over the mesh. | Change the mesh CIDR (the log suggests an alternative) or remove the other route. |

Suggestions are same-size CIDRs inside RFC 1918 private space (`10.0.0.0/8`,
`172.16.0.0/12`, `192.168.0.0/16`), generated for any prefix size those
blocks can host, and always stay outside Tailscale's `100.64.0.0/10` CGNAT
range.

## Limitations

- **Kill switches are one-way.** A VPN-side firewall (ExpressVPN's Network
  Lock, NordVPN's kill switch, ...) can silently drop veld's UDP. Veld
  detects and reports the VPN, but only the VPN's own settings (split
  tunneling / kill-switch exclusions) can let veld's traffic through. No
  route metric can fix a firewall.
- **Veldmesh's own TUN is excluded** from detection via its interface
  name (`veld0` by default on Linux, the Wintun adapter is named `Veld` on
  Windows, macOS gets the kernel-assigned `utunN`; override with
  `node.iface_name`). In static mode the TUN exists at startup; in coord
  mode the TUN is created after the coordinator assigns the VPN address.
  Veldmesh resolves its own interface at each check time, so the exclusion
  applies as soon as a TUN exists.
- On macOS and Windows, route metrics are not available from the parsed
  command output, so collision findings may omit the metric.
- **The name `tun0` can no longer be requested.** Configs written by older
  veld versions carry `iface_name = "tun0"`; veld migrates that to the
  platform default and logs one line saying so. Literal `tun0` is rejected
  deliberately: `TUNSETIFF` fails with EEXIST when OpenVPN already owns
  the name, so veld could not even start next to an OpenVPN-based VPN with
  it.

## What veld does *not* do

No fwmark/policy routing: marking veld's packets would require cooperation
from (or configuration of) the commercial VPN, so veld relies on split
tunneling on the VPN side instead.
