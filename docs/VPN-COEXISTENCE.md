# Commercial VPN coexistence

Veldmesh is designed to run next to a commercial VPN (NordVPN, Mullvad,
ProtonVPN, ExpressVPN, Surfshark, Tailscale, ZeroTier, ...). This page
explains what veld does automatically, what its log lines mean, and the one
thing only the VPN's side can fix.

## What veld does automatically

**Route installation.** Veldmesh never claims a default route or CGNAT
range — it installs only the routes for its mesh CIDR and the subnets its
peers advertise. Two properties make those routes order-independent on
Linux:

- **Add-as-replace.** If a VPN already installed a route for the same
  prefix (VPN connected first), veld's `Add` takes the prefix over instead
  of failing with "file exists".
- **Metric 0.** All veld routes carry the highest-priority kernel metric,
  so among equal-prefix routes the kernel prefers veld's route regardless
  of which side connected first.

**Startup detection.** When the daemon starts it inspects the host's
interfaces and routing table and logs actionable guidance — no manual
`ip route` commands needed. For every route veld is about to install, it
also checks the routing table for conflicts at install time.

## Reading the log lines

| Log line | Meaning | What to do |
|---|---|---|
| `veld: coexist: NordVPN detected (interface nordlynx): ...` | A known provider's tunnel is up. | Nothing, unless peers fail to connect — then follow the advice (add veld to the VPN's split tunneling, or disable its kill switch, and restart veld). |
| `... full-tunnel — the default route passes through it ...` | All traffic, including veld's UDP hole-punching, is routed through the VPN. Direct peer connections may fail; relay fallback (if configured) usually still works. | Enable split tunneling for veld in the VPN, or configure a relay. |
| `veld: coexist: mesh prefix 10.100.0.0/24: route 10.0.0.0/8 via tun0 covers ... but Veldmesh's more-specific route takes precedence` | A broader route covers the mesh prefix. Informational: longest-prefix match keeps mesh traffic on veld's route. | Nothing. |
| `... conflicts with 10.100.0.0/24 via tun0: ... exact conflict; Veldmesh installs its route with metric 0 ...` | Another interface claims the exact same prefix. Veld wins ties via metric. | Prefer moving one side to a different CIDR; the log suggests one (`consider using 10.109.0.0/24 instead`). |
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
- **Veldmesh's own TUN is excluded** from detection (`tun0` by default, or
  `node.iface_name`), so veld never reports itself. In coord mode the TUN
  appears only after the coordinator assigns the VPN address; veld resolves
  its own interface at check time, so the exclusion keeps working.
- On macOS and Windows, detection works by interface name; CIDR-conflict
  checking currently requires Linux netlink.

## What veld does *not* do

No fwmark/policy routing: marking veld's packets would require cooperation
from (or configuration of) the commercial VPN, so veld relies on split
tunneling on the VPN side instead.
