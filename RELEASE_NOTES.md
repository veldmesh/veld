# Release notes

Notes for upcoming and past releases. User-visible behavior changes and
deployment coordination requirements are recorded here before they ship.

## Unreleased

Changes since v0.2.1. Read the upgrade notes before you replace any binary.

### Upgrading from v0.2.1

**Upgrade every node, the coord server and every relay together, and plan for
an interruption.** Do not count on old and new binaries working side by side:

- **Coord server:** `Watch`, `SendSignal` and `Leave` must now be signed by the
  calling peer. A new coord server rejects these calls from v0.2.1 daemons, so
  upgrading the coord server first does not keep old daemons working.
- **Direct connections:** the reply format used for NAT hole punching changed,
  so old and new daemons cannot complete hole punching with each other.
- **Relays:** the relay handshake now carries the client's clock. A new relay
  refuses old daemons, and an old relay refuses new ones.
- **Clocks:** keep them synchronised. A relay refuses a daemon whose clock is
  more than 30 seconds off its own, and handshakes between nodes have the same
  limit.

Also check these:

- **Saved peer key pins are reset.** The new daemon cannot convert the pins
  v0.2.1 saved (`tofu.json`) and discards them. Each address is pinned again to
  the key used in its first handshake after the upgrade, so upgrade at a time
  when you trust the network and the coord server's peer list. Static
  `[[peers]]` keys are not affected.
- **`network_id` must match.** Handshakes from a different network are now
  dropped, including between static configs that disagree.
- **LAN discovery: only listed peers join by default.** In LAN-only mode, hosts
  that are not listed under `[[peers]]` are now ignored. If you relied on
  devices joining automatically, list them (`endpoint` can be left out), or set
  `allow_unknown = true` under `[mdns]`, which lets any host on the LAN join.
  Discovery also stops advertising the tunnel address, which peers could not
  reach; it advertises the address the node sends multicast from, when it can
  tell which that is.
- **Who can run the daemon (`deploy/install.sh`):** `veld-daemon` is installed
  as `root:veld`, mode `0750`. Add trusted users to the `veld` group.
- **Control socket:** it is created with mode `0660`, and the daemon refuses to
  put it in a directory that group or others can write to.
- **Config file:** `veld` writes it with mode `0600`. An existing file keeps its
  owner and group but loses any access for others.

### Added

- **Access control lists.** Local policy files restrict which peers can connect,
  on which protocols and ports, including outbound-only peers. A network policy
  signed with an admin key can be added; where both apply, both must allow the
  connection. Without a policy, traffic is not restricted. You distribute the signed file to each node yourself: the coord
  server does not distribute it in this version. New `veld policy` commands
  include `check`, `test`, `status`, `keygen`, `sign` and `reload`. See
  [docs/ACL.md](docs/ACL.md).
- **Userspace mode**, which runs without a kernel TUN device. It has limits,
  including no subnet routes and no LAN discovery. See
  [docs/USERSPACE.md](docs/USERSPACE.md).
- **`pkg/veldnet`**, a package for joining a network from a Go program. See
  [docs/EMBED.md](docs/EMBED.md).
- **`veld tofu list` and `veld tofu forget`** to inspect and reset key pins.
- **`veld-coord`:** native TLS (`-tls-cert`, `-tls-key`), the token from
  `-token-file` or `VELD_COORD_TOKEN`, and optional PROXY protocol from trusted
  load balancers (`-proxy-protocol-from`).
- **CLI:** `veld login --token` and `veld join` can read the token from standard
  input, which keeps it out of the process list.

### Security

- Inbound packets are delivered only if their source address belongs to the
  sending peer or to a subnet route it advertises.
- Coord server: peers must prove their own key for `Watch`, `SendSignal` and
  `Leave`; the account token alone is no longer enough.
- NAT probe replies are authenticated, and the number of candidates is capped.
- Relays refuse replayed handshakes and limit open connections.
- Handshake replay protection is kept across restarts.
- A peer can no longer take over another peer's VPN address, name or endpoint,
  and a pinned key's old address stays reserved for it.
- The install script verifies downloads against the release checksums. The
  release workflow also signs `checksums.txt`.
- Session encryption now uses the packet counter sent on the wire, which also
  prevents two packets being sealed with the same nonce.

### Fixed

- Linux: delivering a packet to the TUN device could fail with
  `invalid offset` and stop the data plane.
- A single lost or reordered packet could stall a session until the next rekey.
- Stuck handshakes are retried, sessions are rekeyed, and two peers connecting
  to each other at once no longer lose traffic.
- A malformed STUN reply could crash the daemon.
- Relays keep serving after temporary accept errors, and a peer's newest
  reconnect replaces its waiting connection.
- IP forwarding is restored when a subnet-routing node exits cleanly.
- Linux: a same-metric route that Veld replaced (for example another VPN's) is
  restored on a clean stop.
- The coord server hands out never-used VPN addresses before freed ones,
  including after upgrading an existing database.
- Nodes register under their own name instead of `host`.

## v0.2.1

- **Coord: add proof of key possession to `Register`.** A daemon's `Register`
  request now carries `timestamp_unix` and `signature` — an Ed25519 signature
  by the machine's private key over the request's identity fields (network,
  keys, endpoint, subnet routes and the timestamp) — and the coord server
  rejects a missing, invalid or stale (±120 s) signature with
  `Unauthenticated` before writing anything. Only the holder of an Ed25519
  private key can register or update the peer whose ID is that key.

  **The client and the coord server must be released together.** The wire
  change is a backwards-compatible proto3 addition, but the behavior is not:
  an updated coord server rejects registrations from older clients (they never
  sign), while older coord servers simply ignore the new fields. Ship `veld` /
  `veld-daemon` and `veld-coord` in the same release; self-hosters must
  upgrade their coord server before (or together with) their daemons.

  Signed key rotation (an old-key → new-key handover) is deliberately out of
  scope for this change and is the planned follow-up.

- **Coord: sign peer `name` in `Register` proof of possession.** The `name`
  field is now covered by the Ed25519 signature (domain bumped to
  `veld-coord-register-v2`), so a peer's displayed name cannot be tampered
  with after registration. The golden test vector in
  `internal/crypto/register_test.go` has been updated.

- **Coord: uniform `Unauthenticated` errors for `Register`.** The server now
  returns a single generic message (`"invalid register signature or timestamp"`)
  for all signature and timestamp verification failures, avoiding leakage of
  which check failed or the server's clock. Detailed reasons are still logged
  server-side (including a "check system clock" hint for timestamp failures).
  A new test (`TestServer_Register_UniformAuthError`) asserts the client-visible
  message is identical for a stale timestamp and a bad signature.

- **Docs: document `Register` replay window.** `docs/ARCHITECTURE.md` now notes
  that a captured `Register` can be replayed within the ±120 s window (e.g.
  to re-add a peer after it leaves), but this requires both the account token
  and the captured request; the window is narrow enough to limit practical
  risk while tolerating ordinary clock skew.
