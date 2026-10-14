# Veld Relay Operator Guide (`veld-relay`)

This guide is for operators who want to run a **Veld relay** for their mesh —
or for peers that plan to use one. It covers what the relay is, how to deploy
it, how peers configure it, and how to manage its identity key.

---

## What the relay is

The relay is a **volunteer mesh peer** that acts as a fallback when two peers
cannot establish a direct connection by NAT hole punching — typically when
both sit behind symmetric NATs. It works like Tailscale's DERP: each peer
opens an encrypted connection to the relay, and the relay **splices the two
connections together**, blindly forwarding bytes between them.

The relay is **not** the coordination server. The coord server is a thin
public-key directory; it never carries traffic. The relay is a separate
process (`veld-relay`) that anyone in the mesh can volunteer to run on any
host both peers can reach over TCP. A relayed path is used only after hole
punching times out — the P2P-first model is unchanged.

The relay is **blind by construction**: it forwards frames that are already
end-to-end encrypted between the peers, so it can observe connection
endpoints, traffic volume, and timing — never packet contents.

---

## Cryptography

- **Handshake.** Each peer connects to the relay over TCP and completes a
  Noise **IK** handshake (X25519 + SHA-256 + ChaCha20-Poly1305) against the
  relay's **pinned X25519 static key**. The peers refuse to talk to a relay
  whose key does not match the pinned `relay_x25519` value, so the handshake
  is mutually authenticated and not downgradeable by an impostor relay.
- **Rendezvous channel.** The encrypted payload of the handshake's first
  message carries the **remote peer's X25519 public key**. The relay derives
  a rendezvous channel ID as an **order-independent SHA-256** over both
  peers' keys (so both sides arrive at the same channel no matter who
  connects first) and splices the two connections that arrive on that
  channel from opposite sides. Because the channel is derived from the
  *authenticated* initiator key — not from a client-supplied channel ID — a
  third party who merely knows both public keys cannot join or hijack a
  pair's channel.
- **Data plane.** Frames forwarded over a channel are the peers' own
  data-plane datagrams, already protected end-to-end by the session layer
  (peer-to-peer Noise IK + ChaCha20-Poly1305). The relay is cryptographically
  blind to their contents.

---

## Deployment

The relay is a single static binary built from [`cmd/veld-relay`](../cmd/veld-relay/):

```sh
make veld-relay     # → bin/veld-relay
# or copy veld-relay out of a release archive to /usr/local/bin/
```

It takes a TCP listen address and a path to an identity keystore:

```sh
veld-relay -listen :41820 -identity /etc/veld-relay/identity.json
```

On first run the relay **generates an identity** and **prints its X25519
public key**. To provision the identity without starting the listener — for
example before the systemd service's first start — use `-gen-identity`,
which loads an existing keystore or creates one, prints the public key, and
exits. It never rotates an existing identity, so it is safe to re-run:

```sh
veld-relay -gen-identity -identity /etc/veld-relay/identity.json
```

The operator then shares two values with every peer that should use the
relay:

- `relay_addr` — the relay's public address as `host:port` (the `-listen`
  address, e.g. `relay.example.com:41820`), and
- `relay_x25519` — the base64 X25519 public key the relay printed.

Peers pin both values in their own config; the coord server does **not**
hand them out (see [Key management](#key-management) for why they must never
silently change).

### Running under systemd (Ubuntu 24.04)

The repo ships a unit at [`deploy/veld-relay.service`](../deploy/veld-relay.service):

```sh
# 1. Install the binary.
install -m 0755 veld-relay /usr/local/bin/veld-relay

# 2. Create the dedicated veld-relay user and provision the identity.
#    Run the provisioning step as the veld-relay user so the directory
#    (/etc/veld-relay, mode 0700) and keystore (identity.json, mode 0600)
#    are owned by veld-relay and readable by the service.
sudo useradd --system --no-create-home --shell /sbin/nologin veld-relay
sudo -u veld-relay /usr/local/bin/veld-relay -gen-identity -identity /etc/veld-relay/identity.json

# 3. Install and start the service.
sudo cp deploy/veld-relay.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now veld-relay

# 4. Watch the startup lines (they print the public key once more).
journalctl -u veld-relay
```

The unit runs as the dedicated unprivileged `veld-relay` user, restarts on
failure, logs to the journal, and applies systemd sandboxing
(`ProtectSystem=strict`, `NoNewPrivileges`, `PrivateTmp`, ...). `:41820` is
an unprivileged port, so no `CAP_NET_BIND_SERVICE` is needed; if you change
`-listen` to a port below 1024, uncomment the `AmbientCapabilities` line in
the unit.

### Manual provisioning (without systemd)

If you run the relay outside systemd, create the user and directory with the
correct ownership, then run the binary. The `-gen-identity` flag handles
creating the directory (mode 0700) and keystore (mode 0600) with the right
owner if you run it as the `veld-relay` user:

```sh
sudo useradd --system --no-create-home --shell /sbin/nologin veld-relay
sudo -u veld-relay /usr/local/bin/veld-relay -gen-identity -identity /etc/veld-relay/identity.json
```

Then run the service as that user:
```sh
sudo -u veld-relay /usr/local/bin/veld-relay -listen :41820 -identity /etc/veld-relay/identity.json
```

### Logging and privacy

By default the relay logs only startup output — **no per-connection events**
(no channel IDs, no client addresses). A `-verbose` flag exists for local
debugging (truncated client addresses); it is off by default and not intended
for production.

---

## Configuring peers

Peers opt into the relay by pinning its address and key in their
`config.toml`, inside the `[coord]` section (relay fallback is engaged by
the daemon after NAT hole punching times out):

```toml
[coord]
addr         = "coord.example.com:50051"
network_id   = "0123456789abcdef0123456789abcdef"
token        = "..."
relay_addr   = "relay.example.com:41820"              # empty = no relay fallback
relay_x25519 = "<base64 X25519 public key printed by veld-relay>"
```

`relay_x25519` is required whenever `relay_addr` is set — the daemon refuses
to use an unpinned relay. Today these values are distributed manually (any
secure channel works: they are public values, and the pinning makes
tampering detectable). When coord mode grows support for managed relay
distribution, peers will be able to receive them from the coord server
instead.

---

## Ports and firewalls

| Direction | Port | Protocol | Purpose |
|---|---|---|---|
| Inbound (relay host) | 41820 | **TCP only** | Noise IK relay connections from peers |

The listen port is configurable via `-listen` (and in the systemd unit).
There is **no UDP** component — the relay only splices TCP connections; the
datagrams inside them belong to the peers' end-to-end session.

```sh
ufw allow 41820/tcp
```

---

## Scaling

One relay instance handles many concurrent rendezvous channels; the work per
frame is a ChaCha20-Poly1305 decrypt/encrypt pair, so CPU and RAM use are
negligible even for a busy mesh. The relay keeps no per-peer state beyond
in-flight channels, and unpaired connections are evicted after 60 seconds.

A relay can run on the same VM as other services (including a coord server),
as a tiny sidecar on any always-on host, or on the cheapest available VPS —
all that matters is that both peers of a failing NAT pair can reach it over
TCP. Run more than one relay (with different identities and addresses) for
redundancy; peers pin one relay per config today.

---

## Key management

The relay's identity lives in `/etc/veld-relay/identity.json` (mode 0600,
owned by the `veld-relay` user). It **must persist across restarts, service
upgrades, and redeploys**: peers pin `relay_x25519` and `relay_addr` in their
own configs, and the coord server does not distribute them — so a rotated
identity silently breaks every peer's relay fallback until each one is
updated.

- **Backup** `/etc/veld-relay/identity.json` **off the VM** at your
  discretion. Treat it like a TLS private key: anyone who obtains it can
  impersonate the relay to peers that pin it.
- **If the identity is lost**, regenerate it with
  `veld-relay -gen-identity -identity /etc/veld-relay/identity.json`, which
  prints the new X25519 public key — then distribute the new
  `relay_x25519` and `relay_addr` to **all peers** and update their
  `config.toml`.
- The `-gen-identity` flag is idempotent: re-running it never rotates an
  existing key; it only prints the current public key.

---

## License note

The **relay server** (`cmd/veld-relay` and the top-level `relay/` package) is
licensed under the **Business Source License 1.1** (BSL-1.1), like the coord
server: the source is available and you may self-host it freely for personal
or internal use, but you may **not** offer it to third parties as a hosted,
managed, or embedded relay service (or as part of a competing mesh VPN
service) without a commercial license. Each version converts to Apache 2.0
four years after its public release.

The **relay client** ([`internal/relay/`](../internal/relay/)), which is
linked into every MIT-licensed daemon, stays **MIT** — the wire protocol is
open, and peers never need a BSL-licensed component to *use* a relay.

See [`relay/LICENSE`](../relay/LICENSE) for the full terms and
`licensing@veldmesh.io` for commercial licensing.
