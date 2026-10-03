# Veld Architecture

This document describes the high-level design of Veld — how the daemon, data plane,
NAT traversal, and coordination server fit together. It complements the low-level
*crypto invariants and packet formats* in [`DEVELOPMENT.md`](DEVELOPMENT.md); where
the two disagree, this document is the narrative and DEVELOPMENT.md is normative.

Veld is a **decentralized peer-to-peer private mesh network**. Devices connect directly,
everywhere, without trusting a middleman. The coordination server is a thin public-key
directory that is **cryptographically blind** to traffic after the initial handshake.

---

## 1. Core design principle

**The coordination server must never see, route, or authenticate data-plane traffic.**

After peers exchange public keys and an endpoint, all traffic flows directly between
machines over a Noise IK-encrypted UDP tunnel. The coordination server's only role is to
answer the question *"who else is in my network, and how do I reach them?"* — and it is
structurally incapable of doing more, because it stores nothing but public keys, opaque
endpoints, and opaque NAT-traversal signal payloads it cannot decrypt.

Every architectural decision is evaluated against this invariant:
> *"Does this preserve the user's ability to verify that the coordination server is blind?"*

---

## 2. System overview

```
┌─────────────────────────────────────────────────────┐
│  Your machine                                       │
│  ┌──────────────┐    UDP (Noise-encrypted)          │
│  │   kernel     │◄──────────────────────────────►   │
│  │  (routing)   │                         Peer B    │
│  └──────┬───────┘                                   │
│         │ TUN interface (10.100.0.1)                │
│  ┌──────▼───────────────────────────────────────┐   │
│  │  veld-daemon                                 │   │
│  │  ┌──────────┐ ┌──────────┐ ┌─────────────┐   │   │
│  │  │ dataplane│ │ session  │ │ nat/ICE     │   │   │
│  │  │dispatcher│ │ (Noise)  │ │ traversal   │   │   │
│  │  └──────────┘ └──────────┘ └──────┬──────┘   │   │
│  │  ┌──────────┐ ┌──────────┐ ┌──────▼──────┐   │   │
│  │  │   TUN    │ │ peer tbl │ │ coord client│   │   │
│  │  └──────────┘ └──────────┘ └──────┬──────┘   │   │
│  └───────────────────────────────────┬──────────│───┘
│                                      │ gRPC (TLS)│
└──────────────────────────────────────┼──────────┘────
                                       ▼
                            ┌─────────────────┐
                            │ veld-coord      │  ← thin: pubkeys +
                            │ (coord server)  │    endpoints only
                            └─────────────────┘
```

Veld runs in three operating modes:

| Mode | Discovery | Requires a server? | Use case |
|---|---|---|---|
| **Static config** | Peer endpoints hard-coded in `config.toml` | No | VPS pairs, port-forwarded routers |
| **LAN (mDNS)** | mDNS/DNS-SD on the local network | No | Peers already on the same LAN |
| **Coord server** | Public-key directory with NAT traversal | Yes (or self-host) | Full mesh over the internet |

---

## 3. Component breakdown

### 3.1 Coordination server (`coord/`)

- **Role:** public-key directory plus a NAT-traversal signal channel. Nothing else.
- **Store:** bbolt single-file DB (`coord/server/registry.go`) mapping
  `peer ID → public key (Ed25519 + cross-signed X25519) + last-seen endpoint + VPN address`.
- **API:** gRPC service `Coord` (`proto/veld/coord/v1/coord.proto`), defined by five RPCs:
  `Register`, `ListPeers`, `Watch` (server-streaming), `SendSignal`, `Leave`.
- **Network isolation:** `ListPeers`/`Watch` are scoped by `network_id`. Peers in network
  A can never query network B.
- **Auth:** a network `token` resolves to an account; the daemon presents it on every RPC.
- **Blind by construction:** the server stores and relays only public keys, endpoints, and
  opaque signal payloads. Preregistered traffic and data payloads never transit the server.
  NAT-traversal signals are encrypted *end-to-end* between peers (via each peer's X25519
  key), so the server cannot read candidate endpoints — it is a dumb relay for those bytes.

### 3.2 Tier enforcement (`coord/core/` + `coord/ce/`)

All monetization logic sits behind five interfaces in `coord/core/`:

| Interface | CE implementation | Responsibility |
|---|---|---|
| `PlanEnforcer` | `FreeEnforcer` | Gates machine count, network count, subnet routing |
| `AccountStore` | `TokenAccountStore` | Resolves tokens → accounts + tier |
| `AuditLogger` | `NoopAuditLogger` | Compliance event logging |
| `SubnetPolicy` | `RejectSubnetPolicy` | Allows/denies CIDR route announcements |
| `LifecycleHooks` | `NoopHooks` | Billing counters, webhooks, metrics |

The CE (`coord/ce/`) implementations **are the complete, free-tier implementations** — there
are no hidden toggles. Managed implementations (billing, SSO, real audit pipeline) are
closed-source and inject the same interfaces. Adding a gated feature means adding a method
to the relevant interface plus a reject/no-op CE implementation — never a boolean flag.

### 3.3 Data plane (`internal/dataplane/`, `internal/session/`, `internal/crypto/`)

- **Encryption:** Noise IK pattern (X25519 + SHA-256 + ChaCha20-Poly1305), via
  `github.com/flynn/noise`. Identity keys are Ed25519; ephemeral session keys are X25519.
- **Tunnels:** userspace TUN via `golang.zx2c4.com/wireguard/tun` — **no kernel module, no
  WireGuard daemon**. The cipher is ChaCha20-Poly1305 directly, not WireGuard's.
- **Sessions:** per-peer symmetric send/recv cipher states with a monotonically increasing
  nonce per direction and a 2048-entry replay window. Rekey triggers before the nonce
  crosses 2³². Session keys exist only in memory — never serialized or transmitted.
- **Hot path** (`internal/dataplane/dispatcher.go`): two goroutines move packets between the
  TUN device and the UDP socket, applying session encrypt/decrypt. On a session miss, the
  packet is held in a bounded queue (max 64) while a handshake completes, then flushed.

### 3.4 Handshake (`internal/handshake/`)

Custom Noise IK handshake. Two encrypted messages:

- **message_1** (initiator → responder): initiator X25519 static pubkey, initiator
  Ed25519 pubkey, Ed25519 signature binding `(init_x25519 ‖ resp_x25519 ‖ timestamp)`,
  and the 16-byte network UUID.
- **message_2** (responder → initiator): responder Ed25519 pubkey + its own signature
  binding, plus a random 8-byte session id.

Timestamp window is ±30 s. The initiator's Ed25519 key must already be in the peer table.
**Any validation failure is a silent drop** (no error reply — an error would be an oracle),
with a metric increment. Binding the network ID and uncached signatures prevents cross-network
replay and key-substitution attacks, and makes the handshake self-authenticating once the
peer table is seeded.

### 3.5 NAT traversal (`internal/nat/`)

ICE-style UDP hole punching:

1. On discovering a peer, the NAT manager gathers **candidates** (interface IPs + optional
   server-reflexive address from a STUN server).
2. Candidates are JSON-encoded, **encrypted for the peer's X25519 key**, and sent via
   `coord SendSignal`. The coord server relays the ciphertext but cannot read it.
3. Both sides send `NATProbe` UDP packets to every candidate they received, on the shared
   data-plane connection.
4. When a probe reply arrives with a matching probe nonce, the endpoint is confirmed and
   handed to the daemon, which initiates the Noise handshake.

For peers reachable purely within a LAN, mDNS discovery (`internal/mdns/`) avoids the coord
server and NAT traversal entirely.


**Relay fallback (DERP-style).** When hole punching times out — e.g. both peers behind
symmetric NATs — the NAT manager hands off to a relay path instead of giving up
(`internal/relay/`). The relay is a volunteer mesh peer running the `veld-relay`
command, reachable over TCP by both sides and configured via `coord.relay_addr` + the
relay's pinned X25519 key (`coord.relay_x25519`). It is *not* the coord server —
it is an out-of-band mesh peer, not an extension of the directory — and no relay
traffic ever transits the coord server:

1. Each peer opens a TCP connection to the relay and completes a **Noise IK
   handshake** against the relay's pinned static key. The encrypted payload of
   message_1 carries the *remote peer's* X25519 public key; the relay derives the
   rendezvous channel from the client key it just authenticated plus that payload
   (order-independent SHA-256), so no extra signalling is needed and a third party
   who merely knows both peers' public keys cannot join or hijack a pair's
   channel. The relay splices the two connections of a matched channel and forwards
   opaque frames between them.
2. Each daemon stands up a loopback UDP proxy (`relay.Proxy`) that frames data-plane
   datagrams onto the relay channel and injects arriving datagrams back into the local
   data-plane socket. The proxy accepts datagrams only from the daemon's own socket;
   its loopback address becomes the peer's endpoint, so the dispatcher and handshake
   manager treat the relay path exactly like a direct one. The daemon keeps at most
   one proxy per peer — replaced on a fresh fallback, torn down when the peer leaves.
3. The peers then run the normal peer-to-peer Noise IK data-plane handshake *through*
   the channel. All payloads are end-to-end session-encrypted (ChaCha20-Poly1305), so
   the relay — like the coord server — is cryptographically blind to traffic content;
   it observes only connection metadata, volume, and timing. Unpaired connections are
   evicted after a wait timeout, and the handshake itself is time-bounded.

The P2P-first model is unchanged: the relay is used only after hole punching fails,
and any mesh peer (or a small self-hosted VM) can volunteer as a relay.

### 3.6 Client (`cmd/`, `internal/`, `tray/`)

- **`veld`** — CLI control tool (add/remove peers and networks).
- **`veld-daemon`** — background service wiring TUN + UDP + peer table + dispatcher +
  handshake manager + (optional) coord client + (optional) NAT manager, over an IPC socket.
- **`veld-coord`** — the CE coordination server binary (single process, bbolt-backed).
- **`veld-relay`** — volunteer DERP-style relay binary (§3.5); generates an identity on first run and prints its X25519 public key.
- **`tray/`** — desktop tray front end.
- Config lives in `~/.config/veld`, is 0600, and holds the persistent Ed25519 identity.
  The coord server address is configurable, enabling self-hosted deployments.

---

## 4. Subnet routing

A peer may act as a **subnet router**, advertising a CIDR prefix on behalf of a local
network (`internal/route/`, Linux via `vishvananda/netlink`). Advertised prefixes are
validated against `SubnetPolicy` at the coord server (gated at the Teams tier and above),
propagated to other peers through `Register`/`Watch`, and installed as kernel routes through
the router peer. The router enables `ip_forward` on the advertising node. Subnet routes are
rejected by default in the CE/free tier (`RejectSubnetPolicy`).

---

## 5. Trust model & threat boundaries

| Claim | How it's enforced |
|---|---|
| Coord server is blind after handshake | Server stores only pubkeys/endpoints; NAT signals are end-to-end encrypted; no data plane transits the server |
| Private key never leaves the device | Ed25519 identity is generated locally and persisted 0600; only public keys cross the wire; no RPC requests a secret |
| Deterministic, verifiable | Daemon, CLI, and coord server are MIT/BSL open source; protocol is in `proto/` and documented in `DEVELOPMENT.md` |
| Peers in an org are isolated | `network_id` scoping on every coord RPC |
| Compromised coord server ≠ compromised sessions | A malicious or pwned server can re-route handshakes, but TOFU key pinning (`internal/tofu/`) on a fresh-connect fingerprint blocks key substitution on subsequent connections |

---

## 6. Extension points

- **New gated feature** → new method on a `coord/core` interface + reject CE impl; never a flag.
- **New OS platform** → `internal/tun/tun_<os>.go` (build-tagged), implement `CreateTUN`,
  add the `GOOS/GOARCH` pair to the Makefile matrix, and verify with a real e2e ping.
- **Managed SaaS layer** (billing, SSO, audit pipeline, admin dashboard, relay infra) is
  closed-source and plugs into the coord server through the same five interfaces.

See `DEVELOPMENT.md` for the crypto invariants, testing approach, and build targets.
