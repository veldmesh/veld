# Development Guide

This document captures the architectural decisions, invariants, and patterns that every contributor (and Claude Code) should know before touching this codebase.

---

## Crypto invariants — do not break these

1. **Ed25519 private keys never leave the device.** The coord server receives only the Ed25519 *public* key and the X25519 *public* key (cross-signed). Never add an RPC that requests a private key or a derived secret.

2. **Session keys are derived in-memory only.** ChaCha20-Poly1305 send/recv keys exist only in `internal/session/session.go`. They are never serialized to disk or sent over the network.

3. **Nonces are strictly monotonically increasing per session per direction.** The send nonce is an atomic counter. Never reuse a nonce. Rekey (new handshake) before a nonce rolls over 2^32.

4. **The replay window covers the last 2048 nonces.** A packet with a nonce outside the window (too old) is silently dropped. Never respond with an error — it would be an oracle.

5. **Unknown handshake initiators are silently dropped.** No error response. Responding to unknown initiators leaks information about which public keys are valid.

6. **TOFU fingerprints are checked before completing a handshake.** If a peer's Ed25519 pubkey doesn't match the locally pinned fingerprint, abort and log clearly. Do not downgrade to "warn only" mode.

---

## Logging & privacy

Server components (`veld-coord`, `veld-relay`) must not log client IP
addresses or per-connection details. Rules — enforce these in review:

1. **Never log tokens, keys, or other credentials** — not even partially.
2. **Never log a full client IP address.** If a remote address is genuinely
   needed to debug, truncate it with `internal/logsafe.TruncIP` first
   (IPv4 → first three octets, `a.b.c.x`; IPv6 → first 48 bits) — or drop
   the field entirely if it is not needed. Error text counts as a field:
   `*net.OpError` (what every `net.Conn` read/write returns) embeds both
   endpoints' full `ip:port`, so never log a raw connection error — render it
   with `logsafe.ScrubErr`, which drops the endpoints and truncates any
   surviving address.
3. **`veld-relay` logs no per-connection events by default** — no channel
   IDs, no client addresses; only startup/shutdown output. The `-verbose`
   flag re-enables per-connection logs (channel IDs, truncated addresses)
   for local debugging only: off by default, not for production.
4. **`veld-coord` logs no per-connection events at all** — only
   startup/shutdown and top-level operational errors. Auth failures return
   a generic "invalid token" without echoing the token.

Retention: with these rules, default logs retain nothing that identifies a
client — no IP addresses, no channel IDs, no tokens — only what is needed
to operate and debug the service itself.

---

## Extension point rules

All tier enforcement goes through the interfaces in `coord/core/`. Rules:

- **Never call billing or account logic directly from `coord/server/`.** Always go through the injected interface.
- **CE implementations must be complete and independently testable.** The CE binary must compile and pass all tests without any `managed/` code.
- **Adding a new gated feature = add a method to the relevant interface + a no-op/reject CE implementation.** Do not add a boolean flag or config option as a shortcut.
- **`LifecycleHooks` must never block the request path.** Fire-and-forget. Managed implementations should send to a buffered channel, not make synchronous HTTP calls inline.

Current interfaces in `coord/core/`:

| Interface | CE implementation | Purpose |
|---|---|---|
| `PlanEnforcer` | `FreeEnforcer` | Gates machine count, network count, subnet routing |
| `AccountStore` | `TokenAccountStore` | Resolves auth tokens to accounts |
| `AuditLogger` | `NoopAuditLogger` | Event logging for compliance |
| `SubnetPolicy` | `RejectSubnetPolicy` | Allows/denies subnet route announcements |
| `LifecycleHooks` | `NoopHooks` | Billing counters, webhooks, metrics |

---

## Handshake format

Noise IK pattern (`github.com/flynn/noise`). See `internal/crypto/noise.go`.

**message_1** (initiator → responder, encrypted for responder's X25519 pubkey):
```
initiator_x25519_static_pubkey  [32 bytes]
initiator_ed25519_pubkey         [32 bytes]
ed25519_sig(initiator_x25519 || responder_x25519 || unix_timestamp_seconds) [64 bytes]
network_id                       [16 bytes, UUID]
```

**message_2** (responder → initiator, encrypted under shared key):
```
responder_ed25519_pubkey         [32 bytes]
ed25519_sig(responder_x25519 || initiator_x25519 || unix_timestamp_seconds) [64 bytes]
session_id                       [8 bytes, random]
```

Timestamp window: ±30 seconds. Ed25519 key in message_1 must be in the peer table (populated from coord server). On any validation failure: silent drop, increment a metric counter.

---

## Packet format

Every encrypted UDP datagram:
```
[4 bytes]  packet_type   0x01=data, 0x02=handshake_init, 0x03=handshake_resp, 0x04=keepalive
[4 bytes]  sender_index  receiver-assigned session ID (like WireGuard)
[8 bytes]  nonce         monotonically increasing, per-session per-direction
[N bytes]  ciphertext    ChaCha20-Poly1305 encrypted payload + 16-byte auth tag
```

---

## Data plane hot path

`internal/dataplane/dispatcher.go` runs two goroutines:

**TUN read loop:**
1. `tun.ReadPacket()` → raw IP bytes
2. Extract destination IP from IP header
3. `peer.Table.Lookup(destIP)` → `PeerState`
4. If no session: enqueue to `PeerState.HoldQueue` (max 64), trigger handshake, return
5. `session.Encrypt(plaintext)` → increment nonce, ChaCha20-Poly1305
6. Build UDP datagram, `udpConn.WriteToUDP`

**UDP read loop:**
1. `udpConn.ReadFromUDP()` → datagram + source addr
2. Parse `sender_index`, look up session
3. `session.Decrypt(nonce, ciphertext)` → verify replay window + auth tag
4. On auth failure: silent drop
5. `tun.WritePacket(plaintext)`

Do not add allocations to the hot path. Benchmark before and after any change to the dispatcher.

---

## Adding a new OS platform

1. Create `internal/tun/tun_<os>.go` with build tag `//go:build <os>`
2. Implement `CreateTUN(name string, ip netip.Prefix, mtu int) (TUN, error)` using the OS-appropriate method
3. Add the `GOOS/GOARCH` pair to the cross-compile matrix in `Makefile`
4. Test with a VM — do not mark as supported without a real end-to-end ping test

---

## Coord server gRPC API

Defined in `proto/veld/coord/v1/coord.proto`. Always regenerate with `make proto` after editing — never hand-edit files in `gen/`.

The `Coord` service is the daemon-facing gRPC API defined in `proto/veld/coord/v1/coord.proto`. Keep it focused on peer coordination — do not add management, billing, or dashboard endpoints to it. Any separate management surface has different auth, different stability guarantees, and a different audience.

### Register: proof of key possession

`Register` is signed: only the holder of the Ed25519 private key matching
`ed25519_public` can register or update the peer whose ID is that key. The
request carries `timestamp_unix` (field 8, the client clock in unix seconds)
and `signature` (field 9) — an Ed25519 signature over the deterministic
message

```
"veld-coord-register-v1\x00"                       domain-separation prefix
|| u32(len(network_id))     || network_id
|| u32(len(ed25519_public)) || ed25519_public       base64, exactly as sent
|| u32(len(x25519_public))  || x25519_public        base64, exactly as sent
|| u32(len(endpoint))       || endpoint             "ip:port" or ""
|| u32(route count)         || each route as u32(len) || cidr, sorted
|| u64(timestamp_unix)                              big-endian
```

with all lengths big-endian. The encoding lives in one function shared by
client and server — `crypto.RegisterSignedMessage` (`internal/crypto/register.go`;
sign with `crypto.SignRegister`, verify with `crypto.VerifyRegisterSignature`) —
and is locked by the golden vector in `TestRegisterSignedMessage_Vector`
(`internal/crypto/register_test.go`).

The signature is required: there are no unsigned clients in the field, so there
is no transition flag. A missing, garbage or wrong-key signature, any tampered
signed field, or a timestamp with |now − timestamp_unix| > 120 s is rejected with
`codes.Unauthenticated` — before any registry write, so a rejected registration
changes nothing (no record, no machine count, no address consumed, no event).

The proto3 wire addition is backwards compatible (old servers ignore the new
fields), but the behavior is not: a new coord server rejects registrations from
old clients, which never sign. Release the client (`veld`/`veld-daemon`) and
the coord server (`veld-coord`) together — see `RELEASE_NOTES.md`.

Signed key rotation (an old-key → new-key handover) is out of scope here; it is
the planned follow-up.

---

## Coord server peer TTL sweep

`veld-coord` runs a background sweep (`coord/server/sweep.go`, `Server.ExpelStalePeers`) that prunes peers whose
registration has lapsed, keeping the bbolt registry consistent with the "blind directory"
model — entries age out instead of accumulating forever.

- A peer is stale when `now - LastSeen > peer-ttl`. Peers that never sent a heartbeat
  (`LastSeen == 0`) are aged by `RegisteredAt` instead.
- **Peers with an active `Watch` stream are never swept.** A connected daemon is online by
  definition; the server tracks connected peers and refreshes their `LastSeen` every minute
  for the lifetime of the stream, so long-lived connections cannot go stale.
- Expelled peers get the same treatment as a graceful `Leave`: a `LEAVE` event is published
  to the network’s watchers, `LifecycleHooks.OnPeerLeft` fires, and a `peer.left` audit
  entry is written. Remaining peers never keep ghost entries.
- The sweep only deletes existing keys; the on-disk schema is unchanged and backward compatible.
- Flags: `--peer-ttl` (default **720h = 30 days**, exported as `server.DefaultPeerTTL`; `0` disables
  the sweep) and `--sweep-interval` (default **1h**, `server.DefaultSweepInterval`). Values below
  `server.MinSweepInterval` (**1 minute**) are clamped up to it, so a misconfigured flag cannot
  churn the registry write path.

## Coord server endpoint storage

Peer endpoints (public `ip:port`) are the only registry data the coord server needs to
serve to other peers, and they do not need to outlive the process. `coord/server/registry.go`
keeps them in a mutex-guarded in-memory map keyed by peer ID:

- Filled on `Register` (including idempotent re-registrations) and `UpdateEndpoint`.
- Served wherever peers learn about each other: `ListPeers` results and `Watch` snapshot events.
- Dropped when a peer leaves (`Leave`) or is removed by the TTL sweep.
- Never written to bbolt: persisted peer records hold only the peer ID, network ID, name,
  VPN address, public keys, subnet routes, and a last-seen timestamp rounded down to the
  hour — coarse enough for the TTL sweep without retaining precise activity times.
  A zero last-seen is preserved as-is: it is the "never sent a heartbeat"
  sentinel, which the sweep ages by the peer's `RegisteredAt` timestamp
  instead.

After a coord restart the map starts empty; endpoints are re-learned as daemons re-register.
Daemons already re-register whenever they (re)connect to the coord server, so no extra
protocol or operator action is needed.

A one-time, idempotent startup migration in `NewRegistry` blanks the `endpoint` field of
records persisted by older builds, so upgrading never leaves historical endpoints on disk.

---

## Testing approach

Every component has two layers of tests. Both are required — do not skip either.

CI and releases always build with the latest Go 1.26.x patch (`go-version: '1.26.x'`, `check-latest: true` in the workflows); bump the minor (1.27.x) deliberately, not as a side effect of a dependency bump.

CI runs the race detector and `govulncheck` on every pull request: the `race` job runs `go test -race ./...` on Ubuntu (plain `go test ./...` runs on macOS and Windows, where the race detector needs a cgo toolchain), and the `govulncheck` job scans for known vulnerabilities the code actually reaches. To run the same checks locally: `go test -race ./...` for the race detector, and `go install golang.org/x/vuln/cmd/govulncheck@latest && govulncheck ./...` for the vulnerability scan.

### Layer 1 — Unit tests (`internal/<pkg>/*_test.go`)

Each package has its own `_test.go` files that test functions and methods in isolation.

Rules:
- Test every exported function and method, including all error paths.
- For each function, cover: happy path, boundary values, and every distinct failure mode.
- Never mock crypto — use real keys and real primitives.
- Never mock the bbolt registry in coord server tests — use a real in-memory or temp-file instance.
- Use `t.Run` subtests when testing multiple cases of the same function.

Required unit tests per package (non-exhaustive — add more as edge cases are found):

| Package | Must cover |
|---|---|
| `internal/crypto` | Key clamping, sign/verify happy path, wrong key, tampered sig, swapped keys, timestamp boundary (±30s), X25519Sig binding, Register signed-message vector, proof-of-possession window (±120s) and tamper cases |
| `internal/config` | Save/load round-trip, LoadOrGenerate idempotency, invalid JSON, wrong version, file permissions (0600) |
| `internal/session` | Encrypt→decrypt round-trip, nonce monotonicity, replay rejection (duplicate nonce, nonce outside window), auth tag failure → silent drop, rekey trigger at threshold |
| `internal/peer` | Concurrent Upsert/Lookup/Remove, hold queue max-64 drop-oldest behaviour |
| `internal/dataplane` | Packet routing to correct session, session-miss hold-queue behaviour, keepalive handling |
| `coord/server` | Register verifies proof of key possession (missing, wrong-key, tampered-field, stale and future-timestamp rejections change nothing), Register calls PlanEnforcer, ListPeers returns correct subset, SendSignal routes to correct watcher, Leave removes peer |

### Layer 2 — End-to-end tests (`tests/e2e/*_e2e_test.go`)

E2E tests wire multiple real components together without mocks. They live in `tests/e2e/` (package `e2e_test`) so they can import any combination of packages without circular import risk.

Rules:
- One file per major milestone (crypto, session, full-tunnel, coord-server, nat).
- Build up incrementally — each new task adds an e2e test for the complete flow up to that point.
- E2E tests may be slower; tag them `//go:build e2e` if they require a real TUN device (needs root/CAP_NET_ADMIN in CI).
- Always assert on observable behaviour (packets arrive, ping succeeds, session established) — not on internal state.

E2E test progression:

| File | What it tests | When added |
|---|---|---|
| `tests/e2e/crypto_e2e_test.go` | Full two-peer sign/verify round-trip | Task 2 ✓ |
| `tests/e2e/session_e2e_test.go` | Encrypt→send→receive→decrypt between two session objects | Task 4 |
| `tests/e2e/tunnel_e2e_test.go` | Two daemons (static config), ping succeeds, no plaintext on wire | Task 8 |
| `tests/e2e/coord_e2e_test.go` | Two daemons + real coord server, auto-discover and connect | Task 12 |
| `tests/e2e/nat_e2e_test.go` | Two daemons behind simulated NAT, hole-punch succeeds | Task 14 |
| `tests/e2e/relay_e2e_test.go` | Two peers behind symmetric NATs fall back to the relay path; datagrams delivered | Task 15 |

---

## Build targets

```
linux/amd64    linux/arm64    linux/arm/v7   linux/arm/v6
linux/mips     linux/mipsle   darwin/amd64   darwin/arm64
windows/amd64
```

Memory target for MIPS/ARMv6 builds: ≤30 MB RSS. Profile before shipping.

---

## Key dependencies

| Package | Reason for choice |
|---|---|
| `golang.zx2c4.com/wireguard/tun` | Best cross-platform TUN abstraction; Wintun on Windows, utun on macOS, netlink on Linux |
| `github.com/flynn/noise` | ~1500 lines, well-audited, minimal. Not perlin-network/noise (heavier) |
| `github.com/pion/ice/v3` | ICE standalone, no need for full pion/webrtc |
| `go.etcd.io/bbolt` | Zero CGo, crash-safe (ACID), single-file DB for CE coord server |
| `github.com/vishvananda/netlink` | Required to configure TUN IP/routes on Linux after interface creation |

Do not add `pion/webrtc`, `wireguard-go` daemon, or `songgao/water` as dependencies.

---

## Naming placeholder

"veld" is used throughout as a placeholder. When the final name is chosen:
1. `git grep -r veld` to find all occurrences
2. Replace in: package paths (`go.mod`), binary names, config dir (`~/.config/veld`), DNS suffix, proto package name, Docker image name, systemd unit name
3. Single commit, squash if needed before pushing public
