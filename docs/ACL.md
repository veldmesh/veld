# Veld ACL (Access Control List)

Veld implements a two-layer ACL system for fine-grained control over which peers can communicate with each other and on which ports.

## Policy Model

A policy is a TOML file with the following structure:

```toml
version = 1                    # Integer, only increases
default = "deny"               # "allow" or "deny" (required)

[peers]
alice = "ed25519:<base64 or hex pubkey>"
bob   = "ed25519:<base64 or hex pubkey>"

[tags]
admins = ["alice", "bob"]
servers = ["carol"]

[[rule]]
from = "alice"                 # Peer name, "tag:<name>", or "*"
to   = "bob"                   # Peer name, "tag:<name>", or "*"
ports = ["tcp/22", "tcp/8000-8099"]

[outbound_only]
peers = ["bob"]                # Peer names that can only initiate connections
```

### Subjects

Subjects in `from` and `to` fields resolve to Ed25519 peer identities (32-byte public keys), never to VPN addresses or coordinator-assigned names.

- **Peer name**: `alice` — matches the specific peer
- **Tag**: `tag:admins` — matches all peers in the tag
- **Wildcard**: `*` — matches any authenticated peer

### Ports

Port specifications support:
- Single port: `tcp/22`, `udp/53`
- Port range: `tcp/8000-8099`
- ICMP: `icmp` (matches both ICMPv4 and ICMPv6)
- All protocols/ports: `*`

### Rule Semantics

A rule allows `from` to **start** a connection to `to` on the specified `ports`. Rules are one-way — a rule from `alice` to `bob` does not allow `bob` to start connections to `alice`.

Replies to an allowed connection always pass (bidirectional flow once established).

### Outbound-Only Peers

Peers listed in `[outbound_only].peers` may start connections but **cannot receive inbound connection attempts**, even if a rule would otherwise allow them. The keyword `self` refers to the local node.

Example:
```toml
[outbound_only]
peers = ["self"]    # This node is outbound-only
```

## Two-Layer Policy Enforcement

Veld enforces two policy layers:

1. **Local Policy** — File next to the daemon config (root-owned, unsigned). Covers inbound traffic **to this peer**.
2. **Network Policy** — Signed policy file, verified against pinned admin keys. Covers all peers in the network.

A packet passes only if **BOTH** policies allow it. Missing local policy = defer to network policy.

## Operating Modes

### Static Mode (Local File Only)

In static mode, the network policy is read from a local file (`network_file` in config). The daemon watches the file for changes and reloads on SIGHUP or file modification.

### Coordinator Mode (Distributed via Coordinator)

In coordinator mode, the signed network policy is **pushed to the coordinator** (`veld policy push`) which stores it as an opaque blob and distributes it to all peers via the `Watch` stream (initial snapshot + update events). The coordinator:

- **Never parses the policy payload** — only validates the envelope header (magic, format version, length)
- **Enforces size cap** — 256 KiB maximum
- **Enforces version monotonicity** — new version must be strictly greater than stored version
- **Authorizes pushes** — requires account token + call signature by a registered peer's key
- **Survives restarts** — stored in bbolt per network

Peers receive the current policy blob on `Register` and `Watch` and verify it exactly like a static network file:
- Signature validity (Ed25519 over canonical payload)
- Signer authorization (signer's public key in pinned `admin_keys`)
- Version monotonicity (refuse unsigned/unpinned/lower versions)

The coordinator **cannot widen or roll back** the policy — peers enforce the same verification locally.

## Daemon Configuration

Add a `[daemon.policy]` section to your config:

```toml
[daemon]
socket_path = "/run/veld/daemon.sock"

[daemon.policy]
local_file   = "/etc/veld/policy.toml"      # Optional; defaults to policy.toml next to identity file
network_file = "/etc/veld/policy.signed"    # Optional; signed network policy file (static mode)
admin_keys   = ["ed25519:AAAA...", "ed25519:BBBB..."]  # Pinned admin public keys for verification
```

### File Requirements

- **Linux/macOS**: Must be owned by root (UID 0) or the daemon's effective user. Must not be group/world-writable (mode 0600 or 0640).
- **Windows**: File permission checks are skipped (Windows ACLs are used instead).
- Missing file = no local policy (defer to network)
- Invalid/unparseable file = daemon refuses to start (fail closed)

### Network Policy Verification

Network policies are only enforced when at least one admin key is pinned via `admin_keys`. Without pinned keys, network policy files are ignored (logged once at startup). The daemon verifies:

1. **Signature validity** — Ed25519 signature over the canonical policy payload
2. **Signer authorization** — Signer's public key must be in `admin_keys`
3. **Version monotonicity** — New policy version must be higher than the stored highest version (rollback protection)

The highest accepted version and the signed envelope are persisted next to the identity file (`network-policy.bin`, mode 0600) and loaded **before the tunnel comes up**, surviving daemon restarts.

## Policy Loading & Reloading

- Local policy is loaded **before** the tunnel comes up (no unfiltered window on restart)
- Network policy is loaded **before** the tunnel comes up (no unfiltered window on restart)
- Hot-reload on SIGHUP: `kill -HUP <daemon-pid>` (both local and network)
- Automatic reload on file change (atomic swap; existing flows re-checked against new policy)
- Manual reload via IPC: `veld policy reload` (network policy only)
- A revoked peer loses open connections immediately

## Drop Counters & Logging

- Per-peer and per-rule drop counters
- Rate-limited logging: first drop per flow, then periodic summary (every 10s)
- Never logs per packet, never logs payload

## CLI Commands

### `veld policy check <policy.toml>`

Validate a policy file's syntax, resolve names/tags to IDs, and print warnings for unmatchable rules or unknown names. Exits with non-zero on errors.

```bash
$ veld policy check policy.toml
Policy OK (version 1)
  Default: deny
  Peers (3):
    alice: ed25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=
    bob: ed25519:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb=
    carol: ed25519:cccccccccccccccccccccccccccccccccccccccccccc=
  Tags (2):
    admins: alice, bob
    servers: carol
  Rules (3):
    [0] from=alice to=bob ports=tcp/22, tcp/8000-8099
    [1] from=tag:admins to=tag:servers ports=tcp/443, udp/53
    [2] from=* to=carol ports=icmp
  Outbound-only peers: bob

$ veld policy check bad_policy.toml
policy: rule 0: from: unknown peer: "unknown"
```

### `veld policy test <policy.toml> <from> <to> <proto/port>`

Test a policy decision against a policy file. `<from>` and `<to>` accept peer names or Ed25519 public key IDs (32-byte hex). `<proto/port>` examples: `tcp/22`, `udp/53`, `icmp`, `*`.

Prints allow/deny and which rule (or default) decided. Honours outbound_only.

```bash
$ veld policy test policy.toml alice bob tcp/22
ALLOW
  Matched rule 0: from=alice to=bob ports=tcp/22, tcp/8000-8099

$ veld policy test policy.toml bob alice tcp/22
DENY
  Default action: deny

$ veld policy test policy.toml alice bob tcp/80
DENY
  Default action: deny

$ veld policy test policy.toml alice carol icmp
ALLOW
  Matched rule 2: from=* to=carol ports=icmp
```

### `veld policy keygen [--out admin.key]`

Generate an Ed25519 admin key pair for signing network policies. This key is **separate from node keys** and should be kept secure (offline if possible). The private key is written to a file with 0600 permissions. The public key is printed to stdout.

```bash
$ veld policy keygen --out admin.key
ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Private key written to admin.key (0600)
Keep this key secure! It is used to sign network policies.
```

**Key handling advice**: Keep the admin private key **offline** and off the coordinator. Use it only to sign policy files. Distribute the signed `policy.signed` file to peers; the private key never leaves your secure environment.

### `veld policy sign <policy.toml> --key admin.key [--out policy.signed]`

Sign a policy TOML file with an admin private key, producing a signed network policy envelope. The envelope includes the canonical policy, version, signer public key, and Ed25519 signature. Refuses to overwrite an existing output file if its version is >= the new policy's version.

```bash
$ veld policy sign policy.toml --key admin.key --out policy.signed
Signed policy written to policy.signed (version 1)
```

### `veld policy push <policy.signed>`

Push a signed network policy envelope to the coordinator. The coordinator verifies the envelope header, checks the size cap (256 KiB) and version monotonicity, stores it, and distributes it to all peers in the network via the Watch stream. Requires the daemon to be running and connected to a coordinator.

```bash
$ veld policy push policy.signed
network policy pushed (version 2)
```

### `veld policy reload`

Triggers the running daemon to reload the network policy file via IPC. Requires the daemon to be running with a network policy configured.

```bash
$ veld policy reload
network policy reloaded
```

### `veld policy status`

Show the active local policy path and hash, network policy version/signer/age, drop counters per peer and rule, and the last N drops (peer, proto, port, time; no payload). When using coordinator mode, also shows if the coordinator's version differs from the locally enforced version (stale peer visible).

```bash
$ veld policy status
Local Policy:
  Path: /etc/veld/policy.toml
  Hash: sha256:a1b2c3d4e5f67890...
  Version: 1
  Default: deny
  Rules: 3

Network Policy:
  Version: 2
  Signer: ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
  Age: 5m30s
  Coordinator Version: 2  (synced)

Drop Counters:
  By Peer:
    aaaaaaaabbbbbbbb...: 5
  By Rule:
    rule 0: 2
    rule 1: 3
  By Outbound-Only:
    bbbbbbbbcccccccc...: 1

Recent Drops (last 5):
  2026-01-15T10:30:45Z  peer=aaaaaaaa...  proto=TCP  port=22
  2026-01-15T10:31:12Z  peer=bbbbbbbb...  proto=TCP  port=443
```

## Examples

### Basic Server Access

```toml
version = 1
default = "deny"

[peers]
web = "ed25519:AAAA..."
db  = "ed25519:BBBB..."
app = "ed25519:CCCC..."

[[rule]]
from = "app"
to   = "web"
ports = ["tcp/80", "tcp/443"]

[[rule]]
from = "app"
to   = "db"
ports = ["tcp/5432"]
```

### Tag-Based Access

```toml
version = 1
default = "deny"

[peers]
alice = "ed25519:AAAA..."
bob   = "ed25519:BBBB..."
carol = "ed25519:CCCC..."
dave  = "ed25519:DDDD..."

[tags]
admins = ["alice", "bob"]
servers = ["carol", "dave"]

[[rule]]
from = "tag:admins"
to   = "tag:servers"
ports = ["tcp/22", "tcp/443"]
```

### Outbound-Only Node

```toml
version = 1
default = "deny"

[peers]
self = "ed25519:AAAA..."   # This node
api  = "ed25519:BBBB..."

[[rule]]
from = "self"
to   = "api"
ports = ["tcp/443"]

[outbound_only]
peers = ["self"]    # This node cannot receive inbound connections
```

### Allow All (with Explicit Deny)

```toml
version = 1
default = "allow"

[peers]
alice = "ed25519:AAAA..."
bob   = "ed25519:BBBB..."

[[rule]]
from = "bob"
to   = "alice"
ports = ["tcp/22"]
# bob can reach alice on 22, but alice cannot reach bob (no rule)
# All other traffic allowed by default
```

## Failure Modes

| Scenario | Behavior |
|----------|----------|
| No local policy file | Defer to network policy (allow if network allows) |
| Local policy file missing | Same as above |
| Local policy file unparseable | Daemon refuses to start (fail closed) |
| Local policy file group/world-writable | Daemon refuses to start |
| Local policy invalid (unknown peer, bad port) | Daemon refuses to start |
| Network policy unavailable | Local policy only (if present) |
| Network policy forged signature | Ignored, current policy kept, logged |
| Network policy unpinned signer | Ignored, current policy kept, logged |
| Network policy version <= stored | Ignored as rollback, current policy kept, logged |
| Network policy truncated/invalid | Ignored, current policy kept, logged |
| Both policies deny | Packet dropped, drop counter incremented |
| Policy reload removes a rule | Existing flows re-checked; revoked connections dropped |
| Coordinator sends lower version | Refused by peer (rollback protection) |
| Coordinator sends forged envelope | Refused by peer (signature/pinned key check) |

## Testing ACL Policies

Use `veld policy check` and `veld policy test` to verify policy logic before deploying.

## Performance

- Policy decision (`Decide`) is O(rules) — fast enough for per-flow decisions
- Flow table tracks established connections for zero-cost reply forwarding
- Benchmarks: ~50ns per decision with 50-rule policy
- Packet-path overhead: negligible vs. no-policy baseline

## Migration from v1

Policy version is an integer that only increases. When upgrading:
1. Increment `version`
2. Update rules as needed
3. Reload via SIGHUP or file change — no daemon restart required