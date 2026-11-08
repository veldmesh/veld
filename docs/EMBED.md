// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
# Embeddable Veld Mesh Node

The `pkg/veldnet` package provides an embeddable Go library that allows any Go program to join a Veld mesh network as a full peer. This enables applications like bot gateways, sidecars, or microservices to securely communicate with other mesh participants without running a separate daemon process.

## Features

- **Zero-config identity**: Automatically generates and persists an Ed25519/X25519 identity keypair (0600 permissions)
- **Coordinator integration**: Registers with a Veld coordinator using an enrollment token
- **TCP over mesh**: `DialContext` establishes TCP connections to other peers via their VPN addresses
- **Userspace networking**: Runs entirely in userspace (no root, no TUN device, no OS routes)
- **Outbound-only mode**: Optional ACL policy to prevent inbound connections
- **Token security**: Accepts tokens from `io.Reader` (stdin, files, secret managers) — never logged

## Quick Start

```go
import (
    "context"
    "net/http"
    "github.com/veldmesh/veld/pkg/veldnet"
)

func main() {
    ctx := context.Background()

    node, err := veldnet.New(veldnet.Options{
        IdentityPath: "/path/to/identity.json",  // created if missing
        CoordAddr:    "coord.example.com:50051",
        Token:        "enrollment-token",         // or use TokenReader
        NodeName:     "my-gateway",
        Userspace:    true,
    })
    if err != nil {
        log.Fatal(err)
    }

    if err := node.Start(ctx); err != nil {
        log.Fatal(err)
    }
    defer node.Close()

    // Use with http.Client
    client := &http.Client{
        Transport: &http.Transport{
            DialContext: node.DialContext,
        },
    }

    resp, err := client.Get("http://10.100.0.5:8080/health")
    // ...
}
```

## API Reference

### `New(Options) (*Node, error)`

Creates a new embeddable node. The identity is loaded from `IdentityPath` or generated and saved with 0600 permissions.

**Options:**
| Field | Required | Description |
|-------|----------|-------------|
| `IdentityPath` | Yes | Path to identity file (JSON). Created with 0600 if missing. |
| `CoordAddr` | Yes | Coordinator gRPC address (e.g., `coord.example.com:50051`). |
| `CoordTLSInsecure` | No | If true, disables TLS for the coordinator connection (plaintext; testing only). Default: false (uses system CA pool). |
| `Token` | Yes* | Enrollment token. Mutually exclusive with `TokenReader`. |
| `TokenReader` | Yes* | Reads token from an `io.Reader` (stdin, file, secret manager). Token is read once at `Start` time, never logged. |
| `NodeName` | No | Peer name to register with coordinator (default: hostname). |
| `OutboundOnly` | No | If true, sets local ACL policy `outbound_only = ["self"]`, causing the node's own dataplane to drop inbound connections from other peers. |
| `PolicyPath` | No | Path to a local ACL policy file (TOML). If empty, defaults to `policy.toml` next to the identity file. If the file does not exist, no local policy is enforced (defer to network). |
| `Userspace` | Yes | Must be `true` for embeddable package (userspace netstack). |
| `STUNServer` | No | STUN server for NAT traversal (e.g., `stun.l.google.com:19302`). |
| `RelayAddr` | No | Relay server address for fallback (e.g., `relay.example.com:7878`). |
| `RelayX25519` | No | Base64-encoded 32-byte relay static public key (required if `RelayAddr` set). |
| `SubnetRoutes` | No | CIDR prefixes this node advertises (e.g., `["192.168.1.0/24"]`). |
| `NetworkID` | No | 32-char hex network ID. If empty, inferred from token. |
| `ListenAddr` | No | UDP listen address (default: `0.0.0.0:51820`). |
| `MTU` | No | TUN MTU (default: 1420). |
| `DialTimeout` | No | Timeout for `DialContext` connections (default: 10s). |

*Either `Token` or `TokenReader` must be provided.

### `(*Node).Start(ctx context.Context) error`

Connects to the coordinator, registers the node, and begins processing. Blocks until the node has a VPN address or `ctx` is cancelled.

### `(*Node).VPNAddr() netip.Addr`

Returns the VPN address assigned by the coordinator. Zero value until `Start` completes.

### `(*Node).PeerID() string`

Returns the peer ID (hex-encoded Ed25519 public key) assigned by the coordinator. Empty until `Start` completes.

### `(*Node).DialContext(ctx context.Context, network, addr string) (net.Conn, error)`

Establishes a TCP connection to a peer in the mesh.

- `network` must be `"tcp"`, `"tcp4"`, or `"tcp6"`.
- `addr` is the peer's VPN address and port (e.g., `"10.100.0.5:8080"`).
- The connection is routed through the mesh VPN using Noise IK encryption.
- Implements `net.Conn` for use with `http.Transport`, `database/sql`, etc.

### `(*Node).Close() error`

Stops the node and sends a Leave message to the coordinator. Idempotent.

## Example: HTTP Client

See `examples/http-client/main.go` for a complete example that:
1. Joins a mesh with an enrollment token
2. Creates an `http.Client` with `DialContext`
3. Makes an HTTP request to a peer's VPN address

```bash
go run ./examples/http-client \
  -identity /tmp/identity.json \
  -coord coord.example.com:50051 \
  -token - \
  -target http://10.100.0.5:8080/health
```

## Architecture

The embeddable node reuses the internal daemon components:
- **Peer table**: Tracks mesh peers (VPN address, endpoints, keys)
- **Handshake manager**: Performs Noise IK handshakes with peers
- **Dataplane**: Encrypts/decrypts packets (UDP-based)
- **Coord client**: Registers with coordinator, receives peer events

Unlike the standalone daemon, the embeddable node:
- Runs in userspace mode (no TUN device)
- Does not install OS routes
- Does not run mDNS, DNS, or IPC servers
- Exposes only `DialContext` for application-level connections

`DialContext` uses the gVisor netstack's `DialContext` method, so all connections go through the normal dispatcher, Noise sessions, source check, and ACLs — no custom protocol.

## Security

- **Identity**: Ed25519 keypair stored at `IdentityPath` (0600). Never logged.
- **Token**: Read from `Token` or `TokenReader` once at startup. Never logged.
- **Transport**: Noise IK handshake with forward secrecy. All mesh traffic encrypted.
- **TOFU**: Trust-on-first-use fingerprint pinning prevents key substitution.
- **OutboundOnly**: When enabled, the node's own dataplane drops inbound connections from other peers via the local ACL policy `outbound_only = ["self"]`.
- **TLS**: Coordinator connection uses verified TLS with the system CA pool by default. `CoordTLSInsecure` disables TLS entirely (plaintext; testing only).

### Default ACL Behavior

When no local policy file exists and `OutboundOnly` is not enabled, the embeddable node **allows all traffic** (no filtering). This matches the pre-ACL behavior and the standalone daemon's behavior.

| Scenario | Behavior |
|----------|----------|
| No `policy.toml`, no `OutboundOnly` | Allow all (no filtering) |
| No `policy.toml`, `OutboundOnly=true` | Drop inbound connections; allow outbound |
| `policy.toml` present | Local policy enforced (both local and network must allow) |

To enforce a custom policy, place a `policy.toml` file next to the identity file, or specify `PolicyPath` in options. See [ACL.md](ACL.md) for policy syntax.

## Testing

The package includes integration tests that spin up an in-process coordinator, a normal daemon, and an embeddable node:

```bash
go test -v ./pkg/veldnet/...
```

Tests verify:
- Embeddable node registers and appears as a peer
- `DialContext` initiates handshakes
- `Close` sends Leave and deregisters
- Concurrent operations (race detector)
- TokenReader support
- Identity generation and persistence
- OutboundOnly option
- Custom PolicyPath with deny-all policy
- PolicyPath and OutboundOnly conflict

## Limitations

- **No inbound listeners**: The embeddable node only initiates connections via `DialContext`. To accept inbound connections, run a normal daemon or implement a custom listener using the internal session API.
- **No subnet routing**: Subnet route advertisement (`SubnetRoutes`) is supported but OS routes are not installed in userspace mode.
- **No mDNS/DNS**: LAN discovery and DNS stub resolver are disabled.
- **Single-threaded packet processing**: The read loop runs in a single goroutine. High-throughput applications may need connection pooling.

## Migration from CLI

If you currently use `veld up` via shell exec, replace with:

```go
// Before: exec.Command("veld", "up")
// After:
node, _ := veldnet.New(veldnet.Options{
    IdentityPath: "/etc/veld/identity.json",
    CoordAddr:    "coord.example.com:50051",
    Token:        os.Getenv("VELD_TOKEN"),
})
node.Start(ctx)
defer node.Close()
```

This gives you direct control over lifecycle, errors, and connection handling.