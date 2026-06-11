# Veld

A decentralized peer-to-peer mesh VPN. Connect your devices privately, anywhere, without trusting a middleman.

Unlike Tailscale, the coordination server never sees, routes, or authenticates your traffic. After an initial handshake, all communication goes directly between your machines — encrypted end-to-end. The coordination server is a thin public-key directory you can self-host or use as a managed service.

---

## How it's different

| | Tailscale | Veld |
|---|---|---|
| Traffic routing | Via relay if direct fails | Always P2P; relay is a volunteer mesh peer |
| Coord server sees traffic | Yes (DERP relay) | Never |
| Open source | Client only | Daemon + CE coord server (BSL) |
| Pricing model | Per user | Per network |
| Runs without a server | No | Yes (static config or LAN mDNS) |
| IoT / OpenWrt | Yes | Yes (MIPS + ARMv6 builds) |

---

## Features

- **Custom Noise IK handshake** — Ed25519 identity keys, X25519 session keys, ChaCha20-Poly1305 encryption, forward secrecy
- **No kernel modules** — userspace TUN via `wireguard/tun`; no WireGuard daemon
- **NAT traversal** — UDP hole-punching via ICE; covers ~85–90% of home/office networks
- **Three operating modes** — static config (no server), LAN mDNS discovery, full coord server
- **Name-based routing** — `ping server1.veld` via local DNS stub
- **Subnet routing** — expose a whole LAN through one Veld node (IoT gateway)
- **TOFU key pinning** — peer fingerprints saved on first connect; mismatches blocked
- **IoT friendly** — builds for `linux/mips`, `linux/arm/v6`, `linux/arm/v7`, `linux/arm64`, OpenWrt

---

## Quick start — managed service

Install and log in with one command. See [veldmesh.io](https://veldmesh.io) for setup instructions.

---

## Quick start — self-hosted coordination server

```sh
# Run the coordination server (Docker)
docker run -p 50051:50051 ghcr.io/veldmesh/veld-coord

# On each machine
veld login --coord your-server:50051
veld up --network mynet
```

Or without Docker:
```sh
./veld-coord --listen :50051 --db ./peers.db
```

---

## Quick start — no server (static config)

Works when both machines have known IPs (VPS, port-forwarded router).

```toml
# config.toml on machine A
listen_addr = "0.0.0.0:51820"
vpn_ip      = "10.0.0.1/24"
name        = "machine-a"

[[peers]]
name     = "machine-b"
pubkey   = "base64-ed25519-pubkey-of-b"
endpoint = "1.2.3.4:51820"
vpn_ip   = "10.0.0.2"
```

```sh
veld-daemon --config config.toml
ping 10.0.0.2   # or: ping machine-b.veld
```

---

## Architecture overview

```
┌─────────────────────────────────────────────────────┐
│  Your machine                                        │
│  ┌──────────────┐    UDP (encrypted)                 │
│  │   kernel     │◄──────────────────────────────►   │
│  │  (routing)   │                          Peer B    │
│  └──────┬───────┘                                    │
│         │ TUN interface (10.0.0.1)                   │
│  ┌──────▼───────────────────────────────────────┐   │
│  │  veld-daemon                            │   │
│  │  ┌──────────┐ ┌──────────┐ ┌─────────────┐  │   │
│  │  │ dataplane│ │ session  │ │ nat/ICE     │  │   │
│  │  │dispatcher│ │ (Noise)  │ │ traversal   │  │   │
│  │  └──────────┘ └──────────┘ └──────┬──────┘  │   │
│  └─────────────────────────────────┬─┘          │   │
│                                    │ gRPC (TLS) │   │
└────────────────────────────────────┼────────────┘   │
                                     ▼
                            ┌─────────────────┐
                            │ veld-coord  │  ← thin: pubkeys +
                            │ (coord server)   │    endpoints only
                            └─────────────────┘
                                     ▲
                            optional dashboard
                            (self-host or managed)
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full design: crypto stack, handshake format, packet format, extension point interfaces, and NAT traversal flow.

---

## Building from source

**Prerequisites:** Go 1.22+, `protoc`, `protoc-gen-go`, `protoc-gen-go-grpc`

```sh
make proto      # regenerate gen/ from proto/
make build      # build all binaries for host OS
make build-all  # cross-compile for all targets
make test
make docker     # build coord server Docker image
```

Cross-compile targets: `linux/amd64`, `linux/arm64`, `linux/arm/v7`, `linux/arm/v6`, `linux/mips`, `linux/mipsle`, `darwin/amd64`, `darwin/arm64`, `windows/amd64`.

---

## Repository layout

```
core/
├── cmd/
│   ├── veld-daemon/   # daemon entrypoint
│   ├── veld-coord/    # CE coordination server entrypoint
│   └── veld/          # CLI control tool
├── internal/               # daemon internals (crypto, tun, session, nat, …)
├── coord/
│   ├── core/               # shared interfaces (PlanEnforcer, AccountStore, …)
│   ├── ce/                 # Community Edition (free tier) implementations
│   └── server/             # gRPC server, bbolt registry, signal bus
├── proto/                  # source .proto files
├── gen/                    # committed generated protobuf stubs
├── web/                    # Next.js marketing site
└── docs/                   # architecture, development, and protocol docs
```

---

## Coordination server: Community Edition

The CE coordination server (`veld-coord`) is fully self-hostable. All tier-enforcement logic lives behind the interfaces in `coord/core/` — the CE implementations are the complete implementations in this repo. There are no locked features or hidden toggles.

---

## Contributing

Contributions to the daemon, CLI, CE coord server, and docs are welcome. Please read [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) before opening a PR — it covers the crypto invariants, extension point rules, and testing approach.

---

## License

The **daemon, CLI, and web frontend** (`cmd/`, `internal/`, `web/`) are licensed under the **MIT License**.

The **coordination server** (`coord/`) is licensed under the **Business Source License 1.1 (BSL-1.1)**. Source code is publicly available. You may self-host it for personal or internal use. You may not offer it as a competing managed network service. The license converts to Apache 2.0 four years after each version's release date.

See [`LICENSE`](LICENSE) and [`coord/LICENSE`](coord/LICENSE) for full terms.
