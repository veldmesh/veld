# Userspace Mode

Veld can run entirely in userspace without requiring root privileges, a TUN device,
or OS-level network configuration. This is achieved using the gVisor network stack
(`golang.zx2c4.com/wireguard/tun/netstack`), which implements a complete TCP/IP stack
in Go.

## When to Use

Userspace mode is designed for scenarios where:
- Running in containers without `CAP_NET_ADMIN`
- Running as a non-root user
- Running on platforms where TUN devices are unavailable
- Agent peers (bot gateways) that join the mesh as their own host
- Development and testing environments

## Configuration

Enable userspace mode by adding `userspace = true` to the `[node]` section of your config:

```toml
[node]
identity_path = "~/.config/veld/identity.json"
vpn_addr = "10.100.0.1/24"
listen_addr = "0.0.0.0:51820"
network_id = "abcdef1234567890abcdef1234567890"
userspace = true
```

Or pass it programmatically when constructing a daemon.

## How It Works

In userspace mode:
1. No TUN device is created (`/dev/net/tun`, `utun`, or Wintun)
2. No IP addresses are assigned to OS interfaces
3. No OS routes are installed
4. No IP forwarding is enabled
5. No commercial VPN coexistence checks run
6. No mDNS LAN discovery runs (requires a real interface)

Instead, the gVisor netstack creates a virtual network interface inside the process.
The netstack is assigned the configured VPN address and a default route for the mesh
subnet. All IP packets to/from the mesh flow through this userspace stack.

Applications within the same process can use the netstack's `DialContext`, `ListenTCP`,
and `ListenUDP` methods to communicate over the VPN using the VPN address.

## Limitations

### No Subnet Routes

In userspace mode, subnet routes (both local and peer-advertised) are **not** installed
in the OS routing table. This means:

- Other processes on the host cannot reach mesh subnets
- The mesh cannot reach other processes on the host
- Peer subnet routes are ignored

If you need subnet routing, run with a kernel TUN (default mode) and appropriate
privileges.

### No OS-Level Visibility

- `ip route`, `netstat`, `ss`, `route print` will not show the VPN interface
- Firewall rules cannot match on the VPN interface
- Traffic captures (tcpdump, Wireshark) cannot see the VPN interface

### No mDNS LAN Discovery

mDNS requires binding to a real multicast-capable interface. In userspace mode,
the netstack does not expose a real interface, so mDNS LAN discovery is disabled.

### Platform Support

Userspace mode builds on all platforms supported by gVisor's netstack:
- linux/amd64
- linux/arm64
- darwin/arm64
- windows/amd64
- linux/mips (and other Go-supported architectures)

No CGO is required. The netstack is pure Go.

### Performance

The gVisor netstack is optimized for correctness and compatibility, not raw throughput.
For high-throughput scenarios, kernel TUN mode is recommended.

## Programmatic Access

When running in userspace mode, the daemon's TUN device implements additional methods
for direct netstack access:

```go
// From github.com/veldmesh/veld/internal/tun
type NetstackTUN interface {
    // Standard TUN interface
    Read(p []byte) (int, error)
    Write(p []byte) (int, error)
    Close() error
    Name() string
    Addr() netip.Prefix
    MTU() int

    // Netstack-specific methods
    DialContext(ctx context.Context, network, address string) (net.Conn, error)
    Dial(network, address string) (net.Conn, error)
    ListenTCP(addr *net.TCPAddr) (net.Listener, error)
    ListenTCPAddrPort(addr netip.AddrPort) (net.Listener, error)
    ListenUDP(laddr *net.UDPAddr) (net.PacketConn, error)
    ListenUDPAddrPort(laddr netip.AddrPort) (net.PacketConn, error)
}
```

Example: Starting a TCP server on the VPN address:

```go
tunDev := daemon.TUN() // returns tun.TUN
if ns, ok := tunDev.(*tun.NetstackTUN); ok {
    listener, err := ns.ListenTCPAddrPort(netip.AddrPortFrom(tunDev.Addr().Addr(), 8080))
    if err != nil {
        log.Fatal(err)
    }
    for {
        conn, err := listener.Accept()
        if err != nil {
            log.Printf("accept: %v", err)
            continue
        }
        go handleConn(conn)
    }
}
```

## Building

Userspace mode requires the `userspace` build tag:

```bash
go build -tags userspace ./cmd/veld
go build -tags userspace ./cmd/veld-daemon
```

The netstack dependency (`golang.zx2c4.com/wireguard/tun/netstack`) is pinned to a
version at least two weeks old (as of this writing, the wireguard-go module
v0.0.0-20231211153847-12269c276173).

## Testing

Run the userspace tests with:

```bash
go test -tags userspace ./internal/tun -run TestNetstackTUN
```

This runs:
- TCP echo between two in-process nodes over the userspace TUN
- UDP echo between two in-process nodes over the userspace TUN
- MTU-sized packets (including fragmentation) over the userspace TUN
- Verification that dataplane hooks see the same packets as with kernel TUN

## Security Considerations

Userspace mode does not change the threat model:
- All mesh traffic is still encrypted with WireGuard-style Noise IK
- Peer authentication is unchanged (Ed25519 identities, TOFU pinning)
- The netstack runs in the same process as the daemon; compromise of the daemon
  implies compromise of the netstack

However, because no kernel interfaces are created, the attack surface is reduced:
- No TUN device to exploit
- No route manipulation in the kernel
- No interaction with OS networking stack