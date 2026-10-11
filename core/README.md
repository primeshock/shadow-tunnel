# Candy-Spoof

> **⚠️ EDUCATIONAL PURPOSES ONLY**
> This software is provided for educational, research, and authorized security testing purposes only. Users are responsible for ensuring compliance with all applicable laws and regulations in their jurisdiction. Unauthorized use of IP spoofing may be illegal and unethical. The authors assume no liability for misuse of this software.

**Candy-Spoof** is a bidirectional IP spoofing tunnel designed for use in heavily censored networks. Both the client and server forge their source IP addresses, making traffic analysis and blocking significantly harder.

## Features

| Feature | Description |
|---------|-------------|
| Mutual IP spoofing | Both client and server use fake source addresses |
| Spoofed-IP pools | Rotate source addresses per session for better evasion |
| Data channel | Spoofed UDP with configurable port |
| Control channel | Spoofed ICMP Echo Request/Reply (looks like ping traffic) |
| Reliable delivery | Selective Repeat ARQ with per-packet retransmission |
| Congestion control | TCP-like AIMD: slow-start, congestion avoidance, fast retransmit, RTT estimation (RFC 6298) |
| SOCKS5 proxy | Local proxy on port 1080 – route any app through the tunnel |
| Whitelist validation | Packets from unknown IPs are silently dropped |
| Multiple tunnels | Configurable number of parallel independent tunnels |
| Pre-shared key | Optional PSK for packet authentication |

## Prerequisites

- **Operating System**: Linux (requires raw socket support)
- **Permissions**: `CAP_NET_RAW` capability or root access
- **Compiler**: Rust 1.70 or later (edition 2021)

## Building from Source

Build the project using Cargo:

```bash
cargo build --release
```

The compiled binaries will be available at:
- Client: `target/release/client`
- Server: `target/release/server`

## Usage

### Running the Server

Start the server with the configuration file:

```bash
sudo ./target/release/server --config config/server.toml
```

Or during development:

```bash
sudo cargo run --bin server -- --config config/server.toml
```

### Running the Client

Start the client with the configuration file:

```bash
sudo ./target/release/client --config config/client.toml
```

After starting the client, configure your applications (browser, curl, etc.) to use the SOCKS5 proxy at `127.0.0.1:1080`.

## Configuration

| Field | Where | Description |
|-------|-------|-------------|
| `real_ip` | both | Your machine's actual IPv4 address |
| `peer_real_ip` | both | The peer's actual IPv4 address |
| `spoofed_ip` | both | The fake source IP for outgoing packets |
| `peer_spoofed_ip` | both | The fake source IP the peer uses |
| `spoofed_ip_pool` | both | Optional pool of source IPs to rotate |
| `data_port` | both | UDP port for the data channel (must match) |
| `icmp_id` | both | ICMP echo identifier (must match) |
| `pre_shared_key` | both | Secret for packet authentication (must match) |
| `allowed_peers` | both | Extra IPs to whitelist |
| `interface` | both | Network interface (e.g. `eth0`) |
| `socks5_port` | client | Local SOCKS5 proxy port (default `1080`) |
| `tunnel_count` | both | Number of parallel tunnels (default `4`) |
| `mtu` | both | Max payload bytes per packet (default `1380`) |
| `initial_cwnd` | both | Initial congestion window in packets (default `10`) |

**Note**: Both client and server configurations must match on critical fields like `data_port`, `icmp_id`, and `pre_shared_key` for the tunnel to work properly.

Refer to `config/client.toml` and `config/server.toml` for complete configuration examples.

## How It Works

```
[Application]
     │  TCP (SOCKS5 CONNECT)
     ▼
[SOCKS5 Proxy – 127.0.0.1:1080]
     │  Candy-Spoof data (ARQ + CC)
     ▼
[Raw UDP – src=spoofed_client_ip  dst=real_server_ip]
─── censored network ──────────────────────────────────
[Tunnel Manager – server demultiplexes by tunnel_id]
     │  TCP
     ▼
[Target Server]
     │
     ▼
[Raw UDP – src=spoofed_server_ip  dst=real_client_ip]
─── censored network ──────────────────────────────────
[Application receives response]
```

**Control Channel**: Control packets (SYN, ACK, NACK, Heartbeat) use ICMP Echo Request/Reply messages to blend with ordinary ping traffic, making detection more difficult.

## ARQ & Congestion Control

- **Selective Repeat ARQ** – only missing packets retransmitted; out-of-order
  packets buffered until gap is filled.
- **Slow-start** – window grows exponentially from `initial_cwnd` until `ssthresh`.
- **Congestion avoidance** – additive increase of ~+1 per RTT.
- **Fast retransmit** – triggered on 3 duplicate ACKs; window halved.
- **Timeout** – window reset to 1, exponential RTO back-off (up to 60 s).
- **RTT estimation** – Jacobson/Karels algorithm (RFC 6298).

## Security Considerations

- **Minimize privileges**: Use `CAP_NET_RAW` capability instead of running as full root when possible
- **Protect credentials**: Keep `pre_shared_key` secret and rotate it regularly
- **Choose spoofed IPs carefully**: Use globally routable addresses that are not yours; CDN or public DNS addresses help blend traffic patterns
- **Be aware of limitations**: Ingress filtering (BCP 38) on upstream routers may block packets with spoofed source addresses
- **Legal compliance**: Ensure you have authorization to use this tool in your network environment

## Performance Tips

- Increase `tunnel_count` for higher parallelism on fast links.
- Tune `mtu` to match path MTU (`tracepath` helps).
- Raise `initial_cwnd` (e.g. `30`) on low-latency links to reduce slow-start
  ramp-up time.
- Use a `spoofed_ip_pool` of 3–5 addresses to distribute traffic patterns.

## License

MIT
