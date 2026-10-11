# Candy-Spoof Web Panel

A self-contained web panel, live monitor, and CLI for operating a Candy-Spoof
tunnel node. It is written in the Python **standard library only** (no pip
dependencies), shipped and installed by [`install.sh`](install.sh), and runs as
a hardened systemd service.

The panel does not replace the Rust tunnel binary — it reads the real system
state (systemd, `/proc`, `ss`, journald) and edits the same TOML config the
binary parses, so what you see is what the service actually does.

---

## Contents

- [Architecture](#architecture)
- [Installing & accessing](#installing--accessing)
- [Security model](#security-model)
- [The tabs](#the-tabs)
  - [Overview](#overview)
  - [Tunnels](#tunnels)
  - [Logs](#logs)
  - [Health](#health)
  - [Diagnose — the tunnel doctor](#diagnose--the-tunnel-doctor)
  - [Settings](#settings)
- [Configuration reference](#configuration-reference)
- [`candyctl` command-line](#candyctl-command-line)
- [HTTP API](#http-api)
- [Troubleshooting a tunnel](#troubleshooting-a-tunnel)
- [Internationalisation (EN / FA RTL)](#internationalisation-en--fa-rtl)

---

## Architecture

| Piece | What it is | Runs as |
|---|---|---|
| `candy-spoof-client` / `candy-spoof-server` | the Rust tunnel binary (built from the `Candy-Spoof` repo) | `candy-spoof` user, `CAP_NET_RAW` |
| `candy-panel.py panel` | the web panel (this document) | **root**, hardened by systemd |
| `candy-panel.py monitor` | background sampler that writes metrics/history/events | `candy-spoof` user |
| `candyctl` | the operator CLI | root (via `sudo`) |

The panel, monitor, and CLI are all the same `candy-panel.py` file invoked with
different sub-commands. The panel talks to systemd through `candyctl`/`systemctl`
and reads `/etc/candy-spoof/*.toml`, `/proc`, `ss`, and journald.

A node is exactly one **role** — `client` **or** `server` — chosen at install
time. One config file + one process = one **tunnel instance**. The main instance
is `main`; extra instances created from the panel live in
`/etc/candy-spoof/tunnels/<name>.toml` and run as `candy-spoof-<role>@<name>`.

---

## Installing & accessing

The panel is installed by `install.sh` (answer yes when asked to enable it).
After install, the final report prints the URL and the one-time password.

```bash
sudo ./install.sh                 # interactive; enables the panel by default
candyctl panel info               # print the panel URL any time
```

Defaults: it listens on **`127.0.0.1:7777`** over HTTP. Because it binds to
loopback, reach it from your workstation with an SSH tunnel:

```bash
ssh -L 7777:127.0.0.1:7777 root@<your-server>
# then open http://127.0.0.1:7777
```

Change where it listens (see also the **Settings** tab):

```bash
candyctl panel port 8443
candyctl panel bind 10.0.0.5      # bind a specific address
candyctl panel tls on             # serve HTTPS with a self-signed cert
candyctl panel passwd             # set a new password (prompted)
candyctl panel restart
```

---

## Security model

- **Password**: stored only as a PBKDF2-HMAC-SHA256 hash (200k iterations,
  random salt) in `/etc/candy-spoof/panel.json` (mode `0600`). Minimum 10 chars.
- **Sessions**: an opaque `cs_session` cookie, `HttpOnly`, `SameSite=Strict`,
  `Secure` when TLS is on; 24 h lifetime, 12 h idle timeout. Mutating requests
  carry a CSRF token issued at login.
- **Brute-force**: failed logins are rate-limited per client IP.
- **Loopback by default** + optional TLS; intended to be reached over SSH.
- **Secrets**: the pre-shared key is shown in the UI only after re-entering the
  panel password, and is redacted in `candyctl config` output.

> The panel runs as root (it manages systemd units and raw-socket services), so
> treat access to it as root access. Keep it on loopback + SSH, or behind TLS.

---

## The tabs

### Overview

At-a-glance health of the node: CPU / memory / disk / load sparklines (from the
monitor service) and a card per tunnel showing state, uptime, CPU, RAM, live
connection count, RX/TX throughput, tunnel count, last handshake, and a 5-minute
log tally (info / warn / error).

If the monitor service is not running, a banner says so and the cards degrade
gracefully instead of blanking.

### Tunnels

Create, edit, start/stop/restart, and delete tunnel instances.

- **+ Create tunnel** — add a second (or third…) tunnel instance alongside `main`.
- **Import link** — paste a `candyspoof://…` setup link from the other side to
  pre-fill every matching field (see [Diagnose](#diagnose--the-tunnel-doctor)).
- **Edit** — the full config form (addresses, pools, interface, ports, ICMP id,
  MTU, CWND, the robustness knobs, and the pre-shared key). Saving is
  **validated, written atomically, parser-checked, restarted, and rolled back
  automatically** if the service does not come back up.
- **Key & link** — reveal the pre-shared key (after re-auth) and copy the setup
  link to hand to the peer.
- **Link test** — run the end-to-end handshake/data test.

### Logs

A live, colourised, level-filterable view of the service journal
(`journalctl` under the hood). Filter by level (debug/info/warn/error) and search
text.

### Health

A quick environment checklist: binary present, template unit installed,
`CAP_NET_RAW` granted, monitor service active, `rp_filter` sanity, per-instance
required fields, interface existence, SOCKS5 listening (client), and a reminder
that the pre-shared key authenticates every packet.

### Diagnose — the tunnel doctor

> **This is the tab to open when a tunnel "just won't come up."** It walks the
> whole path a tunnel depends on and names the **specific config field** at
> fault, with a concrete fix — not just a log dump.

**Local checks** (each finding carries the offending field + a `→ fix`):

1. **Parser acceptance** — runs the binary's own `--check-config`; if the file
   is rejected, the offending field is extracted from the error.
2. **Self-consistency** — `real_ip` vs `peer_real_ip` must differ; `spoofed_ip`
   vs `peer_spoofed_ip` must differ; `spoofed_ip` must be in `spoofed_ip_pool`
   when a pool is set.
3. **Interface** — the configured NIC exists (raw sockets are bound to it via
   `SO_BINDTODEVICE`) and actually carries `real_ip`.
4. **`rp_filter`** — strict reverse-path filtering (`=1`) silently drops packets
   whose spoofed source isn't routed back via the arrival interface. **This is
   the single most common silent failure.**
5. **Capability & service** — `CAP_NET_RAW` present, service active, and (client)
   SOCKS5 actually listening on `127.0.0.1:<socks5_port>`.
6. **Reachability** — can this host reach `peer_real_ip` at all (ICMP).

**Peer cross-check (the decisive one):** paste the **other** host's
`candyspoof://…` setup link. Because a link is generated *for* the opposite side,
its fields are exactly what this host should have — so the doctor compares them
field by field and tells you precisely what's wrong, e.g.:

```
✕ icmp_id does not match the peer      [icmp_id]
  peer uses 9999, this host has 17185
  → set icmp_id = 9999 to match the peer

✕ pre_shared_key does not match the peer   [pre_shared_key]
  key fingerprints differ (peer df0a… vs here 1b2c…)
  → re-import the peer link, or copy the peer's key exactly
```

Symmetric fields (`data_port`, `icmp_id`, `pre_shared_key`) must match exactly;
the addressing fields are checked against what the peer's link expects. Fields
that already agree produce no noise.

### Settings

Watchdog (periodic restart timer), change panel password, and node info
(role, build commit, panel bind/port/TLS). Sign out.

---

## Configuration reference

All fields live in `/etc/candy-spoof/config.toml` (and
`/etc/candy-spoof/tunnels/<name>.toml` for extra instances). The panel validates
these and the Rust binary enforces them.

| Field | Meaning | Notes |
|---|---|---|
| `real_ip` | this node's real IPv4 | must differ from `peer_real_ip` |
| `peer_real_ip` | the peer's real IPv4 | the tunnel's routing destination |
| `spoofed_ip` | source IP this node forges | must differ from `peer_spoofed_ip` |
| `peer_spoofed_ip` | source IP the peer forges | what we expect on inbound |
| `spoofed_ip_pool` | optional rotation pool | when set, **only** pool addresses are used |
| `allowed_peers` | extra trusted source IPs | list every pool address the peer may use |
| `data_port` | UDP data-channel port | **must match the peer** |
| `icmp_id` | ICMP echo id (control channel) | **must match the peer** (dec or `0x…`) |
| `pre_shared_key` | hex key, ≥ 32 chars | **must match the peer**; authenticates every packet (HMAC-SHA256) |
| `interface` | NIC to bind raw sockets to | bound via `SO_BINDTODEVICE`; must exist |
| `socks5_port` | local SOCKS5 port (client only) | binds `127.0.0.1` |
| `mtu` | max payload bytes per packet | 512–1400 |
| `initial_cwnd` | initial congestion window (packets) | 1–1000 |
| `max_retries` | ARQ retransmits before giving up | 1–100, default 8 |
| `rto_min_ms` | retransmission-timeout floor (ms) | 10–60000, default 200; raise on lossy/high-latency links |
| `tunnel_count` | *parsed but not applied* | each connection already uses its own tunnel; see below |

**Notes on behaviour**

- **Authentication**: every packet carries a keyed HMAC-SHA256 tag derived from
  `pre_shared_key`; packets that fail verification are dropped. Both ends must
  share the identical key and be built from the same version.
- **`max_retries` / `rto_min_ms`**: safe robustness knobs that tune the existing
  ARQ/RTO. Defaults preserve historical behaviour and they do **not** increase
  how many packets are sent in the no-loss case.
- **`tunnel_count`**: has no effect — each SOCKS5 connection already opens its
  own independent tunnel, and per-packet duplication is intentionally not
  implemented. The binary logs a warning if it is set to anything but 1.

---

## `candyctl` command-line

```
candyctl [-t NAME] <command>

  status                  services, watchdog, panel and (redacted) config
  check                   validate the config with the binary (--check-config); exit 1 if rejected
  tunnels                 list tunnels on this host
  start | stop | restart  all tunnels (or one with -t NAME)
  logs [journalctl args]  e.g. candyctl logs -f
  monitor                 live dashboard (CPU/RAM/connections/traffic/events)
  monitor logs [LEVEL]    live colourised logs
  test [--host H --port P --secs N]
                          end-to-end tunnel test: handshake, real data, packet capture
  config                  print the config (pre_shared_key redacted)
  config edit             edit in $EDITOR; validated, applied with automatic rollback
  set key=value ...       change fields, e.g. candyctl set icmp_id=17185 mtu=1300
  token                   print the pre-shared key
  link                    print the setup link for the other side
  watchdog <off|30m|1h|6h|12h|24h>
  restart-sec <1-3600>    crash-recovery delay (RestartSec)
  socks-port <PORT>       (client) change the local SOCKS5 port
  panel [info|passwd|passwd-set|port N|bind IP|tls on|off|start|stop|restart]
```

`candyctl check` is the quickest way to confirm a config will actually be
accepted by the binary before (re)starting the service.

---

## HTTP API

All endpoints are under `/api`, require a valid session, and return JSON.
Mutating requests carry the CSRF token from `/api/session`.

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/session` | current CSRF token (401 if not logged in) |
| GET | `/api/overview` | metrics + per-tunnel state |
| GET | `/api/meta` | role, build, UI defaults |
| GET | `/api/health` | environment checklist |
| GET | `/api/settings` | watchdog / bind / port / tls |
| GET | `/api/tunnels/<name>/logs` | journal rows (filterable) |
| POST | `/api/login` · `/api/logout` | auth |
| POST | `/api/keygen` | generate a hex pre-shared key |
| POST | `/api/tunnels` | create a tunnel |
| PUT | `/api/tunnels/<name>` | edit (validate → write → check → restart → rollback) |
| DELETE | `/api/tunnels/<name>` | delete a non-main tunnel |
| POST | `/api/tunnels/<name>/{start,stop,restart}` | service control |
| POST | `/api/tunnels/<name>/secret` | reveal the key (re-auth) |
| POST | `/api/tunnels/<name>/test` | end-to-end tunnel test |
| POST | `/api/link/parse` | decode a `candyspoof://` link into fields |
| POST | `/api/diagnose` | **tunnel doctor** (optional `{link}` for peer cross-check) |
| POST | `/api/settings/watchdog` · `/api/settings/password` | settings |

---

## Troubleshooting a tunnel

Most setup failures fall into a few buckets — run **Diagnose** first; it checks
all of these and names the field:

1. **Client/server mismatch** — `data_port`, `icmp_id`, or `pre_shared_key`
   differ between the two ends, or the spoofed-IP pairing is crossed. Paste the
   peer's setup link into Diagnose to pinpoint it, or re-import the link so both
   sides are generated from one source.
2. **`rp_filter=1`** — strict reverse-path filtering drops spoofed-source
   packets. Set `net.ipv4.conf.<iface>.rp_filter=2` (loose) on **both** ends and
   persist it.
3. **Wrong/missing `interface`** — raw sockets are bound to it; the service
   won't start if it doesn't exist. Use the device that owns `real_ip`.
4. **Firewall** — inbound `UDP/<data_port>` and ICMP echo from the peer must be
   allowed.
5. **Service "up" but not working** — `candyctl check` confirms the config
   parses; the Logs tab shows `tunnel N established` on success. Process-liveness
   alone is not success.

---

## Internationalisation (EN / FA RTL)

The whole UI is bilingual — English and Persian — with a toggle in the header.
Persian switches the layout to full right-to-left; monospace/technical values
(IPs, ports, keys, config dumps) stay left-to-right for readability.
