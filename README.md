# Shadow Tunnel

A Candy-Spoof tunnel node — the Rust tunnel core, a one-shot installer, a
`candyctl` CLI, and a bilingual (EN/FA) web panel with a built-in **tunnel
doctor** — bundled so it builds and runs from this one repository.

> Linux + systemd server, root required. The tunnel uses raw sockets
> (`CAP_NET_RAW`) and authenticates every packet with a shared key.

## What's inside

| Path | What it is |
|---|---|
| `install.sh` | installer + runtime layer (builds the core, writes config/units, installs `candyctl` and the web panel) |
| `core/` | the Rust tunnel core (client/server binaries) — built automatically |
| `PANEL.md` | full documentation for the web panel, `candyctl`, config fields, API, and troubleshooting |

## Install

**One-liner** (fetches and runs the installer, which pulls this repo's core and builds it):

```bash
curl -fsSL https://raw.githubusercontent.com/primeshock/shadow-tunnel/master/install.sh | sudo bash
```

**Or clone first** (recommended if you want to read the script, or to build fully offline from the bundled `core/`):

```bash
git clone https://github.com/primeshock/shadow-tunnel.git
cd shadow-tunnel
sudo ./install.sh
```

Both are interactive — pick the role (**client** or **server**) and follow the
prompts (the piped form reads your answers from the terminal). When cloned, the
installer builds from the bundled `core/` with no extra network fetch.

For an unattended install:

```bash
curl -fsSL https://raw.githubusercontent.com/primeshock/shadow-tunnel/master/install.sh \
  | sudo CANDY_NONINTERACTIVE=1 CANDY_ROLE=server CANDY_REAL_IP=203.0.113.1 bash
```

> It runs as root and installs a Rust toolchain + packages on first run. Review
> [`install.sh`](install.sh) before piping it to `sudo bash` if you prefer.

When it finishes it prints the pre-shared key, a `candyspoof://` setup link for
the other side, and the web-panel URL + password.

## Use it

**`candyshadow`** — one command opens an interactive menu for everything:
manage tunnels (list/active state, per-field config edit, start/stop/restart/
delete), open the web panel, **update**, **backup**, health, logs, the
**Diagnose** tunnel-doctor, and panel settings (password/watchdog/bind/port/TLS).

```bash
sudo candyshadow
```

Or drive it directly with `candyctl`:

```bash
candyctl status          # services, config (key redacted)
candyctl check           # validate the config against the binary
candyctl diagnose        # tunnel doctor (add --link <peer link> for a 2-sided check)
candyctl test            # end-to-end tunnel test
candyctl logs -f         # follow the logs
candyctl backup          # tar.gz of /etc/candy-spoof (config + keys)
candyctl update          # rebuild + reinstall the latest, keeping your config
candyctl panel info      # print the panel URL
```

### Updating without losing your tunnels

`candyctl update` (or re-running the installer) **keeps `/etc/candy-spoof`** —
your config, keys, panel password and extra tunnels are preserved; only the
binary, CLI and panel are rebuilt. It makes a backup first. To update by hand:

```bash
sudo candyctl update            # recommended
# or, equivalently, re-run the installer (answer "y" to "keep configuration")
curl -fsSL https://raw.githubusercontent.com/primeshock/shadow-tunnel/master/install.sh | sudo bash
```

Reach the panel (loopback by default) over SSH:

```bash
ssh -L 7777:127.0.0.1:7777 root@<your-server>
# open http://127.0.0.1:7777
```

## Setting up both ends

1. Install on the **server**, copy the `candyspoof://` link it prints.
2. Install on the **client**; paste that link (installer prompt, or the panel's
   **Tunnels → Import link**) to pre-fill every matching field.
3. If the tunnel doesn't come up, open the panel's **Diagnose** tab and paste the
   other side's link — it checks the whole path and names the exact setting that
   is wrong (ports, ICMP id, key, spoofed-IP pairing, `rp_filter`, interface…).

## Transport modes

Each tunnel picks a `transport` (installer prompt, or the panel's Tunnels → Edit):

- **`spoof`** (default) — UDP data + ICMP control over raw sockets with a forged
  source IP (needs `CAP_NET_RAW`; Linux only). The original behaviour.
- **`tcp`** — an ordinary, **non-spoofed** kernel TCP connection between the two
  real IPs. No raw sockets or spoofing; use it for reliable server-to-server
  tunneling, or where raw/spoofed packets are filtered. The session is
  authenticated with the pre-shared key; `spoofed_ip`/`icmp_id`/`interface` are
  ignored. Both ends must use the same `transport`.

See **[PANEL.md](PANEL.md)** for the complete reference.

## Build from a different source

To build a specific upstream ref instead of the bundled `core/`:

```bash
sudo CANDY_REF=<commit> ./install.sh                 # clone + build a ref
sudo CANDY_SRC_DIR=/path/to/checkout ./install.sh    # build a local checkout
```
