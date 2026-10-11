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

```bash
candyctl status          # services, config (key redacted)
candyctl check           # validate the config against the binary
candyctl test            # end-to-end tunnel test
candyctl logs -f         # follow the logs
candyctl panel info      # print the panel URL
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

See **[PANEL.md](PANEL.md)** for the complete reference.

## Build from a different source

To build a specific upstream ref instead of the bundled `core/`:

```bash
sudo CANDY_REF=<commit> ./install.sh                 # clone + build a ref
sudo CANDY_SRC_DIR=/path/to/checkout ./install.sh    # build a local checkout
```
