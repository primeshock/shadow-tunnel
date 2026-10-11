#!/usr/bin/env bash
# =============================================================================
# Shadow Spoof installer + runtime management layer
#
# Everything below is derived from the repository source at the pinned commit
# (src/config.rs, src/bin/client.rs, src/bin/server.rs, src/raw_socket.rs,
# src/socks5.rs, Cargo.toml):
#
#   binaries      : target/release/client , target/release/server
#   CLI           : --config <path> , --log-level <lvl>   (clap)
#   config        : TOML, flat keys, schema = struct Config in src/config.rs
#   capabilities  : CAP_NET_RAW only (SOCK_RAW sockets); SOCKS5 binds
#                   127.0.0.1:<socks5_port> (client only), no privileged port
#   logging       : env_logger (RUST_LOG honoured, default "info")
#
# Also installs: shadow-spoof-monitor (metrics + log sampler), an optional web panel
# (monitor, create/edit tunnels, tests) and `shadowctl` (see: shadowtun help).
#
# Usage:
#   sudo ./install.sh                       interactive
#   sudo ./install.sh --role client|server
#   sudo SHADOW_NONINTERACTIVE=1 SHADOW_REAL_IP=... ./install.sh --role server
#
# Environment overrides:
#   SHADOW_REF           git ref/commit to build (default: pinned commit below)
#   SHADOW_REPO_URL      git remote
#   SHADOW_SRC_DIR       build from an existing local checkout instead of cloning
#   SHADOW_<FIELD>       preset any prompt value (REAL_IP, SPOOFED_IP, ...)
# =============================================================================
set -Eeuo pipefail
umask 077

readonly SVC_USER=shadow-spoof
readonly ETC_DIR=${SHADOW_ETC_DIR:-/etc/shadow-spoof}
readonly CONF=$ETC_DIR/config.toml
readonly PSK_FILE=$ETC_DIR/psk
readonly ROLE_FILE=$ETC_DIR/role
readonly BUILD_INFO=$ETC_DIR/build-info
readonly STATE_DIR=${SHADOW_STATE_DIR:-/var/lib/shadow-spoof}
readonly SRC_DIR=$STATE_DIR/src
readonly UNIT_DIR=${SHADOW_UNIT_DIR:-/etc/systemd/system}
readonly BIN_DIR=/usr/local/bin
readonly SHADOWCTL=$BIN_DIR/shadowctl
readonly SHADOWTUN=$BIN_DIR/shadowtun
readonly LIB_DIR=${SHADOW_LIB_DIR:-/usr/local/lib/shadow-spoof}
readonly PANEL_PY=$LIB_DIR/shadow-panel.py
readonly PANEL_JSON=$ETC_DIR/panel.json
readonly TUNNELS_DIR=$ETC_DIR/tunnels
readonly DEFAULT_ICMP_ID=17185   # 0x4321 - identical default on client and server
readonly DEFAULT_REF=master
readonly MIN_RUSTC=1.85.0

REPO_URL=${SHADOW_REPO_URL:-https://github.com/primeshock/shadow-tunnel.git}
REPO_REF=${SHADOW_REF:-$DEFAULT_REF}
NONINTERACTIVE=${SHADOW_NONINTERACTIVE:-0}
ROLE=${SHADOW_ROLE:-}
TTY_IN=/dev/stdin
BUILD_REF=unknown
NEW_KEY=0
PSK=
PANEL_ENABLE=1
PANEL_KEEP=0
PANEL_TLS=0
PANEL_PW_SHOWN=
PANEL_CHANGED=0
PY3=(python3 "$PANEL_PY")

# ---------------------------------------------------------------- messaging --
if [[ -t 2 ]]; then c_r=$'\e[31m'; c_g=$'\e[32m'; c_y=$'\e[33m'; c_b=$'\e[36m'; c_0=$'\e[0m'
else c_r=; c_g=; c_y=; c_b=; c_0=; fi
info() { printf '%s[*]%s %s\n' "$c_b" "$c_0" "$*" >&2; }
ok()   { printf '%s[+]%s %s\n' "$c_g" "$c_0" "$*" >&2; }
warn() { printf '%s[!]%s %s\n' "$c_y" "$c_0" "$*" >&2; }
die()  { printf '%s[x]%s %s\n' "$c_r" "$c_0" "$*" >&2; exit 1; }
trap 'die "failed at line $LINENO (exit $?)"' ERR

# --------------------------------------------------------------- validators --
v_ipv4() {
  local o
  [[ ${1-} =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  for o in "${BASH_REMATCH[@]:1}"; do (( 10#$o <= 255 )) || return 1; done
}
v_ipv4_list() { # comma separated, empty allowed
  local item
  [[ -z ${1// /} ]] && return 0
  local IFS=,
  for item in $1; do item=${item// /}; [[ -z $item ]] && continue; v_ipv4 "$item" || return 1; done
}
v_port()       { [[ ${1-} =~ ^[0-9]{1,5}$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 )); }
v_socks_port() { [[ ${1-} =~ ^[0-9]{1,5}$ ]] && (( 10#$1 >= 1024 && 10#$1 <= 65535 )); }
v_u16() {
  if [[ ${1-} =~ ^0[xX][0-9a-fA-F]{1,4}$ ]]; then return 0; fi
  [[ ${1-} =~ ^[0-9]{1,5}$ ]] && (( 10#$1 <= 65535 ))
}
v_tunnels() { [[ ${1-} =~ ^[0-9]{1,3}$ ]] && (( 10#$1 >= 1 && 10#$1 <= 256 )); }
v_mtu()     { [[ ${1-} =~ ^[0-9]{3,4}$ ]] && (( 10#$1 >= 512 && 10#$1 <= 1400 )); }
v_cwnd() {
  [[ ${1-} =~ ^[0-9]{1,4}(\.[0-9]+)?$ ]] || return 1
  awk -v v="$1" 'BEGIN{exit !(v+0 >= 1 && v+0 <= 1000)}'
}
v_iface() {
  [[ ${1-} == auto ]] && return 0
  [[ ${1-} =~ ^[A-Za-z0-9_.:@-]{1,15}$ ]]
}
v_psk() { [[ ${1-} =~ ^[0-9a-fA-F]{32,}$ ]]; }
v_transport() { [[ ${1-} == spoof || ${1-} == tcp ]]; }

norm_u16()  { if [[ $1 =~ ^0[xX] ]]; then printf '%d' "$1"; else printf '%d' "$((10#$1))"; fi; }
norm_float(){ if [[ $1 == *.* ]]; then printf '%s' "$1"; else printf '%s.0' "$((10#$1))"; fi; }
norm_list() { # "a, b,a" -> "a,b"
  local item out="" seen=","
  local IFS=,
  for item in $1; do
    item=${item// /}; [[ -z $item ]] && continue
    [[ $seen == *",$item,"* ]] && continue
    seen+="$item,"; out+="${out:+,}$item"
  done
  printf '%s' "$out"
}
to_toml_list() { # csv -> ["a", "b"]
  local item out="" first=1
  local IFS=,
  for item in $1; do
    [[ -z $item ]] && continue
    if (( first )); then out="\"$item\""; first=0; else out+=", \"$item\""; fi
  done
  printf '[%s]' "$out"
}

# ------------------------------------------------------------------- prompts --
# ask VAR "Label" "default" validator "hint"
# A SHADOW_<VAR> environment variable presets the answer.
ask() {
  local var=$1 label=$2 def=${3-} validator=$4 hint=${5-} preset="SHADOW_${1^^}" val prompt
  if [[ -n ${!preset-} ]]; then
    val=${!preset}
    "$validator" "$val" || die "Invalid $preset='$val' ${hint:+($hint)}"
    printf -v "$var" '%s' "$val"; return 0
  fi
  if [[ $NONINTERACTIVE == 1 ]]; then
    "$validator" "$def" || die "Missing or invalid value: set $preset ${hint:+($hint)}"
    printf -v "$var" '%s' "$def"; return 0
  fi
  while :; do
    if [[ -n $def ]]; then prompt="$label [$def]: "; else prompt="$label: "; fi
    printf '%s' "$prompt" >&2
    IFS= read -r val <"$TTY_IN" || die "input closed"
    val=${val#"${val%%[![:space:]]*}"}; val=${val%"${val##*[![:space:]]}"}
    [[ -z $val ]] && val=$def
    if "$validator" "$val"; then printf -v "$var" '%s' "$val"; return 0; fi
    warn "Invalid value.${hint:+ $hint}"
  done
}

ask_yn() { # ask_yn "Question" default(y|n) -> returns 0 for yes
  local q=$1 def=${2:-y} ans hint="[Y/n]"
  [[ $def == n ]] && hint="[y/N]"
  [[ $NONINTERACTIVE == 1 ]] && { [[ $def == y ]]; return; }
  while :; do
    printf '%s %s ' "$q" "$hint" >&2
    IFS= read -r ans <"$TTY_IN" || die "input closed"
    ans=${ans,,}; [[ -z $ans ]] && ans=$def
    case $ans in y|yes) return 0;; n|no) return 1;; esac
  done
}

# ------------------------------------------------------------ network helpers --
detect_ip() { # source address of the default route
  ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -n1
}
detect_iface() { # interface that owns $1
  ip -4 -o addr show 2>/dev/null | awk -v ip="$1" '{split($4,a,"/"); if (a[1]==ip) {print $2; exit}}'
}
iface_exists() { ip link show dev "$1" >/dev/null 2>&1; }

# ------------------------------------------------------------ existing config --
cfg_get() { # raw scalar value of key from the installed config
  [[ -r $CONF ]] || return 0
  sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" "$CONF" | head -n1 \
    | sed 's/[[:space:]]*#.*$//; s/^"//; s/"$//'
}
cfg_get_list() { cfg_get "$1" | tr -d '[]" '; }

# --------------------------------------------------------------- key handling --
gen_psk() { # 256 bits from the kernel CSPRNG, hex encoded (config.rs: "hex string")
  local k
  k=$(head -c 32 /dev/urandom | od -An -vtx1 | tr -d ' \n')
  [[ ${#k} -eq 64 ]] || die "could not read 32 random bytes from /dev/urandom"
  printf '%s' "$k"
}
key_fingerprint() { printf '%s' "$1" | sha256sum | cut -c1-8; }

read_secret() { # read_secret VAR "Label"
  local var=$1 label=$2 a
  if [[ -n ${SHADOW_PRE_SHARED_KEY-} ]]; then
    v_psk "$SHADOW_PRE_SHARED_KEY" || die "SHADOW_PRE_SHARED_KEY must be hex, >= 32 chars"
    printf -v "$var" '%s' "$SHADOW_PRE_SHARED_KEY"; return 0
  fi
  [[ $NONINTERACTIVE == 1 ]] && die "set SHADOW_PRE_SHARED_KEY (hex, >= 32 chars)"
  while :; do
    printf '%s: ' "$label" >&2
    IFS= read -rs a <"$TTY_IN" || die "input closed"; printf '\n' >&2
    a=${a//[[:space:]]/}
    if v_psk "$a"; then printf -v "$var" '%s' "$a"; return 0; fi
    warn "Key must be a hex string of at least 32 characters (as printed by the client)."
  done
}

# ------------------------------------------------------------------ steps ----
parse_args() {
  while (( $# )); do
    case $1 in
      --role) ROLE=${2-}; shift 2 || die "--role needs a value";;
      --role=*) ROLE=${1#*=}; shift;;
      --non-interactive|-y) NONINTERACTIVE=1; shift;;
      -h|--help) sed -n '2,32p' "${BASH_SOURCE[0]:-$0}" 2>/dev/null | sed 's/^# \{0,1\}//'; exit 0;;
      *) die "unknown argument: $1";;
    esac
  done
  case ${ROLE,,} in ""|client|server) ROLE=${ROLE,,};; *) die "role must be client or server";; esac
}

require_root() {
  if [[ $EUID -ne 0 ]]; then
    command -v sudo >/dev/null && exec sudo -E -- "${BASH_SOURCE[0]:-$0}" "$@"
    die "run as root"
  fi
}
require_env() {
  [[ -d /run/systemd/system ]] || die "systemd is required (not running as PID 1 here)"
  [[ $(uname -s) == Linux ]] || die "Linux only (raw sockets)"
  case $(uname -m) in x86_64|aarch64|arm64) :;; *) warn "untested architecture: $(uname -m)";; esac
  if command -v flock >/dev/null; then
    mkdir -p /run/lock; exec 9>/run/lock/shadow-spoof-install.lock
    flock -n 9 || die "another installer instance is running"
  fi
}
setup_tty() {
  if [[ $NONINTERACTIVE == 1 ]]; then return 0; fi
  if [[ -t 0 ]]; then TTY_IN=/dev/stdin
  elif { : </dev/tty; } 2>/dev/null; then TTY_IN=/dev/tty
  else die "no terminal available; use SHADOW_NONINTERACTIVE=1 with SHADOW_* variables"; fi
}

choose_role() {
  local existing=""
  [[ -f $ROLE_FILE ]] && existing=$(<"$ROLE_FILE")
  if [[ -z $ROLE ]]; then
    if [[ $NONINTERACTIVE == 1 ]]; then ROLE=$existing; [[ -n $ROLE ]] || die "--role is required"
    else
      local sel def=""
      [[ $existing == client ]] && def=1; [[ $existing == server ]] && def=2
      printf '\nShadow Spoof installer\n  1) Client\n  2) Server\n' >&2
      while :; do
        printf 'Select role%s: ' "${def:+ [$def]}" >&2
        IFS= read -r sel <"$TTY_IN" || die "input closed"; sel=${sel:-$def}
        case $sel in 1) ROLE=client; break;; 2) ROLE=server; break;; esac
      done
    fi
  fi
  if [[ -n $existing && $existing != "$ROLE" ]]; then
    die "this host is already installed as '$existing'. Remove it first:
      systemctl disable --now shadow-spoof-$existing.service shadow-spoof-watchdog.timer
      rm -rf $ETC_DIR   (and the unit files in $UNIT_DIR)"
  fi
  info "Role: $ROLE"
}

install_deps() {
  local need=(git curl cc make ip sha256sum od python3)
  local missing=() c
  for c in "${need[@]}"; do command -v "$c" >/dev/null || missing+=("$c"); done
  (( ${#missing[@]} == 0 )) && { info "Build/runtime dependencies present"; return 0; }
  info "Installing dependencies (missing: ${missing[*]})"
  if   command -v apt-get >/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends build-essential git curl ca-certificates iproute2 util-linux coreutils python3 openssl
  elif command -v dnf >/dev/null; then
    dnf install -y gcc make git curl ca-certificates iproute util-linux coreutils python3 openssl
  elif command -v yum >/dev/null; then
    yum install -y gcc make git curl ca-certificates iproute util-linux coreutils python3 openssl
  elif command -v pacman >/dev/null; then
    pacman -Sy --needed --noconfirm base-devel git curl ca-certificates iproute2 util-linux python openssl
  elif command -v zypper >/dev/null; then
    zypper --non-interactive install -y gcc make git curl ca-certificates iproute2 util-linux python3 openssl
  else die "unsupported package manager; install: ${missing[*]}"; fi
}

ensure_user() {
  if ! id -u "$SVC_USER" >/dev/null 2>&1; then
    local nologin; nologin=$(command -v nologin || echo /usr/sbin/nologin)
    useradd --system --no-create-home --home-dir /nonexistent --shell "$nologin" "$SVC_USER"
    ok "Created system user $SVC_USER"
  fi
  install -d -m 0750 -o root -g "$SVC_USER" "$ETC_DIR"
  install -d -m 0755 -o root -g root "$STATE_DIR"
  install -d -m 0750 -o root -g "$SVC_USER" "$TUNNELS_DIR"
  install -d -m 0750 -o "$SVC_USER" -g "$SVC_USER" "$STATE_DIR/monitor"
  # After a migration the files carry the old group; re-apply ownership so the
  # new service user can read them.
  chown -R root:"$SVC_USER" "$ETC_DIR" 2>/dev/null || true
  [[ -f $PSK_FILE ]] && chown root:root "$PSK_FILE" 2>/dev/null || true
  chmod 0640 "$ETC_DIR"/config.toml 2>/dev/null || true
  [[ -f $PSK_FILE ]] && chmod 0600 "$PSK_FILE" 2>/dev/null || true
}

ver_ge() { [[ $(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1) == "$2" ]]; } # $1 >= $2

ensure_toolchain() {
  if command -v cargo >/dev/null && command -v rustc >/dev/null; then
    local v; v=$(rustc --version | awk '{print $2}')
    if ver_ge "${v%%-*}" "$MIN_RUSTC"; then info "Using system Rust $v"; return 0; fi
    info "System Rust $v is older than $MIN_RUSTC; using a private rustup toolchain"
  fi
  export RUSTUP_HOME=$STATE_DIR/rustup CARGO_HOME=$STATE_DIR/cargo
  if [[ ! -x $CARGO_HOME/bin/cargo ]]; then
    local tmp; tmp=$(mktemp)
    curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs -o "$tmp"
    sh "$tmp" -y --profile minimal --default-toolchain stable --no-modify-path
    rm -f "$tmp"
  else
    "$CARGO_HOME/bin/rustup" update stable --no-self-update >/dev/null 2>&1 || true
  fi
  export PATH=$CARGO_HOME/bin:$PATH
}

fetch_source() {
  # Prefer a Rust core bundled next to this installer (e.g. ./core) unless the
  # operator pointed SHADOW_SRC_DIR somewhere else or asked for a specific ref.
  if [[ -z ${SHADOW_SRC_DIR-} && -z ${SHADOW_REF-} ]]; then
    local here; here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
    [[ -f $here/core/Cargo.toml ]] && { SHADOW_SRC_DIR=$here/core; info "Using bundled source at $SHADOW_SRC_DIR"; }
  fi
  if [[ -n ${SHADOW_SRC_DIR-} ]]; then
    [[ -f $SHADOW_SRC_DIR/Cargo.toml ]] || die "SHADOW_SRC_DIR has no Cargo.toml"
    SRC=$SHADOW_SRC_DIR; BUILD_REF="local:$(cd "$SRC" && git rev-parse HEAD 2>/dev/null || echo unversioned)"
    return 0
  fi
  SRC=$SRC_DIR
  if [[ -d $SRC/.git ]]; then
    git -C "$SRC" remote set-url origin "$REPO_URL"
    git -C "$SRC" fetch --quiet --tags origin
  else
    rm -rf "$SRC"; git clone --quiet "$REPO_URL" "$SRC"
  fi
  # Prefer the freshly fetched remote branch: a plain `checkout master` would use
  # the STALE local branch from the first install, so updates rebuilt old code.
  { git -C "$SRC" checkout --quiet --detach "origin/$REPO_REF" 2>/dev/null \
      || git -C "$SRC" checkout --quiet --detach "$REPO_REF"; } \
    || die "cannot check out '$REPO_REF' (set SHADOW_REF to a valid commit)"
  BUILD_REF=$(git -C "$SRC" rev-parse HEAD)
  if [[ $REPO_REF =~ ^[0-9a-f]{40}$ && $BUILD_REF != "$REPO_REF" ]]; then die "commit mismatch"; fi
  [[ $REPO_REF =~ ^[0-9a-f]{40}$ ]] || warn "building unpinned ref '$REPO_REF' -> $BUILD_REF"
  # This repo keeps the Rust core in a core/ subdirectory; build from there.
  if [[ ! -f $SRC/Cargo.toml && -f $SRC/core/Cargo.toml ]]; then SRC=$SRC/core; fi
  ok "Source at $BUILD_REF"
}

build_and_install() {
  fetch_source
  ensure_toolchain
  info "Building (cargo build --release --bins) - this can take a few minutes"
  export CARGO_TARGET_DIR=$STATE_DIR/target
  ( cd "$SRC" && cargo build --release --bins )
  local b src dst changed=0
  for b in client server; do
    src=$CARGO_TARGET_DIR/release/$b; dst=$BIN_DIR/shadow-spoof-$b
    [[ -x $src ]] || die "build did not produce $src"
    if ! cmp -s "$src" "$dst" 2>/dev/null; then
      install -m 0755 -o root -g root "$src" "$dst.new" && mv -f "$dst.new" "$dst"; changed=1
    fi
  done
  BINARY_CHANGED=$changed
  printf 'commit=%s\nbuilt=%s\nrole=%s\n' "$BUILD_REF" "$(date -u +%FT%TZ)" "$ROLE" >"$BUILD_INFO"
  chmod 0644 "$BUILD_INFO"
  ok "Installed $BIN_DIR/shadow-spoof-{client,server}"
}

# ---------------------------------------------------------- configuration ----
collect_config() {
  local o_real o_sp o_pool o_peer o_peersp o_peerpool o_port o_icmp o_socks o_tun o_mtu o_cwnd o_tp
  o_tp=$(cfg_get transport)
  o_real=$(cfg_get real_ip);        o_sp=$(cfg_get spoofed_ip)
  o_pool=$(cfg_get_list spoofed_ip_pool)
  o_peer=$(cfg_get peer_real_ip);   o_peersp=$(cfg_get peer_spoofed_ip)
  o_peerpool=$(cfg_get_list allowed_peers)
  o_port=$(cfg_get data_port)
  o_icmp=$(cfg_get icmp_id);        o_socks=$(cfg_get socks5_port)
  o_tun=$(cfg_get tunnel_count);    o_mtu=$(cfg_get mtu); o_cwnd=$(cfg_get initial_cwnd)

  local who peer
  if [[ $ROLE == client ]]; then who=client; peer=server; else who=server; peer=client; fi

  ask transport "Transport (spoof|tcp)" "${o_tp:-spoof}" v_transport "spoof = UDP data + ICMP control (forged source); tcp = standard non-spoofed TCP"

  local real_default=${o_real:-$(detect_ip)}
  ask real_ip        "Real $who IP"                    "$real_default" v_ipv4 "IPv4 address, e.g. 203.0.113.10"
  ask peer_real_ip   "Real peer $peer IP"              "$o_peer"       v_ipv4 "IPv4 address"

  if [[ $transport == tcp ]]; then
    # tcp mode: no raw sockets, no spoofed addresses. Fill the spoof-only
    # fields with inert defaults so the written config still parses.
    spoofed_ip=0.0.0.0; peer_spoofed_ip=0.0.0.0; spoofed_pool=""; peer_pool=""
    iface=""; icmp_id=0
    info "tcp transport: spoofed IPs / ICMP id / interface are not used and are left blank"
  else
    {
      echo
      echo "Field semantics (src/config.rs):"
      echo "  - spoofed IP      : source address this node forges on every outgoing packet"
      echo "  - peer spoofed IP : source address the $peer forges (must match its own setting)"
      echo "  - spoofed pool    : one address is picked at random each time the service starts"
      echo "  - peer pool       : extra $peer source addresses to accept (written to allowed_peers);"
      echo "                      list EVERY pool address the $peer may use, or packets from it are dropped"
      echo
    } >&2
    ask spoofed_ip     "Spoofed $who IP"                 "$o_sp"         v_ipv4 "IPv4 address"
    ask spoofed_pool   "Spoofed IP pool (comma-separated, optional)" "$o_pool" v_ipv4_list "comma-separated IPv4 list"
    ask peer_spoofed_ip "Spoofed peer $peer IP"          "$o_peersp"     v_ipv4 "IPv4 address"
    ask peer_pool      "Peer $peer spoofed IP pool (comma-separated, optional)" "$o_peerpool" v_ipv4_list "comma-separated IPv4 list"
    ask iface          "Interface"                       "auto" v_iface "interface name, or 'auto' to detect from the real IP"
    ask icmp_id        "ICMP ID (0-65535 or 0x....)"     "${o_icmp:-$DEFAULT_ICMP_ID}" v_u16 "must match the $peer (default $DEFAULT_ICMP_ID = 0x4321 on both sides)"
  fi
  ask data_port      "Data port"                       "${o_port:-51820}" v_port "1-65535 (must match the $peer)"
  if [[ $ROLE == client ]]; then
    ask socks5_port  "SOCKS5 port"                     "${o_socks:-1080}" v_socks_port "1024-65535 (binds 127.0.0.1)"
  fi
  ask tunnel_count   "Tunnel count"                    "${o_tun:-4}"   v_tunnels "1-256"
  ask mtu            "MTU"                             "${o_mtu:-1380}" v_mtu "512-1400"
  ask initial_cwnd   "Initial CWND"                    "${o_cwnd:-10}" v_cwnd "number of packets, 1-1000"

  # Interface: derive from the real IP; fall back to asking. (spoof mode only)
  if [[ $transport == tcp ]]; then
    :
  elif [[ $iface == auto ]]; then
    iface=$(detect_iface "$real_ip" || true)
    if [[ -n $iface ]]; then ok "Interface for $real_ip: $iface"
    else
      warn "No local interface carries $real_ip (NAT / floating IP?). Available:"
      ip -o link show | awk -F': ' '{print "    " $2}' >&2
      local manual=""
      if [[ $NONINTERACTIVE == 1 ]]; then die "interface detection failed; set SHADOW_IFACE"; fi
      while :; do
        printf 'Interface name: ' >&2; IFS= read -r manual <"$TTY_IN" || die "input closed"
        [[ -n $manual ]] && iface_exists "${manual%%@*}" && { iface=${manual%%@*}; break; }
        warn "interface not found"
      done
    fi
  elif ! iface_exists "$iface"; then
    warn "interface '$iface' does not exist on this host"
  fi

  spoofed_pool=$(norm_list "$spoofed_pool"); peer_pool=$(norm_list "$peer_pool")
  if [[ -n $spoofed_pool && ",$spoofed_pool," != *",$spoofed_ip,"* ]]; then
    warn "spoofed_ip is not in the pool: when a pool is set, ONLY pool addresses are used (src/config.rs pick_spoofed_ip)"
  fi
  icmp_id=$(norm_u16 "$icmp_id"); initial_cwnd=$(norm_float "$initial_cwnd")
}

handle_psk() {
  local existing=""
  [[ -r $PSK_FILE ]] && existing=$(<"$PSK_FILE")
  if [[ -n ${SHADOW_PRE_SHARED_KEY-} && ${SHADOW_PRE_SHARED_KEY-} != "$existing" ]]; then existing=""; fi
  if [[ -n $existing ]] && v_psk "$existing"; then
    if [[ $NONINTERACTIVE == 1 ]]; then
      if [[ -n ${SHADOW_PRE_SHARED_KEY-} && $SHADOW_PRE_SHARED_KEY != "$existing" ]]; then existing=""; fi
    elif ask_yn "Keep the existing pre-shared key?" y; then :; else existing=""; fi
  else existing=""; fi

  if [[ -n $existing ]]; then PSK=$existing; NEW_KEY=0; return 0; fi

  if [[ $ROLE == client ]]; then
    PSK=${SHADOW_PRE_SHARED_KEY:-$(gen_psk)}
    v_psk "$PSK" || die "invalid pre-shared key"
    NEW_KEY=1
  else
    echo >&2; info "Paste the pre-shared key generated by the client (input is hidden)."
    read_secret PSK "Pre-shared key"
    NEW_KEY=0
    ok "Key accepted (fingerprint $(key_fingerprint "$PSK") - compare with the client's)"
  fi
}

write_config() {
  local tmp b
  tmp=$(mktemp "$ETC_DIR/.config.XXXXXX")
  {
    echo "# Managed by the Shadow Spoof installer ($(date -u +%FT%TZ)) - role: $ROLE"
    echo "# Schema: src/config.rs @ $BUILD_REF"
    printf 'transport = "%s"\n'        "${transport:-spoof}"
    printf 'real_ip = "%s"\n'          "$real_ip"
    printf 'peer_real_ip = "%s"\n'     "$peer_real_ip"
    printf 'spoofed_ip = "%s"\n'       "$spoofed_ip"
    printf 'peer_spoofed_ip = "%s"\n'  "$peer_spoofed_ip"
    printf 'spoofed_ip_pool = %s\n'    "$(to_toml_list "$spoofed_pool")"
    printf 'data_port = %s\n'          "$((10#$data_port))"
    printf 'icmp_id = %s\n'            "$icmp_id"
    printf 'pre_shared_key = "%s"\n'   "$PSK"
    printf 'allowed_peers = %s\n'      "$(to_toml_list "$peer_pool")"
    printf 'tunnel_count = %s\n'       "$((10#$tunnel_count))"
    printf 'mtu = %s\n'                "$((10#$mtu))"
    printf 'initial_cwnd = %s\n'       "$initial_cwnd"
    printf 'interface = "%s"\n'        "$iface"
    if [[ $ROLE == client ]]; then printf 'socks5_port = %s\n' "$((10#$socks5_port))"; fi
  } >"$tmp"
  if [[ -f $CONF ]]; then
    b="$CONF.bak.$(date +%s)"; install -m 0600 -o root -g root "$CONF" "$b"
    # keep the three newest backups
    ls -1t "$CONF".bak.* 2>/dev/null | tail -n +4 | xargs -r rm -f
  fi
  chown "root:$SVC_USER" "$tmp"; chmod 0640 "$tmp"; mv -f "$tmp" "$CONF"

  local ptmp; ptmp=$(mktemp "$ETC_DIR/.psk.XXXXXX")
  printf '%s\n' "$PSK" >"$ptmp"; chown root:root "$ptmp"; chmod 0600 "$ptmp"; mv -f "$ptmp" "$PSK_FILE"
  printf '%s\n' "$ROLE" >"$ROLE_FILE"; chmod 0644 "$ROLE_FILE"
  ok "Wrote $CONF (0640 root:$SVC_USER) and $PSK_FILE (0600 root)"
}

configure() {
  RECONFIGURED=0
  if [[ -f $CONF ]]; then
    info "Existing configuration found at $CONF"
    local keep=1
    if [[ $NONINTERACTIVE == 1 ]]; then [[ ${SHADOW_RECONFIGURE:-0} == 1 ]] && keep=0
    elif ! ask_yn "Keep it (no prompts)?" y; then keep=0; fi
    if (( keep )); then
      if [[ ! -s $PSK_FILE ]]; then
        local k; k=$(cfg_get pre_shared_key); [[ -n $k ]] || die "config has no pre_shared_key"
        printf '%s\n' "$k" >"$PSK_FILE"; chmod 0600 "$PSK_FILE"
      fi
      printf '%s\n' "$ROLE" >"$ROLE_FILE"; chmod 0644 "$ROLE_FILE"
      return 0
    fi
  fi
  link_prefill
  collect_config
  handle_psk
  write_config
  RECONFIGURED=1
}

# ------------------------------------------------------------------ systemd --
emit_unit() { # emit_unit <description> <config path> <syslog identifier>
  cat <<UNIT
[Unit]
Description=$1
Documentation=https://github.com/AmiRCandy/Shadow Spoof
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=$SVC_USER
Group=$SVC_USER
ExecStart=$BIN_DIR/shadow-spoof-$ROLE --config $2
# Crash recovery. (Periodic restarts are handled separately by shadow-spoof-watchdog.timer.)
Restart=on-failure
RestartSec=5
SyslogIdentifier=$3
StandardOutput=journal
StandardError=journal
LimitNOFILE=65536

# Privileges: SOCK_RAW for the spoof transport (src/raw_socket.rs), and
# NET_BIND_SERVICE so the tcp transport can bind a low data_port (e.g. 443).
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_RAW CAP_NET_BIND_SERVICE
NoNewPrivileges=yes

# Sandboxing
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
ProcSubset=pid
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RemoveIPC=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
UMask=0077

[Install]
WantedBy=multi-user.target
UNIT
}

write_service_unit() {
  local unit=$UNIT_DIR/shadow-spoof-$ROLE.service tmpl=$UNIT_DIR/shadow-spoof-$ROLE@.service
  emit_unit "Shadow Spoof $ROLE" "$CONF" "shadow-spoof-$ROLE" >"$unit.new"
  # Template used by tunnels created from the panel / shadowctl: shadow-spoof-<role>@<name>.service
  emit_unit "Shadow Spoof $ROLE tunnel %i" "$TUNNELS_DIR/%i.toml" "shadow-spoof-$ROLE-%i" >"$tmpl.new"
  chmod 0644 "$unit.new" "$tmpl.new"; mv -f "$unit.new" "$unit"; mv -f "$tmpl.new" "$tmpl"

  local rs=${SHADOW_RESTART_SEC:-5} d
  [[ $rs =~ ^[0-9]+$ ]] && (( rs >= 1 && rs <= 3600 )) || die "SHADOW_RESTART_SEC must be 1-3600"
  for d in "shadow-spoof-$ROLE.service.d" "shadow-spoof-$ROLE@.service.d"; do
    install -d -m 0755 "$UNIT_DIR/$d"
    if [[ ! -f $UNIT_DIR/$d/10-restart.conf ]]; then
      printf '[Service]\nRestartSec=%s\n' "$rs" >"$UNIT_DIR/$d/10-restart.conf"; chmod 0644 "$UNIT_DIR/$d/10-restart.conf"
    fi
  done
}

install_shadowctl() {
  cat >"$SHADOWCTL.new" <<'SHADOWCTL_EOF'
#!/usr/bin/env bash
# shadowtun - runtime management for Shadow Spoof (installed by install.sh)
set -Eeuo pipefail
umask 077

ETC=${SHADOW_ETC_DIR:-/etc/shadow-spoof}
CONF=$ETC/config.toml
PSK_FILE=$ETC/psk
ROLE_FILE=$ETC/role
BUILD_INFO=$ETC/build-info
UNIT_DIR=${SHADOW_UNIT_DIR:-/etc/systemd/system}
STATE=${SHADOW_STATE_DIR:-/var/lib/shadow-spoof}
SVC_USER=shadow-spoof
LIB=/usr/local/lib/shadow-spoof
PYSCRIPT=$LIB/shadow-panel.py

die() { printf 'shadowctl: %s\n' "$*" >&2; exit 1; }

usage() {
cat <<EOF
Usage: shadowtun [-t NAME] <command>

  status                 services, watchdog, panel and (redacted) configuration
  tunnels                list tunnels on this host
  start | stop | restart all tunnels (or one with -t NAME)
  logs [journalctl args] e.g.  shadowtun logs -f
  monitor                live dashboard (CPU/RAM/connections/traffic/events)
  monitor logs [LEVEL]   live colourised logs (LEVEL: debug|info|warn|error)
  test [--host H --port P --secs N]
                         end-to-end tunnel test: handshake, real data, packet capture
  check                  validate the configuration with the binary (--check-config); exit 1 if rejected
  diagnose [--link L]    full tunnel-path doctor; pass the peer's setup link for a two-sided check
  mtu                    path-MTU probe to the peer; recommends a tunnel mtu (Linux)
  update                 update to the latest release (rebuild), keeping your configuration
  backup [FILE]          write a .tar.gz of /etc/shadow-spoof (config + keys)
  restore <FILE>         restore config/keys from a backup, then restart (backs up current first)
  uninstall              remove services, binaries, panel and config
  config                 print the configuration (pre_shared_key redacted)
  config edit            edit in \$EDITOR; validated, applied with automatic rollback
  set key=value ...      change fields, e.g.  shadowtun set icmp_id=17185 mtu=1300
  token                  print the pre-shared key
  link                   print the setup link for the other side
  watchdog <off|30m|1h|6h|12h|24h>   periodic restart via systemd timer
  restart-sec <1-3600>   crash-recovery delay (RestartSec)
  socks-port <PORT>      (client) change the local SOCKS5 port
  panel [info|passwd|port N|bind IP|tls on|off|enable|disable|start|stop|restart]
EOF
}

# ---- argument parsing: -t NAME may appear anywhere ----
TARGET=""
ARGS=()
while (( $# )); do
  case $1 in
    -t|--tunnel) TARGET=${2-}; [[ -n $TARGET ]] || die "-t needs a name"; shift 2 ;;
    *) ARGS+=("$1"); shift ;;
  esac
done
set -- "${ARGS[@]+"${ARGS[@]}"}"
[[ $# -eq 0 || $1 == help || $1 == -h || $1 == --help ]] && { usage; exit 0; }

if [[ $EUID -ne 0 ]]; then
  command -v sudo >/dev/null && exec sudo -- "$0" ${TARGET:+-t "$TARGET"} "$@"
  die "must run as root"
fi

[[ -r $ROLE_FILE ]] || die "Shadow Spoof is not installed (missing $ROLE_FILE)"
ROLE=$(<"$ROLE_FILE")
SYSTEMCTL=$(command -v systemctl)
PY=(python3 "$PYSCRIPT")

inst_names() { echo main; local f; for f in "$ETC"/tunnels/*.toml; do [[ -e $f ]] && basename "$f" .toml; done; return 0; }
unit_of() { if [[ $1 == main ]]; then echo "shadow-spoof-$ROLE.service"; else echo "shadow-spoof-$ROLE@$1.service"; fi; }
conf_of() { if [[ $1 == main ]]; then echo "$CONF"; else echo "$ETC/tunnels/$1.toml"; fi; }
check_target() { [[ -z $TARGET ]] && return 0; inst_names | grep -qx -- "$TARGET" || die "no such tunnel '$TARGET' (have: $(inst_names | tr '\n' ' '))"; }
one() { check_target; echo "${TARGET:-main}"; }          # single target, default main
targets() { check_target; if [[ -n $TARGET ]]; then echo "$TARGET"; else inst_names; fi; }

cfg_get() { sed -n "s/^[[:space:]]*$2[[:space:]]*=[[:space:]]*//p" "$(conf_of "$1")" | head -n1 | sed 's/[[:space:]]*#.*$//; s/^"//; s/"$//'; }
redacted() { sed -E 's/^([[:space:]]*pre_shared_key[[:space:]]*=[[:space:]]*).*/\1"********"/' "$(conf_of "$1")"; }
listening() { ss -H -ltn "sport = :$1" 2>/dev/null | awk '{print $4}' | grep -qx "127.0.0.1:$1"; }
wait_listen() { local i; for ((i = 0; i < 30; i++)); do listening "$1" && return 0; sleep 0.5; done; return 1; }
need_py() { [[ -f $PYSCRIPT ]] || die "panel/monitor tools are not installed (re-run install.sh)"; command -v python3 >/dev/null || die "python3 is required"; }

status_one() {
  local n=$1 u active enabled since nrest pid
  u=$(unit_of "$n")
  active=$($SYSTEMCTL is-active "$u" 2>/dev/null || true)
  enabled=$($SYSTEMCTL is-enabled "$u" 2>/dev/null || true)
  since=$($SYSTEMCTL show "$u" -p ActiveEnterTimestamp --value 2>/dev/null || true)
  nrest=$($SYSTEMCTL show "$u" -p NRestarts --value 2>/dev/null || true)
  pid=$($SYSTEMCTL show "$u" -p MainPID --value 2>/dev/null || true)
  printf '\n== %s (%s)\n' "$n" "$ROLE"
  printf 'Service   : %s (%s, enabled: %s)\n' "$u" "${active:-?}" "${enabled:-?}"
  printf 'Since     : %s\nMain PID  : %s   Auto-restarts: %s\n' "${since:--}" "${pid:-0}" "${nrest:-0}"
  if [[ $ROLE == client && $active == active ]]; then
    local p; p=$(cfg_get "$n" socks5_port)
    if listening "$p"; then printf 'SOCKS5    : 127.0.0.1:%s (listening)\n' "$p"
    else printf 'SOCKS5    : 127.0.0.1:%s (NOT listening)\n' "$p"; fi
  fi
  redacted "$n" | grep -vE '^[[:space:]]*(#|$)' | sed 's/^/  /'
  [[ $active == active ]]
}

cmd_status() {
  local n rc=0
  for n in $(targets); do status_one "$n" || rc=1; done
  local wd=off; [[ -r $ETC/watchdog ]] && wd=$(<"$ETC/watchdog")
  printf '\nWatchdog  : %s' "$wd"
  if [[ $wd != off ]]; then
    local nxt; nxt=$($SYSTEMCTL list-timers shadow-spoof-watchdog.timer --no-legend 2>/dev/null | awk '{print $1" "$2" "$3" "$4}')
    [[ -n $nxt ]] && printf '   (next: %s)' "$nxt"
  fi
  printf '\n'
  local x
  for x in monitor panel; do
    $SYSTEMCTL cat "shadow-spoof-$x.service" >/dev/null 2>&1 && printf '%-10s: %s\n' "${x^}" "$($SYSTEMCTL is-active "shadow-spoof-$x.service" 2>/dev/null || true)"
  done
  [[ -r $BUILD_INFO ]] && printf 'Build     : %s\n' "$(sed -n 's/^commit=//p' "$BUILD_INFO")"
  return $rc
}

cmd_tunnels() {
  local n u
  printf '%-14s %-8s %-10s %s\n' NAME ROLE STATE ENDPOINTS
  for n in $(inst_names); do
    u=$(unit_of "$n")
    printf '%-14s %-8s %-10s %s -> %s  udp/%s icmp/%s%s\n' "$n" "$ROLE" "$($SYSTEMCTL is-active "$u" 2>/dev/null || true)" \
      "$(cfg_get "$n" real_ip)" "$(cfg_get "$n" peer_real_ip)" "$(cfg_get "$n" data_port)" "$(cfg_get "$n" icmp_id)" \
      "$([[ $ROLE == client ]] && echo "  socks/$(cfg_get "$n" socks5_port)")"
  done
}

cmd_logs() {
  if [[ -n $TARGET ]]; then check_target; exec journalctl -u "$(unit_of "$TARGET")" -n 200 --no-pager "$@"; fi
  exec journalctl -u "shadow-spoof-$ROLE.service" -u "shadow-spoof-$ROLE@*.service" -n 200 --no-pager "$@"
}

cmd_token() { local n; n=$(one); if [[ $n == main && -r $PSK_FILE ]]; then cat "$PSK_FILE"; else cfg_get "$n" pre_shared_key; fi; }

write_watchdog_service() {
  cat >"$UNIT_DIR/shadow-spoof-watchdog.service" <<UNIT
[Unit]
Description=Shadow Spoof periodic restart (watchdog)
Documentation=man:shadowctl(8)

[Service]
Type=oneshot
# try-restart: does nothing for tunnels the operator deliberately stopped.
ExecStart=$SYSTEMCTL try-restart shadow-spoof-$ROLE.service
ExecStart=-$SYSTEMCTL try-restart shadow-spoof-$ROLE@*.service
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
UNIT
  chmod 0644 "$UNIT_DIR/shadow-spoof-watchdog.service"
}

cmd_watchdog() {
  local v=${1-} spec
  if [[ -z $v ]]; then [[ -r $ETC/watchdog ]] && cat "$ETC/watchdog" || echo off; return 0; fi
  case $v in
    off) spec= ;;
    30m) spec=30min ;;
    1h|6h|12h|24h) spec=$v ;;
    *) die "invalid watchdog value '$v' (use: off 30m 1h 6h 12h 24h)" ;;
  esac
  write_watchdog_service
  if [[ -z $spec ]]; then
    $SYSTEMCTL disable --now shadow-spoof-watchdog.timer >/dev/null 2>&1 || true
    rm -f "$UNIT_DIR/shadow-spoof-watchdog.timer"
    $SYSTEMCTL daemon-reload
    echo off >"$ETC/watchdog"; chmod 0644 "$ETC/watchdog"
    echo "Watchdog disabled (crash recovery via Restart=on-failure is unaffected)."
    return 0
  fi
  cat >"$UNIT_DIR/shadow-spoof-watchdog.timer" <<UNIT
[Unit]
Description=Shadow Spoof periodic restart timer ($v)
Documentation=man:shadowctl(8)

[Timer]
OnBootSec=$spec
OnUnitActiveSec=$spec
AccuracySec=10s
Unit=shadow-spoof-watchdog.service

[Install]
WantedBy=timers.target
UNIT
  chmod 0644 "$UNIT_DIR/shadow-spoof-watchdog.timer"
  $SYSTEMCTL daemon-reload
  $SYSTEMCTL enable shadow-spoof-watchdog.timer >/dev/null 2>&1
  $SYSTEMCTL restart shadow-spoof-watchdog.timer
  echo "$v" >"$ETC/watchdog"; chmod 0644 "$ETC/watchdog"
  echo "Watchdog set to every $v."
  $SYSTEMCTL list-timers shadow-spoof-watchdog.timer --no-legend 2>/dev/null | sed 's/^/  /' || true
}

cmd_restart_sec() {
  local n=${1-} d
  [[ $n =~ ^[0-9]+$ ]] && (( n >= 1 && n <= 3600 )) || die "restart-sec must be an integer 1-3600"
  for d in "shadow-spoof-$ROLE.service.d" "shadow-spoof-$ROLE@.service.d"; do
    mkdir -p "$UNIT_DIR/$d"
    printf '[Service]\nRestartSec=%s\n' "$n" >"$UNIT_DIR/$d/10-restart.conf"; chmod 0644 "$UNIT_DIR/$d/10-restart.conf"
  done
  $SYSTEMCTL daemon-reload
  echo "RestartSec=$n (applies to the next automatic restart)."
}

cmd_socks_port() {
  [[ $ROLE == client ]] || die "socks-port is only available on the client"
  local name port=${1-} cf unit cur
  name=$(one); cf=$(conf_of "$name"); unit=$(unit_of "$name")
  [[ $port =~ ^[0-9]{1,5}$ ]] || die "port must be a number"
  port=$((10#$port))
  (( port >= 1024 && port <= 65535 )) || die "port must be 1024-65535 (the service has no CAP_NET_BIND_SERVICE)"
  cur=$(cfg_get "$name" socks5_port)
  if [[ $cur == "$port" ]]; then
    echo "SOCKS5 port is already $port."
    listening "$port" && echo "Confirmed: 127.0.0.1:$port is listening."
    return 0
  fi
  if ss -H -ltn "sport = :$port" 2>/dev/null | grep -q .; then die "port $port is already in use"; fi
  local bak tmp
  bak=$(mktemp "$ETC/.config.bak.XXXXXX"); cp -p "$cf" "$bak"
  tmp=$(mktemp "$ETC/.config.XXXXXX")
  awk -v p="$port" '
    /^[[:space:]]*socks5_port[[:space:]]*=/ { print "socks5_port = " p; done=1; next }
    { print }
    END { if (!done) print "socks5_port = " p }' "$cf" >"$tmp"
  chown --reference="$cf" "$tmp"; chmod --reference="$cf" "$tmp"
  mv -f "$tmp" "$cf"
  [[ $(cfg_get "$name" socks5_port) == "$port" ]] || { mv -f "$bak" "$cf"; die "config update failed; reverted"; }
  $SYSTEMCTL restart "$unit"
  if wait_listen "$port"; then
    rm -f "$bak"
    echo "SOCKS5 port changed: $cur -> $port"
    echo "Confirmed: 127.0.0.1:$port is listening."
  else
    mv -f "$bak" "$cf"; $SYSTEMCTL restart "$unit" || true
    die "service did not start listening on $port; reverted to $cur. See: shadowtun logs"
  fi
}

ensure_cert() {
  [[ -f $ETC/panel.crt && -f $ETC/panel.key ]] && return 0
  command -v openssl >/dev/null || die "openssl is required to create a TLS certificate"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
    -subj "/CN=shadow-spoof" -keyout "$ETC/panel.key" -out "$ETC/panel.crt" >/dev/null 2>&1
  chmod 0600 "$ETC/panel.key"; chmod 0644 "$ETC/panel.crt"
}

cmd_panel() {
  need_py
  local sub=${1-info}
  case $sub in
    info)
      printf 'URL    : %s\nService: %s\n' "$("${PY[@]}" admin info)" "$($SYSTEMCTL is-active shadow-spoof-panel.service 2>/dev/null || true)" ;;
    passwd)
      local pw; pw=$("${PY[@]}" admin passwd-random)
      printf 'New panel password (shown once): %s\n' "$pw" ;;
    passwd-set)
      local a b
      read -rsp "New password (10+ chars): " a; echo; read -rsp "Repeat: " b; echo
      [[ $a == "$b" ]] || die "passwords differ"
      printf '%s\n' "$a" | "${PY[@]}" admin passwd && echo "Password updated." ;;
    port)  "${PY[@]}" admin set port "${2-}"; $SYSTEMCTL restart shadow-spoof-panel.service; cmd_panel info ;;
    bind)  "${PY[@]}" admin set bind "${2-}"; $SYSTEMCTL restart shadow-spoof-panel.service; cmd_panel info ;;
    tls)
      case ${2-} in
        on)  ensure_cert; "${PY[@]}" admin set tls 1 ;;
        off) "${PY[@]}" admin set tls 0 ;;
        *)   die "usage: shadowtun panel tls on|off" ;;
      esac
      $SYSTEMCTL restart shadow-spoof-panel.service; cmd_panel info ;;
    start|stop|restart) $SYSTEMCTL "$sub" shadow-spoof-panel.service && echo "panel $sub" ;;
    enable)  $SYSTEMCTL enable --now shadow-spoof-panel.service && echo "panel enabled (autostart on)" ;;
    disable) $SYSTEMCTL disable --now shadow-spoof-panel.service && echo "panel disabled (stopped, autostart off)" ;;
    *) die "usage: shadowtun panel [info|passwd|passwd-set|port N|bind IP|tls on|off|enable|disable|start|stop|restart]" ;;
  esac
}

cmd_check() { # validate each target's config with the binary's --check-config
  local bin=/usr/local/bin/shadow-spoof-$ROLE n c out rc fail=0
  [[ -x $bin ]] || die "binary $bin not found (re-run install.sh)"
  for n in $(targets); do
    c=$(conf_of "$n")
    out=$("$bin" --config "$c" --check-config 2>&1) && rc=0 || rc=$?
    if (( rc == 0 )); then
      printf '[+] %s: config accepted (%s)\n' "$n" "$c"
      printf '%s\n' "$out" | grep -i 'WARN' | sed 's/^/    /' || true
    else
      printf '[x] %s: config rejected (%s)\n' "$n" "$c" >&2
      printf '%s\n' "$out" | sed 's/^/    /' >&2
      fail=1
    fi
  done
  return $fail
}

cmd_backup() { # tar.gz of the whole config dir (config + keys + panel + tunnels)
  local out=${1:-/root/shadow-spoof-backup-$(date +%F-%H%M%S).tar.gz}
  [[ -d $ETC ]] || die "nothing to back up ($ETC missing)"
  tar czf "$out" -C "$(dirname "$ETC")" "$(basename "$ETC")" || die "backup failed"
  chmod 0600 "$out" 2>/dev/null || true
  echo "$out"
}

cmd_update() { # rebuild + reinstall from the latest release, keeping the config
  local url=${SHADOW_INSTALL_URL:-https://raw.githubusercontent.com/primeshock/shadow-tunnel/master/install.sh}
  if [[ ${1-} != -y ]]; then
    printf 'Update rebuilds the binary and reinstalls the panel/CLI, keeping %s. Continue? [y/N] ' "$ETC" >&2
    local a=""; read -r a </dev/tty 2>/dev/null || true
    case ${a,,} in y|yes) ;; *) echo "aborted" >&2; return 1 ;; esac
  fi
  command -v curl >/dev/null || die "curl is required"
  echo "Backing up first: $(cmd_backup)" >&2
  curl -fsSL "$url" | SHADOW_NONINTERACTIVE=1 SHADOW_RECONFIGURE=0 SHADOW_ROLE="$ROLE" bash
}

cmd_restore() { # restore /etc/shadow-spoof from a backup tar.gz, then restart
  local f=${1-}
  [[ -f $f ]] || die "backup file not found: '$f'"
  tar tzf "$f" >/dev/null 2>&1 || die "not a valid .tar.gz: $f"
  local safety; safety=$(cmd_backup) && echo "current config saved to $safety first" >&2
  local tmp; tmp=$(mktemp -d)
  tar xzf "$f" -C "$tmp" || die "extract failed"
  local src="$tmp/$(basename "$ETC")"
  [[ -d $src ]] || src=$(find "$tmp" -maxdepth 1 -type d ! -path "$tmp" | head -n1)
  [[ -d $src ]] || die "backup does not contain a config directory"
  rm -rf "$ETC"; mv "$src" "$ETC"; rm -rf "$tmp"
  chown -R root:"$SVC_USER" "$ETC" 2>/dev/null || true
  [[ -f $PSK_FILE ]] && chmod 0600 "$PSK_FILE" 2>/dev/null || true
  $SYSTEMCTL daemon-reload 2>/dev/null || true
  local n; for n in $(inst_names); do $SYSTEMCTL try-restart "$(unit_of "$n")" 2>/dev/null || true; done
  echo "restored $ETC from $f"
}

cmd_uninstall() {
  if [[ ${1-} != -y ]]; then
    printf 'This removes services, binaries, the panel and %s. Type YES to confirm: ' "$ETC" >&2
    local a=""; read -r a </dev/tty 2>/dev/null || true
    [[ $a == YES ]] || { echo "aborted" >&2; return 1; }
  fi
  local u
  for u in $($SYSTEMCTL list-unit-files --no-legend 'shadow-spoof-*' 2>/dev/null | awk '{print $1}'); do
    $SYSTEMCTL disable --now "$u" >/dev/null 2>&1 || true
  done
  rm -f  "$UNIT_DIR"/shadow-spoof-*.service "$UNIT_DIR"/shadow-spoof-*.timer 2>/dev/null || true
  rm -rf "$UNIT_DIR"/shadow-spoof-*.service.d 2>/dev/null || true
  $SYSTEMCTL daemon-reload 2>/dev/null || true
  rm -f  /usr/local/bin/shadow-spoof-client /usr/local/bin/shadow-spoof-server \
         /usr/local/bin/shadowtun /usr/local/bin/shadowtun 2>/dev/null || true
  rm -rf /usr/local/lib/shadow-spoof "$ETC" "${STATE:-/var/lib/shadow-spoof}" 2>/dev/null || true
  echo "Shadow Spoof removed. (the 'shadow-spoof' system user was left in place)"
}

cmd=$1; shift
check_target
case $cmd in
  status)      cmd_status ;;
  check)       cmd_check ;;
  diagnose)    need_py; exec "${PY[@]}" diagnose ${TARGET:+-t "$TARGET"} "$@" ;;
  mtu)         need_py; exec "${PY[@]}" mtu ${TARGET:+-t "$TARGET"} "$@" ;;
  update)      cmd_update "${1-}" ;;
  backup)      cmd_backup "${1-}" ;;
  restore)     cmd_restore "${1-}" ;;
  uninstall)   cmd_uninstall "${1-}" ;;
  tunnels)     cmd_tunnels ;;
  start|stop|restart)
               for n in $(targets); do $SYSTEMCTL "$cmd" "$(unit_of "$n")"; done; echo "$cmd: $(targets | tr '\n' ' ')" ;;
  logs)        cmd_logs "$@" ;;
  monitor)     need_py
               if [[ ${1-} == logs ]]; then exec "${PY[@]}" log-view "${2-info}"; else exec "${PY[@]}" monitor-view; fi ;;
  test)        need_py; exec "${PY[@]}" test ${TARGET:+-t "$TARGET"} "$@" ;;
  config)      if [[ ${1-} == edit ]]; then need_py; exec "${PY[@]}" cfg ${TARGET:+-t "$TARGET"} edit; else redacted "$(one)"; fi ;;
  set)         need_py; exec "${PY[@]}" cfg ${TARGET:+-t "$TARGET"} set "$@" ;;
  token)       cmd_token ;;
  link)        need_py; exec "${PY[@]}" link make "$(one)" ;;
  watchdog)    cmd_watchdog "${1-}" ;;
  restart-sec) cmd_restart_sec "${1-}" ;;
  socks-port)  cmd_socks_port "${1-}" ;;
  panel)       cmd_panel "$@" ;;
  *)           usage >&2; exit 2 ;;
esac
SHADOWCTL_EOF
  chmod 0755 "$SHADOWCTL.new"; chown root:root "$SHADOWCTL.new"; mv -f "$SHADOWCTL.new" "$SHADOWCTL"
  ok "Installed $SHADOWCTL"
}

install_shadowtun() {
  cat >"$SHADOWTUN.new" <<'SHADOWTUN_EOF'
#!/usr/bin/env bash
# shadowtun - the single Shadow Spoof command: interactive menu, or a
# pass-through to the scriptable backend (installed by install.sh).
#
#   shadowtun              open the interactive menu
#   shadowtun <command>    run a backend command, e.g. shadowtun status
set -Euo pipefail

ETC=${SHADOW_ETC_DIR:-/etc/shadow-spoof}
ROLE_FILE=$ETC/role
TUNNELS=$ETC/tunnels
CTL=${SHADOW_CTL:-/usr/local/bin/shadowctl}
VERSION=2.0.0

# Pass-through: `shadowtun <anything>` runs the backend so every command lives
# under one name (status, check, diagnose, update, backup, restore, ...).
if [[ $# -gt 0 ]]; then exec "$CTL" "$@"; fi

if [[ $EUID -ne 0 ]]; then
  command -v sudo >/dev/null && exec sudo -- "$0" "$@"
  echo "shadowtun: must run as root" >&2; exit 1
fi
[[ -r $ROLE_FILE ]] || { echo "shadowtun: not installed (missing $ROLE_FILE)"; exit 1; }
ROLE=$(<"$ROLE_FILE")

if [[ -t 0 ]]; then TTY=/dev/stdin; elif { : </dev/tty; } 2>/dev/null; then TTY=/dev/tty
else echo "shadowtun needs a terminal; run 'shadowtun <command>' for scripting" >&2; exit 1; fi

c_r=$'\e[38;5;203m'; c_c=$'\e[36m'; c_b=$'\e[1m'; c_g=$'\e[32m'; c_y=$'\e[33m'; c_d=$'\e[2m'; c_0=$'\e[0m'
[[ -t 1 ]] || { c_r=; c_c=; c_b=; c_g=; c_y=; c_d=; c_0=; }

ask()   { local p=$1 v=""; printf '%s' "$p" >&2; read -r v <"$TTY" || true; printf '%s' "$v"; }
pause() { printf '\n%sEnter to continue%s ' "$c_d" "$c_0" >&2; read -r _ <"$TTY" || true; }
item()  { printf '  %s%2s)%s %s%-15s%s %s%s%s\n' "$c_c" "$1" "$c_0" "$c_b" "$2" "$c_0" "$c_d" "${3:-}" "$c_0"; }
names() { echo main; local f; for f in "$TUNNELS"/*.toml; do [[ -e $f ]] && basename "$f" .toml; done; return 0; }
active(){ systemctl is-active "shadow-spoof-$ROLE${1:+@$1}.service" 2>/dev/null || true; }
unit_of(){ [[ $1 == main ]] && echo "shadow-spoof-$ROLE.service" || echo "shadow-spoof-$ROLE@$1.service"; }
cfgval(){ "$CTL" -t "$1" config 2>/dev/null | sed -n "s/^[[:space:]]*$2[[:space:]]*=[[:space:]]*//p" | head -n1 | tr -d '"'; }
panel_url() { command -v python3 >/dev/null && python3 /usr/local/lib/shadow-spoof/shadow-panel.py admin info 2>/dev/null || true; }

banner() {
  printf '%s' "$c_r"
  cat <<'ART'
   ███████ ██   ██  █████  ██████   ██████  ██     ██
   ██      ██   ██ ██   ██ ██   ██ ██    ██ ██     ██
   ███████ ███████ ███████ ██   ██ ██    ██ ██  █  ██
        ██ ██   ██ ██   ██ ██   ██ ██    ██ ██ ███ ██
   ███████ ██   ██ ██   ██ ██████   ██████   ███ ███
ART
  printf '%s' "$c_0"
  printf '   %sShadow Spoof%s  %sv%s%s   role: %s%s%s\n' "$c_b" "$c_0" "$c_r" "$VERSION" "$c_0" "$c_g" "$ROLE" "$c_0"
  printf '   %sGitHub: https://github.com/primeshock/shadow-tunnel%s\n' "$c_d" "$c_0"
  local url; url=$(panel_url); [[ -n $url ]] && printf '   %spanel : %s%s\n' "$c_d" "$url" "$c_0"
  printf '  %s%s%s\n\n' "$c_d" "──────────────────────────────────────────────────────" "$c_0"
}

state_tag() { local s=$1 col=$c_y; [[ $s == active ]] && col=$c_g; [[ $s == failed ]] && col=$c_r; printf '%s%s%s' "$col" "${s:-unknown}" "$c_0"; }

edit_fields() { # edit_fields <tunnel>
  local t=$1
  while :; do
    clear 2>/dev/null || true
    printf '%sEdit config%s — %s%s%s\n\n' "$c_b" "$c_0" "$c_c" "$t" "$c_0"
    local fields=(transport "${FIELDS_COMMON[@]}"); [[ $ROLE == client ]] && fields+=(socks5_port)
    local cur i=1
    for f in "${fields[@]}"; do
      cur=$(cfgval "$t" "$f")
      printf '  %s%2d)%s %-16s %s%s%s\n' "$c_c" "$i" "$c_0" "$f" "$c_d" "$cur" "$c_0"; ((i++))
    done
    printf '   %s0)%s back\n' "$c_c" "$c_0"
    local sel; sel=$(ask "pick a field to edit: ")
    [[ $sel == 0 || -z $sel ]] && return 0
    local idx=$((sel-1))
    [[ $idx -ge 0 && $idx -lt ${#fields[@]} ]] || continue
    local key=${fields[$idx]} val
    val=$(ask "new value for $key: ")
    [[ -z $val ]] && { echo "unchanged"; pause; continue; }
    if "$CTL" -t "$t" set "$key=$val"; then printf '%ssaved%s\n' "$c_g" "$c_0"; else printf '%srejected (see message above)%s\n' "$c_y" "$c_0"; fi
    pause
  done
}

FIELDS_COMMON=(real_ip peer_real_ip spoofed_ip peer_spoofed_ip spoofed_ip_pool allowed_peers \
               data_port icmp_id mtu initial_cwnd max_retries rto_min_ms interface pre_shared_key)

tunnel_menu() { # tunnel_menu <tunnel>
  local t=$1
  while :; do
    clear 2>/dev/null || true
    local st tp; st=$(active "$([[ $t == main ]] || echo "$t")"); tp=$(cfgval "$t" transport); tp=${tp:-spoof}
    printf '%sTunnel: %s%s\n' "$c_r" "$t" "$c_0"
    printf '   %s/%s  %s\n\n' "$ROLE" "$tp" "$(state_tag "$st")"
    printf '%sAction%s\n\n' "$c_r" "$c_0"
    item 1 Edit        "ports, transport, settings"
    item 2 Start
    item 3 Stop
    item 4 Restart
    item 5 "Live Log"  "Ctrl+C to return"
    item 6 "Setup Link" "builds the other end"
    item 7 "MTU test"  "recommend a tunnel mtu"
    item 8 Delete      "remove permanently"
    printf '\nEnter your choice (%s0 to go back%s): ' "$c_c" "$c_0"
    local ch; read -r ch <"$TTY" || true
    case "$ch" in
      1) edit_fields "$t" ;;
      2) "$CTL" -t "$t" start || true; pause ;;
      3) "$CTL" -t "$t" stop || true; pause ;;
      4) "$CTL" -t "$t" restart || true; pause ;;
      5) ( "$CTL" -t "$t" logs -f ) || true ;;
      6) echo "pre-shared key:"; "$CTL" -t "$t" token; echo; echo "setup link for the other end:"; "$CTL" -t "$t" link; pause ;;
      7) "$CTL" -t "$t" mtu || true; pause ;;
      8) if [[ $t == main ]]; then echo "the main tunnel cannot be deleted here"; pause
         elif [[ "$(ask "type the name '$t' to confirm delete: ")" == "$t" ]]; then
           systemctl disable --now "$(unit_of "$t")" 2>/dev/null; rm -f "$TUNNELS/$t.toml"; systemctl reset-failed "$(unit_of "$t")" 2>/dev/null
           printf '%sdeleted%s\n' "$c_g" "$c_0"; pause; return 0
         fi ;;
      0|"") return 0 ;;
    esac
  done
}

manage_tunnels() {
  while :; do
    clear 2>/dev/null || true
    printf '%sTunnels%s\n\n' "$c_r" "$c_0"
    local list=() i=1 n st tp
    while read -r n; do
      [[ -z $n ]] && continue
      st=$(active "$([[ $n == main ]] || echo "$n")"); tp=$(cfgval "$n" transport); tp=${tp:-spoof}
      printf '  %s%2d)%s %s%-16s%s %s%-6s%s %s\n' "$c_c" "$i" "$c_0" "$c_b" "$n" "$c_0" "$c_d" "$tp" "$c_0" "$(state_tag "$st")"
      list+=("$n"); ((i++))
    done < <(names)
    printf '   %s0)%s back\n' "$c_c" "$c_0"
    local sel; sel=$(ask "pick a tunnel: ")
    [[ $sel == 0 || -z $sel ]] && return 0
    local idx=$((sel-1))
    [[ $idx -ge 0 && $idx -lt ${#list[@]} ]] && tunnel_menu "${list[$idx]}"
  done
}

panel_menu() {
  while :; do
    clear 2>/dev/null || true
    printf '%sWeb Panel%s   %s%s%s\n\n' "$c_r" "$c_0" "$c_d" "$(panel_url)" "$c_0"
    item 1 "Info / URL"
    item 2 "Reset password"
    item 3 "Watchdog"       "off 30m 1h 6h 12h 24h"
    item 4 "Bind address"
    item 5 "Port"
    item 6 "TLS on/off"
    item 7 "Start"
    item 8 "Stop"
    item 9 "Restart"
    printf '\nEnter your choice (%s0 to go back%s): ' "$c_c" "$c_0"
    local ch; read -r ch <"$TTY" || true
    case "$ch" in
      1) "$CTL" panel info; pause ;;
      2) "$CTL" panel passwd; pause ;;
      3) "$CTL" watchdog "$(ask 'watchdog: ')" || true; pause ;;
      4) "$CTL" panel bind "$(ask 'bind IP (e.g. 0.0.0.0): ')" || true; pause ;;
      5) "$CTL" panel port "$(ask 'port: ')" || true; pause ;;
      6) "$CTL" panel tls "$(ask 'tls on|off: ')" || true; pause ;;
      7) "$CTL" panel start || true; pause ;;
      8) "$CTL" panel stop || true; pause ;;
      9) "$CTL" panel restart || true; pause ;;
      0|"") return 0 ;;
    esac
  done
}

backup_menu() {
  clear 2>/dev/null || true
  printf '%sBackup & Restore%s\n\n' "$c_r" "$c_0"
  item 1 "Backup now"   "write a .tar.gz of all settings"
  item 2 "Restore"      "from a backup file"
  printf '\nEnter your choice (%s0 to go back%s): ' "$c_c" "$c_0"
  local ch; read -r ch <"$TTY" || true
  case "$ch" in
    1) echo "backup written to: $("$CTL" backup)"; pause ;;
    2) local f; f=$(ask "path to backup .tar.gz: "); [[ -n $f ]] && { "$CTL" restore "$f" || true; }; pause ;;
  esac
}

main_menu() {
  while :; do
    clear 2>/dev/null || true
    banner
    item 1 "Manage"        "tunnels, status, edit, start/stop, delete"
    item 2 "Connection Test" "diagnose the whole tunnel path"
    item 3 "Web Panel"     "link, login code, port"
    item 4 "Health & Logs" "service health and live logs"
    item 5 "Setup Link"    "build / import the other end"
    item 6 "Backup"        "backup & restore all settings"
    item 7 "Update"        "rebuild, keep config, auto-rollback"
    item 8 "Uninstall"     "remove everything"
    item 0 "Exit"
    printf '\nSelect an option: '
    local ch; read -r ch <"$TTY" || true
    case "$ch" in
      1) manage_tunnels ;;
      2) "$CTL" diagnose || true; local l; l=$(ask "paste the peer's shadowspoof:// link for a 2-sided check (or Enter to skip): "); [[ -n $l ]] && { "$CTL" diagnose --link "$l" || true; }; pause ;;
      3) panel_menu ;;
      4) "$CTL" status || true; echo; "$CTL" check || true; echo; if [[ "$(ask 'follow live logs? [y/N] ')" =~ ^[Yy] ]]; then ( "$CTL" logs -f ) || true; fi ;;
      5) echo "pre-shared key:"; "$CTL" token; echo; echo "setup link for the OTHER end (paste it there):"; "$CTL" link; echo; printf '%sto import a link into THIS node, use the web panel: Tunnels -> Import link%s\n' "$c_d" "$c_0"; pause ;;
      6) backup_menu ;;
      7) "$CTL" update || true; pause ;;
      8) if [[ "$(ask 'really uninstall everything? type YES: ')" == YES ]]; then "$CTL" uninstall || echo "uninstall: see the project README"; fi; pause ;;
      0|q|"") clear 2>/dev/null || true; exit 0 ;;
    esac
  done
}

main_menu
SHADOWTUN_EOF
  chmod 0755 "$SHADOWTUN.new"; chown root:root "$SHADOWTUN.new"; mv -f "$SHADOWTUN.new" "$SHADOWTUN"
  ok "Installed $SHADOWTUN"
}

install_panel_files() {
  install -d -m 0755 -o root -g root "$LIB_DIR"
  cat >"$PANEL_PY.new" <<'SHADOW_PANEL_PY_EOF'
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Shadow Spoof web panel, monitor and CLI helpers (Python standard library only).

  shadow-panel.py panel          web panel (runs as root, hardened by systemd)
  shadow-panel.py monitor        metrics + log sampler (runs as the shadow-spoof user)
  shadow-panel.py monitor-view   live terminal dashboard           (shadowtun monitor)
  shadow-panel.py log-view [lvl] colourised live log follow        (shadowtun monitor logs)
  shadow-panel.py admin ...      panel.json maintenance            (shadowtun panel ...)

Facts about the upstream binary this relies on (from its source):
  * one config file + one process = one "tunnel instance"; role is client OR server
  * it exposes no API or metrics, so everything here is derived from systemd,
    /proc, `ss` and journald (env_logger lines such as "tunnel 3 established")
  * the SOCKS5 reply is sent after the SYN/SYN-ACK handshake with the server, so a
    SOCKS CONNECT measures the real tunnel round trip
  * pre_shared_key authenticates every packet (HMAC-SHA256); both sides must
    share the identical key, or authentication fails and packets are dropped
  * interface is bound to the raw sockets (SO_BINDTODEVICE)
"""
import argparse
import base64
import glob
import grp
import hashlib
import hmac
import ipaddress
import json
import os
import pwd
import re
import secrets
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
import urllib.request
import urllib.error

# --------------------------------------------------------------------- paths --
ETC = os.environ.get("SHADOW_ETC_DIR", "/etc/shadow-spoof")
STATE = os.environ.get("SHADOW_STATE_DIR", "/var/lib/shadow-spoof")
RUN = os.environ.get("SHADOW_RUN_DIR", "/run/shadow-spoof")
UNIT_DIR = os.environ.get("SHADOW_UNIT_DIR", "/etc/systemd/system")
SYSTEMCTL = os.environ.get("SHADOW_SYSTEMCTL", "systemctl")
JOURNALCTL = os.environ.get("SHADOW_JOURNALCTL", "journalctl")
SS = os.environ.get("SHADOW_SS", "ss")
IPCMD = os.environ.get("SHADOW_IP", "ip")
CTL = os.environ.get("SHADOW_CTL", "/usr/local/bin/shadowctl")
SVC_USER = "shadow-spoof"

CONF_MAIN = os.path.join(ETC, "config.toml")
TUNNELS = os.path.join(ETC, "tunnels")
ROLE_FILE = os.path.join(ETC, "role")
PSK_FILE = os.path.join(ETC, "psk")
BUILD_INFO = os.path.join(ETC, "build-info")
WATCHDOG_FILE = os.path.join(ETC, "watchdog")
PANEL_JSON = os.path.join(ETC, "panel.json")
STATE_JSON = os.path.join(RUN, "state.json")
EVENTS_FILE = os.path.join(STATE, "monitor", "events.jsonl")
CURSOR_FILE = os.path.join(STATE, "monitor", "journal.cursor")

SAMPLE_SEC = 5
HIST_LEN = 360
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,23}$")
HEX_RE = re.compile(r"^[0-9a-fA-F]{32,}$")


# --------------------------------------------------------------------- utils --
def run(cmd, timeout=15, inp=None):
    try:
        p = subprocess.run(cmd, input=inp, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", "command not found: %s" % cmd[0]
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


def read_text(path, default=""):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except OSError:
        return default


def atomic_write(path, data, mode=0o600, group=None, owner="root"):
    d = os.path.dirname(path)
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(data)
        os.chmod(tmp, mode)
        try:
            uid = pwd.getpwnam(owner).pw_uid if owner else -1
            gid = grp.getgrnam(group).gr_gid if group else -1
            os.chown(tmp, uid, gid)
        except (KeyError, PermissionError):
            pass
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def gen_key():
    return secrets.token_hex(32)  # OS CSPRNG, 256 bit


def fingerprint(key):
    return hashlib.sha256(key.encode()).hexdigest()[:8]


def get_role():
    r = read_text(ROLE_FILE).strip()
    return r if r in ("client", "server") else None


# ---------------------------------------------------------------------- toml --
def parse_toml(text):
    """Flat key = value parser sufficient for Shadow Spoof's config (src/config.rs)."""
    d = {}
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#") or s.startswith("["):
            continue
        if "=" not in s:
            continue
        k, v = s.split("=", 1)
        k, v = k.strip(), v.strip()
        if v.startswith("["):
            d[k] = re.findall(r'"([^"]*)"', v)
        elif v.startswith('"'):
            m = re.match(r'"([^"]*)"', v)
            d[k] = m.group(1) if m else v.strip('"')
        else:
            v = re.sub(r"\s*#.*$", "", v)
            try:
                if v.lower().startswith("0x"):
                    d[k] = int(v, 16)
                elif "." in v:
                    d[k] = float(v)
                else:
                    d[k] = int(v)
            except ValueError:
                d[k] = v
    return d


def toml_list(items):
    return "[" + ", ".join('"%s"' % i for i in items) + "]"


def render_config(role, c, note):
    lines = [
        "# Managed by the Shadow Spoof panel/installer - role: %s" % role,
        "# %s" % note,
        'transport = "%s"' % c.get("transport", "spoof"),
        'real_ip = "%s"' % c["real_ip"],
        'peer_real_ip = "%s"' % c["peer_real_ip"],
        'spoofed_ip = "%s"' % c["spoofed_ip"],
        'peer_spoofed_ip = "%s"' % c["peer_spoofed_ip"],
        "spoofed_ip_pool = %s" % toml_list(c["spoofed_ip_pool"]),
        "data_port = %d" % c["data_port"],
        "icmp_id = %d" % c["icmp_id"],
        'pre_shared_key = "%s"' % c["pre_shared_key"],
        "allowed_peers = %s" % toml_list(c["allowed_peers"]),
        "tunnel_count = %d" % c["tunnel_count"],
        "mtu = %d" % c["mtu"],
        "initial_cwnd = %s" % ("%.1f" % c["initial_cwnd"]),
        "max_retries = %d" % c["max_retries"],
        "rto_min_ms = %d" % c["rto_min_ms"],
        'auto_restart = "%s"' % c.get("auto_restart", "on-failure"),
        "restart_sec = %d" % (c.get("restart_sec") or 5),
        'interface = "%s"' % c["interface"],
    ]
    if role == "client":
        lines.append("socks5_port = %d" % c["socks5_port"])
    return "\n".join(lines) + "\n"


# ----------------------------------------------------------------- instances --
class Inst(object):
    def __init__(self, name, role, path):
        self.name, self.role, self.path = name, role, path
        self.unit = ("shadow-spoof-%s.service" % role) if name == "main" else ("shadow-spoof-%s@%s.service" % (role, name))

    def cfg(self):
        return parse_toml(read_text(self.path))


def instances():
    r = get_role()
    out = []
    if not r:
        return out
    if os.path.exists(CONF_MAIN):
        out.append(Inst("main", r, CONF_MAIN))
    for p in sorted(glob.glob(os.path.join(TUNNELS, "*.toml"))):
        name = os.path.basename(p)[:-5]
        if NAME_RE.match(name) and name != "main":
            out.append(Inst(name, r, p))
    return out


def find_inst(name):
    for i in instances():
        if i.name == name:
            return i
    return None


def redact(cfg):
    c = dict(cfg)
    key = c.pop("pre_shared_key", "")
    c["has_key"] = bool(key)
    c["key_fp"] = fingerprint(key) if key else ""
    return c


# --------------------------------------------------------------- validation --
def v_ip(s):
    try:
        ipaddress.IPv4Address(str(s).strip())
        return True
    except Exception:
        return False


def as_ip_list(v):
    if v is None:
        return [], None
    items = v if isinstance(v, list) else str(v).split(",")
    out = []
    for it in items:
        it = str(it).strip()
        if not it:
            continue
        if not v_ip(it):
            return None, "invalid IPv4 address: %s" % it
        if it not in out:
            out.append(it)
    return out, None


def as_int(v, lo, hi):
    try:
        if isinstance(v, str) and v.strip().lower().startswith("0x"):
            n = int(v.strip(), 16)
        else:
            n = int(str(v).strip())
    except (ValueError, TypeError):
        return None
    return n if lo <= n <= hi else None


def detect_ip():
    rc, out, _ = run([IPCMD, "-4", "route", "get", "1.1.1.1"])
    m = re.search(r" src (\d+\.\d+\.\d+\.\d+)", out or "")
    return m.group(1) if m else ""


def detect_iface(ip):
    rc, out, _ = run([IPCMD, "-4", "-o", "addr", "show"])
    for line in (out or "").splitlines():
        p = line.split()
        if len(p) >= 4 and p[3].split("/")[0] == ip:
            return p[1]
    return ""


def list_ifaces():
    rc, out, _ = run([IPCMD, "-o", "link", "show"])
    names = []
    for line in (out or "").splitlines():
        m = re.match(r"\d+:\s+([^:@\s]+)", line)
        if m and m.group(1) != "lo":
            names.append(m.group(1))
    return names


def port_listening(port, local_only=False):
    rc, out, _ = run([SS, "-H", "-ltn", "( sport = :%d )" % port])
    if not out.strip():
        return False
    if local_only:
        return any(l.split()[3:4] == ["127.0.0.1:%d" % port] for l in out.splitlines() if len(l.split()) >= 4)
    return True


def validate(role, data, self_name, current=None):
    """Validate/normalise tunnel fields. Returns (clean, errors)."""
    cur = current or {}
    errs = {}
    c = {}

    def pick(k, default=None):
        v = data.get(k)
        if v is None or (isinstance(v, str) and v.strip() == ""):
            return cur.get(k, default)
        return v

    tp = str(pick("transport", "spoof")).strip().lower()
    if tp not in ("spoof", "tcp"):
        errs["transport"] = 'must be "spoof" or "tcp"'
        tp = "spoof"
    c["transport"] = tp

    # spoofed addresses are required only in spoof mode
    req_ips = ["real_ip", "peer_real_ip"] + (["spoofed_ip", "peer_spoofed_ip"] if tp == "spoof" else [])
    for k in req_ips:
        v = pick(k)
        if v is None or not v_ip(v):
            errs[k] = "valid IPv4 address required"
        else:
            c[k] = str(v).strip()
    if tp == "tcp":
        for k in ("spoofed_ip", "peer_spoofed_ip"):
            v = pick(k)
            c[k] = str(v).strip() if (v and v_ip(v)) else "0.0.0.0"

    pool, e = as_ip_list(data["spoofed_ip_pool"] if "spoofed_ip_pool" in data else cur.get("spoofed_ip_pool", []))
    if e:
        errs["spoofed_ip_pool"] = e
    c["spoofed_ip_pool"] = pool or []
    peers, e = as_ip_list(data["allowed_peers"] if "allowed_peers" in data else cur.get("allowed_peers", []))
    if e:
        errs["allowed_peers"] = e
    c["allowed_peers"] = peers or []

    n = as_int(pick("data_port"), 1, 65535)
    if n is None:
        errs["data_port"] = "1-65535"
    c["data_port"] = n
    n = as_int(pick("icmp_id", 0 if tp == "tcp" else None), 0, 65535)
    if n is None:
        errs["icmp_id"] = "0-65535 (decimal or 0x...)"
    c["icmp_id"] = n
    n = as_int(pick("tunnel_count", 4), 1, 256)
    if n is None:
        errs["tunnel_count"] = "1-256"
    c["tunnel_count"] = n
    n = as_int(pick("mtu", 1380), 512, 1400)
    if n is None:
        errs["mtu"] = "512-1400"
    c["mtu"] = n
    try:
        w = float(pick("initial_cwnd", 10.0))
        if not (1 <= w <= 1000):
            raise ValueError
        c["initial_cwnd"] = w
    except (ValueError, TypeError):
        errs["initial_cwnd"] = "1-1000"
        c["initial_cwnd"] = None
    n = as_int(pick("max_retries", 8), 1, 100)
    if n is None:
        errs["max_retries"] = "1-100"
    c["max_retries"] = n
    n = as_int(pick("rto_min_ms", 200), 10, 60000)
    if n is None:
        errs["rto_min_ms"] = "10-60000"
    c["rto_min_ms"] = n
    ar = str(pick("auto_restart", "on-failure")).strip().lower()
    if ar not in ("no", "on-failure", "always"):
        errs["auto_restart"] = "no, on-failure or always"
        ar = "on-failure"
    c["auto_restart"] = ar
    n = as_int(pick("restart_sec", 5), 1, 3600)
    if n is None:
        errs["restart_sec"] = "1-3600"
    c["restart_sec"] = n

    if role == "client":
        n = as_int(pick("socks5_port", 1080), 1024, 65535)
        if n is None:
            errs["socks5_port"] = "1024-65535 (binds 127.0.0.1)"
        c["socks5_port"] = n

    if tp == "tcp":
        c["interface"] = str(pick("interface", "")).strip()   # ignored in tcp mode
    else:
        iface = str(pick("interface", "auto")).strip() or "auto"
        if not re.match(r"^[A-Za-z0-9_.:-]{1,15}$", iface):
            errs["interface"] = "interface name or 'auto'"
        elif iface == "auto":
            if "real_ip" in c:
                iface = detect_iface(c["real_ip"])
                if not iface:
                    errs["interface"] = "auto-detect failed (no local interface carries %s); choose one" % c["real_ip"]
        c["interface"] = iface

    key = data.get("pre_shared_key")
    if key is None or str(key).strip() == "":
        key = cur.get("pre_shared_key") or gen_key()
    key = str(key).strip()
    if not HEX_RE.match(key):
        errs["pre_shared_key"] = "hex string, at least 32 characters"
    c["pre_shared_key"] = key

    if c.get("spoofed_ip_pool") and c.get("spoofed_ip") and c["spoofed_ip"] not in c["spoofed_ip_pool"]:
        c["_warn"] = ["spoofed IP is not in the pool: when a pool is set only pool addresses are used"]

    if not errs:
        for o in instances():
            if o.name == self_name:
                continue
            oc = o.cfg()
            if oc.get("peer_real_ip") == c["peer_real_ip"] and (
                    oc.get("data_port") == c["data_port"] or oc.get("icmp_id") == c["icmp_id"]):
                errs["data_port"] = "tunnel '%s' already uses this peer with the same data port or ICMP ID" % o.name
            if role == "client" and oc.get("socks5_port") == c["socks5_port"]:
                errs["socks5_port"] = "SOCKS5 port already used by tunnel '%s'" % o.name
        if role == "client" and "socks5_port" not in errs:
            same = cur.get("socks5_port") == c["socks5_port"]
            if not same and port_listening(c["socks5_port"]):
                errs["socks5_port"] = "port %d is already in use" % c["socks5_port"]
    return c, errs


def peer_view(role, cfg):
    """Fields the opposite role needs to talk to this config (used for setup links)."""
    allowed = cfg.get("allowed_peers", [])
    opp_pool = ([cfg["peer_spoofed_ip"]] + [a for a in allowed if a != cfg["peer_spoofed_ip"]]) if allowed else []
    return {
        "role": "server" if role == "client" else "client",
        "transport": cfg.get("transport", "spoof"),
        "real_ip": cfg["peer_real_ip"], "peer_real_ip": cfg["real_ip"],
        "spoofed_ip": cfg["peer_spoofed_ip"], "peer_spoofed_ip": cfg["spoofed_ip"],
        "spoofed_ip_pool": opp_pool, "allowed_peers": cfg.get("spoofed_ip_pool", []),
        "data_port": cfg["data_port"], "icmp_id": cfg["icmp_id"],
        "tunnel_count": cfg.get("tunnel_count", 4), "mtu": cfg.get("mtu", 1380),
        "initial_cwnd": cfg.get("initial_cwnd", 10.0), "pre_shared_key": cfg["pre_shared_key"],
    }


def make_link(name, role, cfg):
    d = peer_view(role, cfg)
    d["v"] = 1
    d["name"] = name
    raw = json.dumps(d, separators=(",", ":")).encode()
    return "shadowspoof://" + base64.urlsafe_b64encode(raw).decode().rstrip("=")


def parse_link(link):
    s = link.strip()
    # Accept the new scheme and the legacy one (links from a candy-spoof install).
    for scheme in ("shadowspoof://", "candyspoof://"):
        if s.startswith(scheme):
            b = s[len(scheme):]
            break
    else:
        raise ValueError("not a shadowspoof:// link")
    b += "=" * (-len(b) % 4)
    d = json.loads(base64.urlsafe_b64decode(b.encode()))
    if d.get("v") != 1 or d.get("role") not in ("client", "server"):
        raise ValueError("unsupported link")
    return d


# ------------------------------------------------------------------- systemd --
PROPS = "Id,ActiveState,SubState,MainPID,NRestarts,ActiveEnterTimestampMonotonic,Result"


def systemd_show(units):
    if not units:
        return {}
    rc, out, _ = run([SYSTEMCTL, "show", "-p", PROPS] + list(units))
    res = {}
    for block in out.strip().split("\n\n"):
        d = {}
        for line in block.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                d[k] = v
        if d.get("Id"):
            res[d["Id"]] = d
    return res


def uptime_sec():
    try:
        return float(read_text("/proc/uptime").split()[0])
    except (IndexError, ValueError):
        return 0.0


def unit_status(inst, props):
    p = props.get(inst.unit, {})
    active = p.get("ActiveState", "unknown")
    mono = int(p.get("ActiveEnterTimestampMonotonic", "0") or 0)
    since = max(0, uptime_sec() - mono / 1e6) if active == "active" and mono else 0
    return {
        "active": active, "sub": p.get("SubState", ""), "pid": int(p.get("MainPID", "0") or 0),
        "restarts": int(p.get("NRestarts", "0") or 0), "uptime": int(since), "result": p.get("Result", ""),
    }


def ctl(*args):
    return run([SYSTEMCTL] + list(args), timeout=40)


# ------------------------------------------------------------------ log parse --
LEVEL_RE = re.compile(r"\b(ERROR|WARN|INFO|DEBUG|TRACE)\b")
KINDS = [
    ("connect", re.compile(r"SOCKS5 CONNECT")),
    ("forward", re.compile(r"forwarding to")),
    ("established", re.compile(r"tunnel \d+ established")),
    ("accepted", re.compile(r"tunnel \d+ accepted")),
    ("opened", re.compile(r"tunnel \d+ opened")),
    ("closed", re.compile(r"tunnel \d+ closed")),
    ("cc_timeout", re.compile(r"CC: timeout")),
    ("dup_acks", re.compile(r"dup-ACKs")),
    ("arq_drop", re.compile(r"exceeded max retries")),
    ("raw_error", re.compile(r"raw-send error|recvfrom")),
    ("session_error", re.compile(r"session error|handle_incoming|tick:")),
    ("start", re.compile(r"Shadow Spoof (client|server) starting")),
    ("listening", re.compile(r"SOCKS5 proxy listening")),
]
LEVEL_ORDER = {"TRACE": 0, "DEBUG": 1, "INFO": 2, "WARN": 3, "ERROR": 4}


def classify(msg, prio=6):
    m = LEVEL_RE.search(msg or "")
    if m:
        lvl = m.group(1)
    else:
        lvl = "ERROR" if prio <= 3 else ("WARN" if prio == 4 else "INFO")
    kind = ""
    for k, rx in KINDS:
        if rx.search(msg or ""):
            kind = k
            break
    return lvl, kind


def journal_entry(line):
    try:
        j = json.loads(line)
    except ValueError:
        return None
    msg = j.get("MESSAGE", "")
    if isinstance(msg, list):
        msg = bytes(msg).decode("utf-8", "replace")
    try:
        ts = int(j.get("__REALTIME_TIMESTAMP", "0")) / 1e6
    except ValueError:
        ts = 0
    try:
        prio = int(j.get("PRIORITY", 6))
    except ValueError:
        prio = 6
    unit = j.get("_SYSTEMD_UNIT", "")
    return ts, msg, prio, unit


def unit_to_name(unit):
    m = re.match(r"^shadow-spoof-(?:client|server)(?:@(.+))?\.service$", unit or "")
    if not m:
        return None
    return m.group(1) or "main"


def read_logs(inst, n=300, level=None, query=None, since=None):
    n = max(1, min(int(n), 2000))
    args = [JOURNALCTL, "-u", inst.unit, "-n", str(n), "--no-pager", "-q", "-o", "json"]
    if since:
        args += ["--since", "@%d" % int(since)]
    rc, out, err = run(args, timeout=20)
    rows = []
    minlvl = LEVEL_ORDER.get((level or "").upper(), 0) if level else 0
    q = (query or "").lower()
    for line in out.splitlines():
        e = journal_entry(line)
        if not e:
            continue
        ts, msg, prio, _ = e
        lvl, _k = classify(msg, prio)
        if LEVEL_ORDER[lvl] < minlvl:
            continue
        if q and q not in msg.lower():
            continue
        rows.append({"ts": ts, "level": lvl, "msg": msg})
    return rows


# -------------------------------------------------------------------- monitor --
def _hist():
    return {k: deque(maxlen=HIST_LEN) for k in ("cpu", "rss", "conns", "rx", "tx", "warn", "err")}


class Monitor(object):
    def __init__(self):
        self.hist = {}
        self.sys_hist = {"cpu": deque(maxlen=HIST_LEN), "mem": deque(maxlen=HIST_LEN)}
        self.prev_cpu = {}
        self.prev_sys = None
        self.prev_net = {}
        self.prev_state = {}
        self.window = deque()
        self.totals = defaultdict(lambda: defaultdict(int))
        self.last_est = {}
        self.throttle = {}
        self.suppressed = defaultdict(int)
        self.iface_cache = {}
        self.listen_alerted = set()
        self.events = deque(maxlen=200)
        self.clk = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
        os.makedirs(os.path.dirname(EVENTS_FILE), exist_ok=True)
        for line in read_text(EVENTS_FILE).splitlines()[-200:]:
            try:
                self.events.append(json.loads(line))
            except ValueError:
                pass

    # -- events
    def event(self, inst, level, msg, key=None):
        now = time.time()
        if key:
            last = self.throttle.get(key, 0)
            if now - last < 30:
                self.suppressed[key] += 1
                return
            self.throttle[key] = now
            extra = self.suppressed.pop(key, 0)
            if extra:
                msg += " (+%d similar in the last 30s)" % extra
        ev = {"ts": now, "inst": inst, "level": level, "msg": msg}
        self.events.append(ev)
        try:
            if os.path.exists(EVENTS_FILE) and os.path.getsize(EVENTS_FILE) > 1_000_000:
                keep = read_text(EVENTS_FILE).splitlines()[-300:]
                atomic_write(EVENTS_FILE, "\n".join(keep) + "\n", 0o640, SVC_USER, None)
            with open(EVENTS_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(ev) + "\n")
        except OSError:
            pass

    # -- system metrics
    def sys_metrics(self):
        s = {}
        try:
            parts = [int(x) for x in read_text("/proc/stat").splitlines()[0].split()[1:9]]
            idle, total = parts[3] + parts[4], sum(parts)
            if self.prev_sys:
                di, dt = idle - self.prev_sys[0], total - self.prev_sys[1]
                s["cpu"] = round(100.0 * (1 - di / dt), 1) if dt > 0 else 0.0
            else:
                s["cpu"] = 0.0
            self.prev_sys = (idle, total)
        except (ValueError, IndexError):
            s["cpu"] = 0.0
        mem = {}
        for line in read_text("/proc/meminfo").splitlines():
            k, _, v = line.partition(":")
            mem[k] = int(v.split()[0]) * 1024 if v.split() else 0
        tot = mem.get("MemTotal", 0)
        s["mem_total"], s["mem_used"] = tot, max(0, tot - mem.get("MemAvailable", 0))
        try:
            st = os.statvfs("/")
            s["disk_total"], s["disk_used"] = st.f_blocks * st.f_frsize, (st.f_blocks - st.f_bfree) * st.f_frsize
        except OSError:
            s["disk_total"] = s["disk_used"] = 0
        try:
            s["load"] = [float(x) for x in read_text("/proc/loadavg").split()[:3]]
        except ValueError:
            s["load"] = [0, 0, 0]
        s["uptime"] = int(uptime_sec())
        return s

    def net_rate(self, iface):
        rx = tx = None
        for line in read_text("/proc/net/dev").splitlines():
            if line.strip().startswith(iface + ":"):
                f = line.split(":", 1)[1].split()
                rx, tx = int(f[0]), int(f[8])
        if rx is None:
            return 0, 0
        now = time.time()
        prev = self.prev_net.get(iface)
        self.prev_net[iface] = (rx, tx, now)
        if not prev or now - prev[2] <= 0:
            return 0, 0
        dt = now - prev[2]
        return max(0, int((rx - prev[0]) / dt)), max(0, int((tx - prev[1]) / dt))

    def proc_metrics(self, pid):
        if pid <= 0:
            return 0.0, 0
        try:
            f = read_text("/proc/%d/stat" % pid).rsplit(")", 1)[1].split()
            ticks = int(f[11]) + int(f[12])
        except (IndexError, ValueError):
            return 0.0, 0
        now = time.time()
        prev = self.prev_cpu.get(pid)
        self.prev_cpu[pid] = (ticks, now)
        cpu = 0.0
        if prev and now > prev[1]:
            cpu = round(100.0 * (ticks - prev[0]) / self.clk / (now - prev[1]), 1)
        m = re.search(r"VmRSS:\s+(\d+)", read_text("/proc/%d/status" % pid))
        return cpu, (int(m.group(1)) * 1024 if m else 0)

    def conns(self, inst, cfg, pid):
        if inst.role == "client":
            p = cfg.get("socks5_port")
            if not p:
                return 0
            rc, out, _ = run([SS, "-H", "-tn", "state", "established", "( sport = :%d )" % p])
            return len([l for l in out.splitlines() if l.strip()])
        if pid <= 0:
            return 0
        rc, out, _ = run([SS, "-H", "-tnp", "state", "established"])
        return len([l for l in out.splitlines() if "pid=%d," % pid in l])

    # -- journal
    def read_journal(self, role):
        args = [JOURNALCTL, "--no-pager", "-q", "-o", "json", "--cursor-file", CURSOR_FILE,
                "-u", "shadow-spoof-%s.service" % role, "-u", "shadow-spoof-%s@*.service" % role]
        if not os.path.exists(CURSOR_FILE):
            args += ["--since", "-2min"]
        rc, out, _ = run(args, timeout=25)
        now = time.time()
        for line in out.splitlines():
            e = journal_entry(line)
            if not e:
                continue
            ts, msg, prio, unit = e
            name = unit_to_name(unit)
            if not name:
                continue
            lvl, kind = classify(msg, prio)
            self.window.append((ts or now, name, lvl, kind))
            if kind:
                self.totals[name][kind] += 1
            if kind in ("established", "accepted", "forward"):
                self.last_est[name] = ts or now
            if lvl in ("WARN", "ERROR"):
                self.event(name, "error" if lvl == "ERROR" else "warn", msg.strip()[:300], key=(name, kind or msg[:40]))
            elif kind in ("start", "listening"):
                self.event(name, "info", msg.strip()[:200])
        cutoff = now - 300
        while self.window and self.window[0][0] < cutoff:
            self.window.popleft()

    # -- one cycle
    def cycle(self):
        role = get_role()
        if not role:
            return
        insts = instances()
        props = systemd_show([i.unit for i in insts])
        self.read_journal(role)
        win = defaultdict(lambda: defaultdict(int))
        for ts, name, lvl, kind in self.window:
            win[name][lvl] += 1
            if kind:
                win[name]["k_" + kind] += 1

        sysm = self.sys_metrics()
        self.sys_hist["cpu"].append(sysm["cpu"])
        self.sys_hist["mem"].append(round(100.0 * sysm["mem_used"] / sysm["mem_total"], 1) if sysm["mem_total"] else 0)
        out = {}
        for inst in insts:
            cfg = inst.cfg()
            st = unit_status(inst, props)
            cpu, rss = self.proc_metrics(st["pid"])
            n_conn = self.conns(inst, cfg, st["pid"])
            iface = cfg.get("interface", "")
            if iface in ("", "auto") or not iface:
                iface = self.iface_cache.get(inst.name) or detect_iface(cfg.get("real_ip", "")) or ""
                self.iface_cache[inst.name] = iface
            rx, tx = self.net_rate(iface) if iface else (0, 0)
            listening = None
            if inst.role == "client" and cfg.get("socks5_port"):
                listening = port_listening(cfg["socks5_port"], True)
            w = win[inst.name]
            out[inst.name] = dict(st, unit=inst.unit, role=inst.role, cpu=cpu, rss=rss, conns=n_conn, iface=iface,
                                  rx=rx, tx=tx, listening=listening,
                                  log5={"info": w["INFO"], "warn": w["WARN"], "error": w["ERROR"]},
                                  totals=dict(self.totals[inst.name]), last_established=self.last_est.get(inst.name, 0))
            h = self.hist.setdefault(inst.name, _hist())
            for k, v in (("cpu", cpu), ("rss", rss), ("conns", n_conn), ("rx", rx), ("tx", tx),
                         ("warn", w["WARN"]), ("err", w["ERROR"])):
                h[k].append(v)

            prev = self.prev_state.get(inst.name)
            if prev:
                if prev["active"] != st["active"]:
                    lvl = "error" if st["active"] == "failed" else "info"
                    self.event(inst.name, lvl, "service %s -> %s%s" % (prev["active"], st["active"],
                               (" (%s)" % st["result"]) if st["result"] not in ("", "success") else ""))
                if st["restarts"] > prev["restarts"]:
                    self.event(inst.name, "warn", "automatic restart after failure (#%d)" % st["restarts"])
            self.prev_state[inst.name] = st
            if listening is False and st["active"] == "active" and st["uptime"] > 15:
                if inst.name not in self.listen_alerted:
                    self.listen_alerted.add(inst.name)
                    self.event(inst.name, "error", "service is active but SOCKS5 port %s is not listening" % cfg.get("socks5_port"))
            else:
                self.listen_alerted.discard(inst.name)
        for gone in set(self.hist) - set(i.name for i in insts):
            self.hist.pop(gone, None)
            self.prev_state.pop(gone, None)

        state = {
            "ts": time.time(), "role": role, "step": SAMPLE_SEC, "system": sysm, "instances": out,
            "history": {n: {k: list(v) for k, v in h.items()} for n, h in self.hist.items()},
            "sys_history": {k: list(v) for k, v in self.sys_hist.items()},
            "events": list(self.events)[-60:],
        }
        os.makedirs(RUN, exist_ok=True)
        atomic_write(STATE_JSON, json.dumps(state), 0o644, None, None)


def cmd_monitor():
    mon = Monitor()
    mon.event("-", "info", "monitor started")
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *a: stop.set())
    signal.signal(signal.SIGINT, lambda *a: stop.set())
    while not stop.is_set():
        t0 = time.time()
        try:
            mon.cycle()
        except Exception as e:  # never die: the watchdog-independent monitor must keep sampling
            sys.stderr.write("monitor cycle error: %r\n" % (e,))
        stop.wait(max(0.5, SAMPLE_SEC - (time.time() - t0)))


def load_state():
    try:
        return json.loads(read_text(STATE_JSON))
    except ValueError:
        return None


# ---------------------------------------------------------------- panel auth --
def hash_pw(password, salt=None, iters=200000):
    salt = salt or secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), iters).hex()
    return {"salt": salt, "iter": iters, "hash": h}


def check_pw(password, rec):
    try:
        h = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(rec["salt"]), int(rec["iter"])).hex()
    except (KeyError, ValueError):
        return False
    return hmac.compare_digest(h, rec.get("hash", ""))


def load_panel():
    try:
        return json.loads(read_text(PANEL_JSON))
    except ValueError:
        return {}


def save_panel(cfg):
    atomic_write(PANEL_JSON, json.dumps(cfg, indent=2) + "\n", 0o600)


SESSIONS = {}
SESS_LOCK = threading.Lock()
FAILS = {}


def new_session(ip):
    tok, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
    with SESS_LOCK:
        now = time.time()
        for k in [k for k, v in SESSIONS.items() if v["exp"] < now]:
            del SESSIONS[k]
        SESSIONS[tok] = {"csrf": csrf, "exp": now + 86400, "idle": now + 43200, "ip": ip}
    return tok, csrf


def get_session(tok):
    with SESS_LOCK:
        s = SESSIONS.get(tok)
        now = time.time()
        if not s or s["exp"] < now or s["idle"] < now:
            SESSIONS.pop(tok, None)
            return None
        s["idle"] = now + 43200
        return s


def locked_out(ip):
    f = FAILS.get(ip)
    return bool(f and f[0] >= 5 and time.time() - f[1] < 300)


def note_fail(ip):
    f = FAILS.get(ip)
    if not f or time.time() - f[1] > 300:
        FAILS[ip] = [1, time.time()]
    else:
        f[0] += 1
        f[1] = time.time()


# ------------------------------------------------------------------ API calls --
class ApiError(Exception):
    def __init__(self, status, msg, extra=None):
        Exception.__init__(self, msg)
        self.status, self.msg, self.extra = status, msg, extra or {}


def _inst_or_404(name):
    inst = find_inst(name)
    if not inst:
        raise ApiError(404, "no such tunnel")
    return inst


def describe(inst, props, st):
    cfg = inst.cfg()
    s = unit_status(inst, props)
    m = (st or {}).get("instances", {}).get(inst.name, {})
    d = {"name": inst.name, "unit": inst.unit, "role": inst.role, "config": redact(cfg)}
    d.update(s)
    for k in ("cpu", "rss", "conns", "iface", "rx", "tx", "listening", "log5", "totals", "last_established"):
        if k in m:
            d[k] = m[k]
    d["history"] = ((st or {}).get("history", {}) or {}).get(inst.name, {})
    return d


def api_overview(req):
    st = load_state()
    insts = instances()
    props = systemd_show([i.unit for i in insts])
    fresh = bool(st) and time.time() - st.get("ts", 0) < SAMPLE_SEC * 4
    wd = read_text(WATCHDOG_FILE).strip() or "off"
    return {
        "role": get_role(), "monitor_up": fresh,
        "system": (st or {}).get("system", {}), "sys_history": (st or {}).get("sys_history", {}),
        "tunnels": [describe(i, props, st if fresh else None) for i in insts],
        "events": ((st or {}).get("events") or [])[-30:], "watchdog": wd,
        "step": SAMPLE_SEC, "now": time.time(),
    }


def api_meta(req):
    info = {}
    for line in read_text(BUILD_INFO).splitlines():
        k, _, v = line.partition("=")
        info[k] = v
    return {"role": get_role(), "detect_ip": detect_ip(), "ifaces": list_ifaces(), "build": info,
            "tls": bool(load_panel().get("tls")), "defaults": {"transport": "spoof", "data_port": 51820, "tunnel_count": 4, "mtu": 1380,
                                                              "initial_cwnd": 10, "socks5_port": 1080,
                                                              "max_retries": 8, "rto_min_ms": 200, "auto_restart": "on-failure", "restart_sec": 5,
                                                              "icmp_id": secrets.randbelow(65536)}}


def api_keygen(req):
    return {"key": gen_key()}


def _write_inst(inst, role, clean, note):
    atomic_write(inst.path, render_config(role, clean, note), 0o640, SVC_USER)
    if inst.name == "main":
        atomic_write(PSK_FILE, clean["pre_shared_key"] + "\n", 0o600)


def api_create(req):
    role = get_role()
    if not role:
        raise ApiError(409, "not installed")
    d = req.json
    name = str(d.get("name", "")).strip().lower()
    if not NAME_RE.match(name) or name == "main":
        raise ApiError(400, "invalid name", {"errors": {"name": "a-z 0-9 and '-', max 24 chars, not 'main'"}})
    if os.path.exists(os.path.join(TUNNELS, name + ".toml")):
        raise ApiError(409, "a tunnel with this name already exists", {"errors": {"name": "already exists"}})
    if not os.path.exists(os.path.join(UNIT_DIR, "shadow-spoof-%s@.service" % role)):
        raise ApiError(409, "template unit missing - re-run install.sh to upgrade")
    clean, errs = validate(role, d, name)
    if errs:
        raise ApiError(400, "validation failed", {"errors": errs})
    warn = clean.pop("_warn", [])
    inst = Inst(name, role, os.path.join(TUNNELS, name + ".toml"))
    os.makedirs(TUNNELS, exist_ok=True)
    _write_inst(inst, role, clean, "created from the panel %s" % time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    _apply_autorestart(inst, clean)
    rc, out, err = ctl("enable", "--now", inst.unit)
    time.sleep(1.5)
    st = unit_status(inst, systemd_show([inst.unit]))
    cfg = inst.cfg()
    return {"ok": True, "name": name, "active": st["active"], "warnings": warn,
            "note": (err or out).strip()[:300] if rc else "", "key": cfg["pre_shared_key"],
            "fp": fingerprint(cfg["pre_shared_key"]), "link": make_link(name, role, cfg)}


def check_config_file(role, path):
    """Validate a config file with the role binary's own parser (--check-config).

    Returns (ok, detail).  ok is True when the parser accepts the file, and also
    when the installed binary predates --check-config (so we never block on an
    older build).  This catches drift between the panel validator and the Rust
    parser before the service is (re)started."""
    binp = "/usr/local/bin/shadow-spoof-%s" % role
    if not os.access(binp, os.X_OK):
        return True, ""
    rc, out, err = run([binp, "--config", path, "--check-config"], timeout=10)
    detail = ((out or "") + (err or "")).strip()
    if rc == 0:
        return True, detail
    if rc == 2 and "check-config" in detail:   # older binary without the flag
        return True, ""
    return False, detail


def _apply_autorestart(inst, c):
    """Per-tunnel systemd Restart=/RestartSec= drop-in from the config fields."""
    mode, sec = c.get("auto_restart"), c.get("restart_sec")
    if not mode or not sec:
        return
    try:
        d = os.path.join(UNIT_DIR, inst.unit + ".d")
        os.makedirs(d, exist_ok=True)
        atomic_write(os.path.join(d, "20-autorestart.conf"),
                     "[Service]\nRestart=%s\nRestartSec=%d\n" % (mode, int(sec)), 0o644)
        ctl("daemon-reload")
    except OSError as e:
        sys.stderr.write("auto-restart drop-in failed for %s: %s\n" % (inst.name, e))


def apply_edit(inst, data, note="edited"):
    """Validate + write + restart with automatic rollback. Returns (active, warnings)."""
    cur = inst.cfg()
    clean, errs = validate(inst.role, data, inst.name, cur)
    if errs:
        raise ApiError(400, "validation failed", {"errors": errs})
    warn = clean.pop("_warn", [])
    old_conf, old_psk = read_text(inst.path), read_text(PSK_FILE)
    _write_inst(inst, inst.role, clean, "%s %s" % (note, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())))
    # Gate on the binary's own parser before touching the running service, so a
    # config the parser rejects is reverted without a failed restart cycle.
    ok_cfg, detail = check_config_file(inst.role, inst.path)
    if not ok_cfg:
        atomic_write(inst.path, old_conf, 0o640, SVC_USER)
        if inst.name == "main" and old_psk:
            atomic_write(PSK_FILE, old_psk, 0o600)
        raise ApiError(400, "the configuration parser rejected the new settings; reverted",
                       {"detail": detail[:500]})
    _apply_autorestart(inst, clean)
    was_active = unit_status(inst, systemd_show([inst.unit]))["active"] == "active"
    ctl("try-restart", inst.unit)
    time.sleep(2.0)
    st = unit_status(inst, systemd_show([inst.unit]))
    if was_active and st["active"] != "active":
        atomic_write(inst.path, old_conf, 0o640, SVC_USER)
        if inst.name == "main" and old_psk:
            atomic_write(PSK_FILE, old_psk, 0o600)
        ctl("restart", inst.unit)
        raise ApiError(409, "service did not come back with the new settings; reverted")
    return st["active"], warn


def api_edit(req, name):
    inst = _inst_or_404(name)
    active, warn = apply_edit(inst, req.json, "edited from the panel")
    return {"ok": True, "warnings": warn, "active": active, "peer": _maybe_push_peer(inst)}


def api_action(req, name, action):
    inst = _inst_or_404(name)
    if action not in ("start", "stop", "restart"):
        raise ApiError(404, "unknown action")
    rc, out, err = ctl(action, inst.unit)
    if rc:
        raise ApiError(500, (err or out or "systemctl failed").strip()[:300])
    time.sleep(1.0)
    return {"ok": True, "active": unit_status(inst, systemd_show([inst.unit]))["active"]}


def api_delete(req, name):
    if name == "main":
        raise ApiError(400, "the main tunnel cannot be deleted from the panel")
    inst = _inst_or_404(name)
    ctl("disable", "--now", inst.unit)
    try:
        os.unlink(inst.path)
    except OSError:
        pass
    ctl("reset-failed", inst.unit)
    return {"ok": True}


def api_secret(req, name):
    pw = str(req.json.get("password", ""))
    if not check_pw(pw, load_panel().get("pw", {})):
        raise ApiError(403, "wrong password")
    inst = _inst_or_404(name)
    cfg = inst.cfg()
    return {"key": cfg.get("pre_shared_key", ""), "fp": fingerprint(cfg.get("pre_shared_key", "")),
            "link": make_link(name, inst.role, cfg), "peer": peer_view(inst.role, cfg)}


def api_link_parse(req):
    try:
        d = parse_link(str(req.json.get("link", "")))
    except Exception as e:
        raise ApiError(400, "invalid link: %s" % e)
    role = get_role()
    if d["role"] != role:
        raise ApiError(400, "this link is meant for a %s host, but this host is a %s" % (d["role"], role))
    d.pop("role", None)
    d.pop("v", None)
    return {"fields": d}


def api_logs(req, name):
    inst = _inst_or_404(name)
    q = req.query
    rows = read_logs(inst, q.get("n", ["300"])[0], q.get("level", [None])[0], q.get("q", [None])[0],
                     q.get("since", [None])[0])
    return {"rows": rows}


def api_tunnel_ping(req, name):
    """Reachability of the other end: ICMP RTT, TCP connect time (tcp transport,
    client side) and - when panels are paired - the peer panel round trip."""
    inst = _inst_or_404(name)
    cfg = inst.cfg()
    peer = cfg.get("peer_real_ip")
    out = {"peer": peer, "ping_ms": None, "tcp_ms": None, "peer_panel": None}
    if peer and v_ip(peer):
        rc, o, _ = run(["ping", "-c", "1", "-W", "1", peer], timeout=4)
        m = re.search(r"time[=<]\s*([\d.]+)\s*ms", o or "")
        if rc == 0 and m:
            out["ping_ms"] = round(float(m.group(1)), 1)
        if str(cfg.get("transport", "spoof")).lower() == "tcp" and inst.role == "client" and cfg.get("data_port"):
            t0 = time.time()
            try:
                socket.create_connection((peer, int(cfg["data_port"])), timeout=2).close()
                out["tcp_ms"] = round((time.time() - t0) * 1000, 1)
            except OSError:
                pass
    p = load_panel()
    if p.get("peer_url") and p.get("sync_token"):
        t0 = time.time()
        try:
            _peer_request("GET", "/api/sync/overview", timeout=3)
            out["peer_panel"] = {"ok": True, "ms": round((time.time() - t0) * 1000)}
        except ApiError as e:
            out["peer_panel"] = {"ok": False, "error": e.msg}
    return out


def api_tunnel_link(req, name):
    # The setup link embeds the pre-shared key; it is returned to the already
    # authenticated session without a second password prompt (convenience for
    # copying links / MTU setup).
    inst = _inst_or_404(name)
    cfg = inst.cfg()
    return {"link": make_link(inst.name, inst.role, cfg), "fp": fingerprint(cfg.get("pre_shared_key", ""))}


MAGIC = b"\xca\xfe\x5f\x00"


def sniff(cfg, seconds, stop=None):
    """Passively count Shadow Spoof packets arriving at this host (raw sockets, needs root)."""
    import select
    allowed = set([cfg.get("peer_real_ip"), cfg.get("peer_spoofed_ip")] + list(cfg.get("allowed_peers") or []))
    icmp_id, port = cfg.get("icmp_id"), cfg.get("data_port")
    res = {"icmp": defaultdict(int), "udp": defaultdict(int), "blocked": defaultdict(int), "other_id": defaultdict(int)}
    try:
        socks = [socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP),
                 socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)]
    except (PermissionError, OSError) as e:
        return {"error": "cannot open raw sockets (%s)" % e}
    deadline = time.time() + seconds
    try:
        while time.time() < deadline and not (stop and stop.is_set()):
            r, _, _ = select.select(socks, [], [], 0.4)
            for s in r:
                data, addr = s.recvfrom(65535)
                src = addr[0]
                if len(data) < 28:
                    continue
                ihl = (data[0] & 0x0F) * 4
                l4 = data[ihl:]
                if data[9] == 1 and len(l4) >= 8 and l4[0] in (0, 8):
                    pid, payload, bucket = struct.unpack("!H", l4[4:6])[0], l4[8:], "icmp"
                    right = pid == icmp_id
                elif data[9] == 17 and len(l4) >= 8:
                    payload, bucket = l4[8:], "udp"
                    pid = None
                    right = struct.unpack("!H", l4[2:4])[0] == port
                else:
                    continue
                if payload[:4] != MAGIC:
                    continue  # unrelated traffic
                if not right:
                    if src in allowed and pid is not None:
                        res["other_id"][pid] += 1
                elif src in allowed:
                    res[bucket][src] += 1
                else:
                    res["blocked"][src] += 1
    finally:
        for s in socks:
            s.close()
    return {k: dict(v) for k, v in res.items()}


def sniff_steps(cfg, sn, peer_word):
    steps = []
    if "error" in sn:
        return [{"ok": None, "title": "Packet capture", "detail": sn["error"]}]
    ok_icmp, ok_udp = sum(sn["icmp"].values()), sum(sn["udp"].values())
    if ok_icmp + ok_udp:
        steps.append({"ok": True, "title": "Packets from the %s reach this host" % peer_word,
                      "detail": "ICMP %d, UDP %d (from %s)" % (ok_icmp, ok_udp, ", ".join(sorted(set(sn["icmp"]) | set(sn["udp"]))))})
    else:
        steps.append({"ok": False, "title": "No packets from the %s reached this host" % peer_word,
                      "detail": "Check: peer service running, firewall allows UDP/%s + ICMP echo, rp_filter, and that the "
                                "peer's spoofed/real IPs match this config." % cfg.get("data_port")})
    for src, n in sn["blocked"].items():
        steps.append({"ok": False, "title": "Shadow Spoof packets from %s are being dropped" % src,
                      "detail": "%d packets with the right port/ID arrived from %s, which is not in the allowed list. "
                                "Add it to 'peer spoofed IP pool' (allowed_peers) or fix peer_spoofed_ip." % (n, src)})
    for pid, n in sn["other_id"].items():
        steps.append({"ok": False, "title": "ICMP ID mismatch",
                      "detail": "the peer sends Shadow Spoof packets with ICMP ID %d (%d seen) but this config expects %s" % (pid, n, cfg.get("icmp_id"))})
    return steps


def recv_n(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def socks_probe(sport, host, port, http):
    t0 = time.time()
    s = socket.create_connection(("127.0.0.1", sport), timeout=4)
    s.settimeout(25)
    s.sendall(b"\x05\x01\x00")
    if recv_n(s, 2) != b"\x05\x00":
        raise IOError("SOCKS5 negotiation failed")
    hb = host.encode()
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + struct.pack(">H", port))
    rep = recv_n(s, 10)
    hs_ms = (time.time() - t0) * 1000
    if len(rep) < 2 or rep[1] != 0:
        s.close()
        raise IOError("tunnel handshake failed (SOCKS reply %s) - the server did not answer the SYN" % (rep[1] if len(rep) > 1 else "none"))
    if not http:
        s.close()
        return hs_ms, None
    sock = s
    if port == 443:
        sock = ssl.create_default_context().wrap_socket(s, server_hostname=host)
    sock.sendall(("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: shadow-spoof-test\r\nConnection: close\r\n\r\n" % host).encode())
    t1 = time.time()
    first = sock.recv(4096)
    ttfb = (time.time() - t1) * 1000
    total = len(first)
    sock.settimeout(8)
    try:
        while total < 200000:
            c = sock.recv(65536)
            if not c:
                break
            total += len(c)
    except (socket.timeout, OSError):
        pass
    sock.close()
    if not first:
        raise IOError("handshake OK but no data came back - the server could not reach %s:%d, or the return data path is broken" % (host, port))
    line = first.split(b"\r\n", 1)[0][:60].decode("latin-1")
    return hs_ms, {"ttfb_ms": round(ttfb, 1), "bytes": total, "status": line, "total_ms": round((time.time() - t0) * 1000, 1)}


def run_test(inst, host="example.com", port=80, secs=10):
    cfg = inst.cfg()
    st = unit_status(inst, systemd_show([inst.unit]))
    steps = [{"ok": st["active"] == "active", "title": "Service %s" % inst.unit,
              "detail": "%s, up %ds, %d auto-restarts" % (st["active"], st["uptime"], st["restarts"])}]
    if st["active"] != "active":
        return {"steps": steps, "verdict": "fail", "summary": "service is not running"}
    if inst.role == "client":
        sp = cfg.get("socks5_port", 0)
        listening = port_listening(sp, True)
        steps.append({"ok": listening, "title": "SOCKS5 listening on 127.0.0.1:%s" % sp, "detail": ""})
        if not listening:
            return {"steps": steps, "verdict": "fail", "summary": "SOCKS5 port not listening"}
        stop = threading.Event()
        box = {}
        th = threading.Thread(target=lambda: box.update(sn=sniff(cfg, 60, stop)), daemon=True)
        th.start()
        time.sleep(0.4)
        hs = []
        for i in range(3):
            try:
                ms, _ = socks_probe(sp, host, port, False)
                hs.append(ms)
            except Exception as e:
                steps.append({"ok": False, "title": "Tunnel handshake #%d" % (i + 1), "detail": str(e)})
            time.sleep(0.3)
        if hs:
            steps.append({"ok": True, "title": "Tunnel handshake (SYN/SYN-ACK through the spoofed path)",
                          "detail": "%d/3 OK, avg %.0f ms - control packets pass in BOTH directions" % (len(hs), sum(hs) / len(hs))})
        data_ok = False
        if hs:
            try:
                _, info = socks_probe(sp, host, port, True)
                data_ok = True
                steps.append({"ok": True, "title": "Data through the tunnel (HTTP%s to %s:%d)" % ("S" if port == 443 else "", host, port),
                              "detail": "%s - first byte %.0f ms, %d bytes in %.0f ms" % (info["status"], info["ttfb_ms"], info["bytes"], info["total_ms"])})
            except Exception as e:
                steps.append({"ok": False, "title": "Data through the tunnel (%s:%d)" % (host, port), "detail": str(e)})
        time.sleep(1.0)
        stop.set()
        th.join(3)
        for st2 in sniff_steps(cfg, box.get("sn", {"error": "capture did not run"}), "server"):
            if hs and st2["ok"] is False and st2["title"].startswith("No packets"):
                st2 = {"ok": None, "title": "Packet capture saw nothing",
                       "detail": "the handshake worked, so packets do flow; the local capture may be restricted on this host"}
            steps.append(st2)
        verdict = "ok" if (hs and data_ok) else ("warn" if hs else "fail")
        summary = {"ok": "Tunnel is up and packets pass in both directions.",
                   "warn": "Handshake works but data did not come back.",
                   "fail": "Tunnel handshake failed: nothing came back from the server."}[verdict]
        return {"steps": steps, "verdict": verdict, "summary": summary}
    # server: passive listen + log evidence
    rows = read_logs(inst, 1000, None, None, time.time() - 600)
    acc = len([r for r in rows if "accepted from" in r["msg"]])
    fwd = len([r for r in rows if "forwarding to" in r["msg"]])
    steps.append({"ok": acc > 0, "title": "Tunnels accepted in the last 10 minutes",
                  "detail": "%d accepted, %d forwarded to a target%s" % (acc, fwd, "" if acc else " (none yet)")})
    steps.append({"ok": None, "title": "Listening for %ds" % secs,
                  "detail": "Run the test on the CLIENT now (shadowtun test) so packets flow while this captures."})
    sn = sniff(cfg, secs)
    steps += sniff_steps(cfg, sn, "client")
    good = "error" not in sn and (sum(sn["icmp"].values()) + sum(sn["udp"].values()) > 0)
    return {"steps": steps, "verdict": "ok" if good else ("warn" if acc else "fail"),
            "summary": "Client packets are arriving." if good else
                       ("No client packets during the capture window (the client may have been idle)." if acc else
                        "No client packets arrived.")}


def api_test(req, name):
    inst = _inst_or_404(name)
    host = str(req.json.get("host", "example.com")).strip()
    port = as_int(req.json.get("port", 80), 1, 65535)
    secs = as_int(req.json.get("secs", 10), 3, 30) or 10
    if not re.match(r"^[A-Za-z0-9.-]{1,253}$", host) or not port:
        raise ApiError(400, "invalid host/port")
    return run_test(inst, host, port, secs)


def api_health(req):
    role = get_role()
    checks = []

    def add(level, title, hint=""):
        checks.append({"level": level, "title": title, "hint": hint})

    if not role:
        add("fail", "Not installed", "run install.sh")
        return {"checks": checks}
    binp = "/usr/local/bin/shadow-spoof-%s" % role
    add("ok" if os.access(binp, os.X_OK) else "fail", "Binary %s" % binp)
    add("ok" if os.path.exists(os.path.join(UNIT_DIR, "shadow-spoof-%s@.service" % role)) else "warn",
        "Template unit for panel-created tunnels", "re-run install.sh to add it")
    rc, out, _ = run([SYSTEMCTL, "show", "-p", "AmbientCapabilities,User", "shadow-spoof-%s.service" % role])
    add("ok" if "cap_net_raw" in out.lower() else "warn", "Service has CAP_NET_RAW (needed for raw sockets)")
    mon = systemd_show(["shadow-spoof-monitor.service"]).get("shadow-spoof-monitor.service", {})
    add("ok" if mon.get("ActiveState") == "active" else "warn", "Monitor service", "systemctl start shadow-spoof-monitor")
    for name in ("all", "default"):
        v = read_text("/proc/sys/net/ipv4/conf/%s/rp_filter" % name).strip()
        if v == "1":
            add("warn", "rp_filter=1 on '%s'" % name,
                "strict reverse-path filtering can drop packets whose spoofed source is not routed via the arrival interface")
    props = systemd_show([i.unit for i in instances()])
    for inst in instances():
        cfg = inst.cfg()
        tag = "[%s] " % inst.name
        st = unit_status(inst, props)
        add("ok" if st["active"] == "active" else "fail", tag + "service %s" % st["active"])
        missing = [k for k in ("real_ip", "peer_real_ip", "spoofed_ip", "peer_spoofed_ip", "data_port", "icmp_id",
                               "pre_shared_key", "interface") if k not in cfg]
        add("ok" if not missing else "fail", tag + "config has all required fields", ", ".join(missing))
        if cfg.get("interface") and not os.path.exists("/sys/class/net/%s" % cfg["interface"]):
            add("fail", tag + "interface '%s' not found" % cfg["interface"],
                "raw sockets are bound to this interface (SO_BINDTODEVICE); the service fails to start until it exists")
        ok_cfg, detail = check_config_file(inst.role, inst.path)
        if not ok_cfg:
            add("fail", tag + "config rejected by the parser", (detail or "")[:200])
        pool = cfg.get("spoofed_ip_pool") or []
        if pool and cfg.get("spoofed_ip") not in pool:
            add("warn", tag + "spoofed IP is not in the pool", "with a pool set, only pool addresses are used")
        if inst.role == "client" and st["active"] == "active":
            ok = port_listening(cfg.get("socks5_port", 0), True)
            add("ok" if ok else "fail", tag + "SOCKS5 listening on 127.0.0.1:%s" % cfg.get("socks5_port"))
    add("ok", "pre_shared_key authenticates every packet (HMAC-SHA256)",
        "both sides must share the identical key; packets failing authentication are dropped")
    return {"checks": checks}


_DIAG_FIELDS = ("pre_shared_key", "data_port", "socks5_port", "interface", "tunnel_count",
                "rto_min_ms", "max_retries", "mtu", "initial_cwnd", "icmp_id",
                "real_ip", "peer_real_ip", "spoofed_ip", "peer_spoofed_ip")


def _parser_field(detail):
    """Best-effort: pull the offending field name out of a parser error."""
    for f in _DIAG_FIELDS:
        if f in (detail or ""):
            return f
    return ""


def api_diagnose(req):
    """Tunnel-path doctor. Optional body {name, link}.

    Walks the whole path a tunnel depends on - config validity, config
    self-consistency, the kernel/interface environment that spoofed packets
    need, service state, peer reachability - and, when the operator pastes the
    OTHER host's setup link, compares the two configs field by field. Each
    finding names the config field at fault and how to fix it, so a failed
    setup points straight at the wrong setting instead of a raw log."""
    role = get_role()
    if not role:
        raise ApiError(409, "not installed")
    body = req.json if isinstance(req.json, dict) else {}
    name = str(body.get("name", "main")).strip() or "main"
    inst = _inst_or_404(name)
    cfg = inst.cfg()
    tcp = str(cfg.get("transport", "spoof")).lower() == "tcp"

    F = []

    def add(level, field, title, detail="", fix=""):
        F.append({"level": level, "field": field or "", "title": title,
                  "detail": detail or "", "fix": fix or ""})

    def safe(fn):
        try:
            fn()
        except Exception as e:                       # one broken probe must not abort the report
            add("warn", "", "a diagnostic check could not run", str(e))

    # 1 - does the binary's own parser accept the file? -----------------------
    def c_parser():
        ok, detail = check_config_file(role, inst.path)
        if ok:
            add("ok", "", "config is accepted by the %s parser" % role)
        else:
            add("fail", _parser_field(detail), "config rejected by the parser", detail,
                "fix the field named above and save")
    safe(c_parser)

    # 2 - config self-consistency --------------------------------------------
    def c_consistency():
        if cfg.get("real_ip") and cfg.get("real_ip") == cfg.get("peer_real_ip"):
            add("fail", "peer_real_ip", "real_ip and peer_real_ip are identical",
                "both ends are set to the same real address",
                "peer_real_ip must be the OTHER host's real IP")
        if not tcp and cfg.get("spoofed_ip") and cfg.get("spoofed_ip") == cfg.get("peer_spoofed_ip"):
            add("fail", "peer_spoofed_ip", "spoofed_ip and peer_spoofed_ip are identical",
                "each side must forge a different source address",
                "set peer_spoofed_ip to the source the peer forges (its spoofed_ip)")
        pool = cfg.get("spoofed_ip_pool") or []
        if not tcp and pool and cfg.get("spoofed_ip") not in pool:
            add("warn", "spoofed_ip_pool", "spoofed_ip is not in spoofed_ip_pool",
                "when a pool is set only pool addresses are used",
                "add spoofed_ip to the pool, or clear the pool")
    safe(c_consistency)

    # 3 - interface the raw sockets bind to (spoof mode only) -----------------
    def c_iface():
        if tcp:
            add("ok", "transport", "transport=tcp (standard socket; no raw sockets / spoofing)")
            return
        iface = cfg.get("interface") or ""
        if not iface:
            add("fail", "interface", "interface is empty",
                "raw sockets must bind to a device", "set interface to a real NIC (see: ip link)")
            return
        if not os.path.exists("/sys/class/net/%s" % iface):
            add("fail", "interface", "interface '%s' does not exist" % iface,
                "raw sockets are bound to it (SO_BINDTODEVICE); the service fails to start",
                "set interface to a device that exists (ip -o link)")
            return
        add("ok", "interface", "interface '%s' exists" % iface)
        det = detect_iface(cfg.get("real_ip", "")) if cfg.get("real_ip") else ""
        if det and det != iface:
            add("warn", "interface", "interface '%s' does not carry real_ip %s" % (iface, cfg.get("real_ip")),
                "real_ip %s is on '%s'" % (cfg.get("real_ip"), det),
                "usually interface should be the device that owns real_ip")
    safe(c_iface)

    # 4 - reverse-path filtering drops spoofed-source packets ------------------
    def c_rpfilter():
        if tcp:
            return
        iface = cfg.get("interface") or "all"
        for scope in dict.fromkeys(["all", iface]):
            v = read_text("/proc/sys/net/ipv4/conf/%s/rp_filter" % scope).strip()
            if v == "1":
                add("fail", "interface", "rp_filter=1 on '%s'" % scope,
                    "strict reverse-path filtering drops packets whose spoofed source is not routed back via the arrival interface - the most common silent tunnel failure",
                    "on BOTH ends: sysctl -w net.ipv4.conf.%s.rp_filter=2 (loose), and persist it" % scope)
    safe(c_rpfilter)

    # 5 - capability + service state ------------------------------------------
    def c_service():
        if not tcp:
            rc, out, _ = run([SYSTEMCTL, "show", "-p", "AmbientCapabilities", inst.unit])
            if "cap_net_raw" not in (out or "").lower():
                add("fail", "", "service is missing CAP_NET_RAW",
                    "raw sockets cannot be opened without it", "re-run install.sh to repair the unit")
        st = unit_status(inst, systemd_show([inst.unit]))
        if st.get("active") == "active":
            add("ok", "", "service is active")
        else:
            add("fail", "", "service is %s" % st.get("active", "unknown"),
                "the process is not running", "shadowtun start, then shadowtun logs -f")
        if role == "client" and st.get("active") == "active":
            p = cfg.get("socks5_port", 0)
            if port_listening(p, True):
                add("ok", "socks5_port", "SOCKS5 is listening on 127.0.0.1:%s" % p)
            else:
                add("fail", "socks5_port", "SOCKS5 is not listening on 127.0.0.1:%s" % p,
                    "the client proxy never bound - initialisation did not complete",
                    "check shadowtun logs; another process may hold the port")
    safe(c_service)

    # 6 - can we even reach the peer's real IP? -------------------------------
    def c_reach():
        peer = cfg.get("peer_real_ip")
        if not peer:
            return
        rc, out, err = run(["ping", "-c", "1", "-W", "1", peer], timeout=4)
        if rc == 0:
            add("ok", "peer_real_ip", "peer %s answers ICMP" % peer)
        else:
            add("warn", "peer_real_ip", "peer %s did not answer ICMP" % peer,
                "the peer may be down or ICMP may be filtered (the tunnel can still work if the data path is open)",
                "verify the peer host is up and reachable from here")
    safe(c_reach)

    # 7 - cross-check against the peer's setup link (the decisive check) -------
    link = str(body.get("link", "")).strip()
    if link:
        def c_peer():
            try:
                d = parse_link(link)
            except Exception as e:
                add("fail", "", "could not read the pasted link", str(e),
                    "paste the shadowspoof:// link generated on the OTHER host")
                return
            if d.get("role") != role:
                add("fail", "", "this link is for a %s host, but this host is a %s" % (d.get("role"), role),
                    "the link must be generated on the peer (the opposite role)", "")
                return
            # Symmetric fields - any difference is definitely wrong.
            sym = ["data_port"] + ([] if tcp else ["icmp_id"])
            for k in sym:
                if d.get(k) is not None and str(d.get(k)) != str(cfg.get(k)):
                    add("fail", k, "%s does not match the peer" % k,
                        "peer uses %s, this host has %s" % (d.get(k), cfg.get(k)),
                        "set %s = %s to match the peer" % (k, d.get(k)))
            if d.get("pre_shared_key") and cfg.get("pre_shared_key"):
                if fingerprint(d["pre_shared_key"]) != fingerprint(cfg["pre_shared_key"]):
                    add("fail", "pre_shared_key", "pre_shared_key does not match the peer",
                        "key fingerprints differ (peer %s vs here %s)" % (
                            fingerprint(d["pre_shared_key"]), fingerprint(cfg["pre_shared_key"])),
                        "re-import the peer link, or copy the peer's key exactly")
                else:
                    add("ok", "pre_shared_key", "pre_shared_key matches the peer")
            # Addressing - the link is already oriented for this host, so its
            # values are exactly what this host should have.
            addr = ["real_ip", "peer_real_ip"] + ([] if tcp else ["spoofed_ip", "peer_spoofed_ip"])
            for k in addr:
                if d.get(k) and str(d.get(k)) != str(cfg.get(k)):
                    add("fail", k, "%s does not match the peer's link" % k,
                        "peer link expects %s, this host has %s" % (d.get(k), cfg.get(k)),
                        "set %s = %s (or re-import the link)" % (k, d.get(k)))
        safe(c_peer)
    else:
        add("info", "", "paste the peer's setup link above for a full two-sided check",
            "most setup failures are a client/server mismatch (ports, ICMP id, key, or the spoofed-IP pairing)", "")

    summary = {"ok": 0, "warn": 0, "fail": 0, "info": 0}
    for f in F:
        summary[f["level"]] = summary.get(f["level"], 0) + 1
    return {"findings": F, "summary": summary, "checked": name}


def api_settings_get(req):
    p = load_panel()
    return {"watchdog": read_text(WATCHDOG_FILE).strip() or "off", "bind": p.get("bind"), "port": p.get("port"),
            "tls": bool(p.get("tls"))}


def api_watchdog(req):
    v = str(req.json.get("value", ""))
    if v not in ("off", "30m", "1h", "6h", "12h", "24h"):
        raise ApiError(400, "invalid value")
    rc, out, err = run([CTL, "watchdog", v], timeout=30)
    if rc:
        raise ApiError(500, (err or out).strip()[:300])
    return {"ok": True, "watchdog": v}


def api_password(req):
    old, new = str(req.json.get("old", "")), str(req.json.get("new", ""))
    p = load_panel()
    if not check_pw(old, p.get("pw", {})):
        raise ApiError(403, "wrong current password")
    if len(new) < 10:
        raise ApiError(400, "new password must be at least 10 characters")
    p["pw"] = hash_pw(new)
    save_panel(p)
    with SESS_LOCK:
        keep = req.token
        for k in [k for k in SESSIONS if k != keep]:
            del SESSIONS[k]
    return {"ok": True}


def api_mtu(req):
    """Path-MTU probe to the peer (DF-set ICMP, binary search) + a recommended
    tunnel mtu.  Linux only (uses `ping -M do`)."""
    inst = _inst_or_404(str((req.json or {}).get("name", "main")))
    cfg = inst.cfg()
    peer = cfg.get("peer_real_ip")
    if not peer or not v_ip(peer):
        raise ApiError(400, "no valid peer_real_ip configured")

    def fits(payload):
        rc, _o, _e = run(["ping", "-M", "do", "-s", str(payload), "-c", "1", "-W", "1", peer], timeout=4)
        return rc == 0

    lo, hi = 500, 1472  # ICMP payload; +28 (IP20+ICMP8) = MTU; 1472 -> 1500
    if not fits(lo):
        raise ApiError(502, "no DF-ping reply from %s - is it reachable and is ICMP allowed through?" % peer)
    best = lo
    while lo <= hi:
        mid = (lo + hi) // 2
        if fits(mid):
            best = mid; lo = mid + 1
        else:
            hi = mid - 1
    path_mtu = best + 28
    # Tunnel overhead (spoof/UDP): IP20 + UDP8 + ShadowPacket header20 + HMAC16.
    overhead = 64
    recommended = max(512, min(1400, path_mtu - overhead))
    return {"peer": peer, "path_mtu": path_mtu, "recommended_mtu": recommended,
            "current_mtu": cfg.get("mtu"), "overhead": overhead}


def _restart_panel_soon():
    # Return the HTTP response first, then restart (which kills this process).
    threading.Timer(1.0, lambda: run([CTL, "panel", "restart"], timeout=30)).start()


def api_panel_cfg(req):
    """Change the panel's own bind address / port / TLS, then restart it.
    The caller will have to reconnect on the new address."""
    d = req.json if isinstance(req.json, dict) else {}
    p = load_panel()
    changed = []
    if "port" in d:
        n = as_int(d.get("port"), 1, 65535)
        if not n:
            raise ApiError(400, "port must be 1-65535")
        p["port"] = n; changed.append("port")
    if "bind" in d:
        b = str(d.get("bind", "")).strip()
        if not v_ip(b):
            raise ApiError(400, "bind must be an IPv4 address")
        p["bind"] = b; changed.append("bind")
    if "tls" in d:
        p["tls"] = bool(d.get("tls")); changed.append("tls")
    if not changed:
        raise ApiError(400, "nothing to change")
    save_panel(p)
    if p.get("tls"):
        run([CTL, "panel", "tls", "on"], timeout=30)  # ensures a cert exists
    _restart_panel_soon()
    return {"ok": True, "changed": changed, "bind": p.get("bind"), "port": p.get("port"),
            "tls": bool(p.get("tls")),
            "note": "panel is restarting - reconnect on %s:%s" % (p.get("bind"), p.get("port"))}


def api_panel_toggle(req):
    """Enable (autostart) or disable (stop + no autostart) the panel."""
    on = bool((req.json or {}).get("on", True))
    if on:
        rc, out, err = run([CTL, "panel", "enable"], timeout=30)
        if rc:
            raise ApiError(500, (err or out or "failed").strip()[:300])
        return {"ok": True, "enabled": True}
    # Disable stops this very process, so return first, then disable.
    threading.Timer(1.0, lambda: run([CTL, "panel", "disable"], timeout=30)).start()
    return {"ok": True, "enabled": False, "note": "panel is being disabled; this session will end"}


# ── peer sync (two panels paired by a shared token) ─────────────────────────

def _peer_request(method, path, body=None, timeout=8):
    p = load_panel()
    base = str(p.get("peer_url") or "").rstrip("/")
    tok = str(p.get("sync_token") or "")
    if not base or not tok:
        raise ApiError(400, "peer not paired - set the peer URL and a shared token in Settings")
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(base + path, data=data, method=method,
                               headers={"X-Sync-Token": tok, "Content-Type": "application/json"})
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # panels usually use self-signed certs
    try:
        with urllib.request.urlopen(r, timeout=timeout, context=ctx) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        try:
            msg = json.loads(e.read().decode()).get("error", str(e))
        except Exception:
            msg = "HTTP %s" % e.code
        raise ApiError(502, "peer: %s" % msg)
    except Exception as e:
        raise ApiError(502, "peer unreachable: %s" % e)


def api_sync_overview(req):
    """Compact status served to a paired peer (token-authed)."""
    role = get_role()
    insts = instances()
    props = systemd_show([i.unit for i in insts]) if insts else {}
    tuns = []
    for i in insts:
        st = unit_status(i, props)
        c = i.cfg()
        tuns.append({"name": i.name, "active": st.get("active"),
                     "transport": c.get("transport", "spoof"),
                     "data_port": c.get("data_port"), "icmp_id": c.get("icmp_id")})
    commit = ""
    if os.path.exists(BUILD_INFO):
        for line in read_text(BUILD_INFO).splitlines():
            if line.startswith("commit="):
                commit = line.split("=", 1)[1][:12]
    return {"role": role, "host": socket.gethostname(), "tunnels": tuns, "build": commit}


def api_sync_apply(req):
    """Apply a config pushed by the paired peer (token-authed).  Reuses the
    validate -> write -> restart -> rollback path, so a bad push is reverted."""
    d = req.json if isinstance(req.json, dict) else {}
    name = str(d.get("name", "main")).strip() or "main"
    inst = _inst_or_404(name)
    active, warn = apply_edit(inst, d, "synced from peer")
    return {"ok": True, "name": name, "active": active, "warnings": warn}


def api_peer_get(req):
    p = load_panel()
    return {"peer_url": p.get("peer_url", ""), "paired": bool(p.get("sync_token"))}


def api_peer_set(req):
    d = req.json if isinstance(req.json, dict) else {}
    p = load_panel()
    if d.get("unpair"):
        p.pop("peer_url", None); p.pop("sync_token", None)
        save_panel(p)
        return {"ok": True, "paired": False, "peer_url": ""}
    if "peer_url" in d:
        u = str(d.get("peer_url", "")).strip().rstrip("/")
        if u and not (u.startswith("http://") or u.startswith("https://")):
            raise ApiError(400, "peer_url must start with http:// or https://")
        p["peer_url"] = u
    reveal = None
    if d.get("generate"):
        reveal = secrets.token_urlsafe(32); p["sync_token"] = reveal
    elif str(d.get("sync_token", "")).strip():
        p["sync_token"] = str(d.get("sync_token")).strip()
    save_panel(p)
    return {"ok": True, "paired": bool(p.get("sync_token")), "peer_url": p.get("peer_url", ""),
            "sync_token": reveal}


UPDATE_LOG = os.path.join(STATE, "update.log")
UPDATE_UNIT = "shadow-spoof-update"
REPO_API = "https://api.github.com/repos/primeshock/shadow-tunnel/commits/master"


def _update_running():
    rc, out, _ = run([SYSTEMCTL, "is-active", UPDATE_UNIT + ".service"])
    return (out or "").strip() in ("active", "activating")


def api_update_status(req):
    cur = ""
    for line in read_text(BUILD_INFO).splitlines():
        if line.startswith("commit="):
            cur = line.split("=", 1)[1].strip()
    latest, err = "", ""
    if str(req.query.get("check", ["1"])[0]) != "0":
        try:
            r = urllib.request.Request(REPO_API, headers={"User-Agent": "shadow-spoof-panel",
                                                          "Accept": "application/vnd.github+json"})
            with urllib.request.urlopen(r, timeout=6) as resp:
                latest = json.loads(resp.read().decode()).get("sha", "")
        except Exception as e:
            err = "could not reach GitHub: %s" % e
    log = read_text(UPDATE_LOG).splitlines()[-60:]
    return {"current": cur[:12], "latest": latest[:12], "error": err,
            "available": bool(latest and (not cur or (not latest.startswith(cur[:12]) and not cur.endswith(latest)))),
            "running": _update_running(), "log": "\n".join(log)}


def api_update_start(req):
    if _update_running():
        raise ApiError(409, "an update is already running")
    if not os.access(CTL, os.X_OK):
        raise ApiError(500, "%s not found - re-run the installer" % CTL)
    # A transient unit outlives the panel restart that the installer performs.
    rc, out, err = run(["systemd-run", "--unit=" + UPDATE_UNIT, "--collect", "--quiet",
                        "-p", "StandardOutput=file:" + UPDATE_LOG,
                        CTL, "update", "-y"], timeout=15)
    if rc:
        raise ApiError(500, (err or out or "systemd-run failed").strip()[:300])
    return {"ok": True}


def api_peer_status(req):
    return _peer_request("GET", "/api/sync/overview")


def _maybe_push_peer(inst):
    """After a local change, push the mirrored config to the paired peer so both
    ends stay consistent.  Best-effort: returns a small status for the UI."""
    p = load_panel()
    if not (p.get("peer_url") and p.get("sync_token")):
        return None
    try:
        mirror = peer_view(inst.role, inst.cfg())
        mirror["name"] = inst.name
        _peer_request("POST", "/api/sync/apply", mirror)
        return {"ok": True}
    except ApiError as e:
        return {"ok": False, "error": e.msg}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ---------------------------------------------------------------- http server --
INDEX_HTML = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="color-scheme" content="dark light">
<title>Shadow Spoof</title>
<link rel="icon" href="data:,">
<style nonce="__NONCE__">
:root{--bg:#0a0d14;--bg2:#0f1420;--card:#141a28;--card2:#182032;--line:#243049;--tx:#eef1f8;--mut:#8f9ab2;--acc:#ff6fae;--acc2:#6fb7ff;--ok:#3ddc97;--warn:#f5b54a;--bad:#ff5d6c;--r:16px;--grad:linear-gradient(135deg,#ff6fae,#b06bff 60%,#6fb7ff);--shadow:0 10px 30px -12px #000a;--ring:0 0 0 3px #ff6fae33}
*{box-sizing:border-box}
html,body{margin:0;background:var(--bg);color:var(--tx);font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,Vazirmatn,Tahoma,sans-serif;-webkit-text-size-adjust:100%}
html{background:#06061a}body{background:transparent}
#bg{position:fixed;inset:-80px;z-index:-1;overflow:hidden;pointer-events:none;background:radial-gradient(120% 90% at 50% 0%,#0a0a24 0%,#04040f 72%);transform:translate3d(calc(var(--mx,0)*22px),calc(var(--my,0)*22px),0);transition:transform 1.6s cubic-bezier(.2,.7,.2,1)}
#bg i{position:absolute;display:block;filter:blur(90px);opacity:.20;will-change:transform,border-radius}
#bg .b1{width:64vmax;height:64vmax;left:-18vmax;top:-22vmax;background:#c026d3;animation:liq1 46s ease-in-out infinite}
#bg .b2{width:58vmax;height:58vmax;right:-20vmax;top:-12vmax;background:#2563eb;animation:liq2 54s ease-in-out infinite}
#bg .b3{width:60vmax;height:60vmax;left:8vmax;bottom:-30vmax;background:#7c3aed;animation:liq3 60s ease-in-out infinite}
#bg .b4{width:44vmax;height:44vmax;right:-8vmax;bottom:-16vmax;background:#db2777;opacity:.14;animation:liq4 50s ease-in-out infinite}
@keyframes liq1{0%,100%{transform:translate(0,0) rotate(0) scale(1);border-radius:42% 58% 61% 39%/45% 38% 62% 55%}33%{transform:translate(16vmax,8vmax) rotate(120deg) scale(1.12);border-radius:58% 42% 38% 62%/55% 62% 38% 45%}66%{transform:translate(5vmax,22vmax) rotate(240deg) scale(.94);border-radius:38% 62% 55% 45%/62% 40% 60% 38%}}
@keyframes liq2{0%,100%{transform:translate(0,0) rotate(0) scale(1);border-radius:55% 45% 40% 60%/50% 58% 42% 50%}40%{transform:translate(-14vmax,14vmax) rotate(-140deg) scale(1.1);border-radius:40% 60% 58% 42%/60% 40% 60% 40%}70%{transform:translate(-4vmax,26vmax) rotate(-250deg) scale(.95);border-radius:60% 40% 45% 55%/42% 55% 45% 58%}}
@keyframes liq3{0%,100%{transform:translate(0,0) rotate(0) scale(1);border-radius:48% 52% 56% 44%/58% 42% 58% 42%}35%{transform:translate(20vmax,-10vmax) rotate(110deg) scale(1.1);border-radius:60% 40% 42% 58%/44% 58% 42% 56%}70%{transform:translate(-8vmax,-18vmax) rotate(230deg) scale(.96);border-radius:42% 58% 60% 40%/56% 44% 56% 44%}}
@keyframes liq4{0%,100%{transform:translate(0,0) rotate(0) scale(1);border-radius:50% 50% 44% 56%/52% 46% 54% 48%}50%{transform:translate(-18vmax,-12vmax) rotate(180deg) scale(1.15);border-radius:44% 56% 52% 48%/48% 56% 44% 52%}}
@media(prefers-reduced-motion:reduce){#bg i{animation:none}#bg{transition:none}}
#app{position:relative;z-index:0}
@media(prefers-reduced-motion:no-preference){.card,.btn,nav.dock button{transition:transform .15s ease,border-color .15s ease,background .15s ease,box-shadow .15s ease}}
body{padding:env(safe-area-inset-top) env(safe-area-inset-right) calc(70px + env(safe-area-inset-bottom)) env(safe-area-inset-left)}
button,input,select{font:inherit;color:inherit}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;direction:ltr;unicode-bidi:plaintext}
.wrap{max-width:1100px;margin:0 auto;padding:14px}
header.top{display:flex;align-items:center;gap:10px;padding:12px 16px;border-bottom:1px solid var(--line);background:var(--bg2);background:color-mix(in srgb,var(--bg2) 82%,transparent);backdrop-filter:saturate(150%) blur(10px);-webkit-backdrop-filter:saturate(150%) blur(10px);position:sticky;top:0;z-index:5}
.logo{font-weight:800;font-size:18px;letter-spacing:.2px}.logo b{background:var(--grad);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
.sp{flex:1}
nav.dock{display:flex;gap:4px;padding:7px;background:var(--bg2);background:color-mix(in srgb,var(--bg2) 80%,transparent);backdrop-filter:saturate(150%) blur(14px);-webkit-backdrop-filter:saturate(150%) blur(14px);border:1px solid var(--line);border-radius:999px;position:fixed;left:50%;transform:translateX(-50%);bottom:calc(12px + env(safe-area-inset-bottom));z-index:6;box-shadow:0 12px 40px -8px #000b}
nav.dock button{background:none;border:0;padding:9px 16px;border-radius:999px;color:var(--mut);cursor:pointer;white-space:nowrap;font-weight:600}
nav.dock button:hover{color:var(--tx)}
nav.dock button.on{background:var(--grad);color:#fff;box-shadow:0 6px 18px -6px var(--acc)}
h2{font-size:15px;margin:22px 0 10px;color:var(--mut);font-weight:600;text-transform:uppercase;letter-spacing:.6px}
.grid{display:grid;gap:12px;grid-template-columns:repeat(auto-fill,minmax(260px,1fr))}
.card{position:relative;background:linear-gradient(180deg,#1b2336cc,#131a28cc);border:1px solid #ffffff14;border-radius:var(--r);padding:16px;box-shadow:var(--shadow),inset 0 1px 0 #ffffff1f;backdrop-filter:blur(8px) saturate(140%);-webkit-backdrop-filter:blur(8px) saturate(140%)}
.grid .card:hover{transform:translateY(-2px);border-color:#ffffff2e;box-shadow:var(--shadow),inset 0 1px 0 #ffffff26,0 0 0 1px #ff6fae22}
.big{font-size:28px;font-weight:800;letter-spacing:-.5px;background:linear-gradient(180deg,#fff,#b9c2d8);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}.lbl{color:var(--mut);font-size:12px}
.row{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.kv{display:grid;grid-template-columns:1fr 1fr;gap:6px 14px;margin:10px 0}
.kv div span{display:block}.kv .v{font-weight:600}
.pill{display:inline-block;padding:1px 9px;border-radius:999px;font-size:12px;border:1px solid var(--line);color:var(--mut)}
.pill.ok{color:var(--ok);border-color:#1f5b44;background:#12301f}.pill.warn{color:var(--warn);border-color:#6b4f17;background:#2a2110}.pill.bad{color:var(--bad);border-color:#6b2530;background:#2c1118}
.tag{font-size:11px;padding:1px 7px;border-radius:6px;background:#202942;color:var(--acc2)}
.btn{background:#1b2338;border:1px solid var(--line);padding:8px 13px;border-radius:11px;cursor:pointer;font-weight:600}
.btn:hover{border-color:#3c4c78;transform:translateY(-1px)}.btn:active{transform:translateY(0)}.btn.pri{background:var(--grad);color:#fff;border-color:transparent;box-shadow:0 8px 20px -8px var(--acc)}.btn.pri:hover{filter:brightness(1.07)}.btn.dng{color:var(--bad)}.btn.dng:hover{border-color:var(--bad)}.btn.sm{padding:5px 10px;font-size:12px}
.btn:disabled{opacity:.5;cursor:default}
input,select{background:#0c1119;border:1px solid var(--line);border-radius:11px;padding:9px 11px;width:100%}
input:focus,select:focus{outline:none;box-shadow:var(--ring);border-color:var(--acc)}
input:hover,select:hover{border-color:#34426a}
label.f{display:block;margin:10px 0}label.f>span{display:block;color:var(--mut);font-size:12px;margin-bottom:3px}
.err{color:var(--bad);font-size:12px;margin-top:3px}.hint{color:var(--mut);font-size:12px;margin-top:3px}
.spark{width:100%;height:30px;display:block}.spark polyline{stroke:var(--acc2);stroke-width:1.5;vector-effect:non-scaling-stroke}.spark.pink polyline{stroke:var(--acc)}.spark.grn polyline{stroke:var(--ok)}
.banner{padding:10px 12px;border-radius:12px;margin:10px 0;border:1px solid #6b4f17;background:#2a2110;color:var(--warn)}
.ev{display:flex;gap:10px;padding:5px 0;border-bottom:1px dashed var(--line);font-size:13px}.ev time{color:var(--mut);min-width:64px}
.ev.error .m{color:var(--bad)}.ev.warn .m{color:var(--warn)}
.overlay{position:fixed;inset:0;background:#000c;backdrop-filter:blur(4px);-webkit-backdrop-filter:blur(4px);z-index:20;display:flex;align-items:flex-start;justify-content:center;padding:20px 12px;overflow:auto}
.modal{background:linear-gradient(180deg,#1b2336f2,#131a28f2);border:1px solid #ffffff1f;border-radius:var(--r);padding:18px;width:100%;max-width:560px;margin:auto 0;box-shadow:0 30px 80px -20px #000d,inset 0 1px 0 #ffffff1f;backdrop-filter:blur(12px) saturate(150%);-webkit-backdrop-filter:blur(12px) saturate(150%)}
.modal h3{margin:0 0 6px}
.two{display:grid;grid-template-columns:1fr 1fr;gap:0 12px}
@media(max-width:560px){.two{grid-template-columns:1fr}}
pre.log{background:#070a10;border:1px solid var(--line);border-radius:12px;padding:10px;height:56vh;overflow:auto;margin:10px 0;font-size:12px;line-height:1.5;white-space:pre-wrap;word-break:break-all;direction:ltr;text-align:left}
pre.log .t{color:var(--mut)}.lv-ERROR{color:var(--bad)}.lv-WARN{color:var(--warn)}.lv-DEBUG,.lv-TRACE{color:var(--mut)}
.chk{display:flex;gap:10px;padding:8px 0;border-bottom:1px solid var(--line)}.chk .i{width:22px;text-align:center;font-weight:700}
.i.ok{color:var(--ok)}.i.warn,.i.info{color:var(--warn)}.i.fail{color:var(--bad)}
.copy{word-break:break-all;background:var(--bg);border:1px solid var(--line);border-radius:10px;padding:8px 10px;margin:6px 0}
.toast{position:fixed;left:50%;transform:translateX(-50%);bottom:90px;background:#202942;border:1px solid var(--line);padding:9px 16px;border-radius:12px;z-index:30;max-width:90vw}
.toast.bad{border-color:var(--bad)}
.loginwrap{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
.login{width:min(440px,100%)}
.login .logo{font-size:34px;text-align:center;margin-bottom:18px}
.login .card{padding:28px 26px}
.login input{height:54px;font-size:16px;border-radius:14px;padding:0 16px}
.login .btn.pri{width:100%;height:54px;font-size:16px;margin-top:6px}
.login label.f span{font-size:13px}
pre.log.ulog{height:150px;margin:10px 0 0}
.ulog:empty{display:none}
.sr{position:absolute;left:-9999px;width:1px;height:1px;opacity:0}
[dir=rtl] .kv .v{text-align:start}
.hint.fix{color:var(--acc2)}
.chk .i{flex:0 0 22px}
.chk .ctext{min-width:0;flex:1}
.dhead{display:flex;gap:6px;margin-bottom:10px;flex-wrap:wrap}
/* ---- responsive ---- */
@media(max-width:760px){
  .wrap{padding:12px}
  .grid{grid-template-columns:1fr;gap:10px}
  .kv{grid-template-columns:1fr 1fr}
  .card{padding:14px}
  .big{font-size:24px}
}
@media(max-width:560px){
  nav.dock{left:12px;right:12px;transform:none;max-width:none;justify-content:space-between;gap:2px;overflow-x:auto;-webkit-overflow-scrolling:touch;scrollbar-width:none}
  nav.dock::-webkit-scrollbar{display:none}
  nav.dock button{padding:8px 12px;flex:0 0 auto}
  header.top{padding:10px 12px}
  .modal{padding:14px}
  .row{gap:6px}
}
@media(max-width:420px){
  .kv{grid-template-columns:1fr}
  nav.dock button{padding:8px 10px;font-size:13px}
}

/* ===== v3: theme variables, glass, sections, light theme ===== */
:root{--g1:rgba(34,40,72,.50);--g2:rgba(20,24,46,.36);--gl:rgba(255,255,255,.15);--m1:rgba(30,36,66,.86);--m2:rgba(18,22,44,.82);--btn:rgba(255,255,255,.07);--inp:rgba(5,7,20,.55);--tagbg:rgba(111,183,255,.13);--logbg:rgba(3,5,14,.62);--dock:rgba(14,16,34,.58);--ovl:rgba(0,0,8,.62)}
:root[data-theme=light]{--bg:#e9ecf8;--bg2:#f4f6ff;--line:#c5cde6;--tx:#161a2e;--mut:#56608a;--acc2:#2563eb;--shadow:0 12px 30px -16px rgba(40,56,130,.45);--ring:0 0 0 3px rgba(37,99,235,.25);--g1:rgba(255,255,255,.66);--g2:rgba(255,255,255,.44);--gl:rgba(255,255,255,.95);--m1:rgba(255,255,255,.92);--m2:rgba(246,248,255,.9);--btn:rgba(30,45,110,.07);--inp:rgba(255,255,255,.75);--tagbg:rgba(37,99,235,.10);--logbg:rgba(255,255,255,.75);--dock:rgba(255,255,255,.66);--ovl:rgba(30,40,90,.35)}
html[data-theme=light]{background:#e6e9f7}
html[data-theme=light] #bg{background:radial-gradient(120% 90% at 50% 0%,#f6f3ff 0%,#e4e9fb 72%)}
html[data-theme=light] #bg i{opacity:.30}
html[data-theme=light] .big{background:linear-gradient(180deg,#161a2e,#3d4875);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
html[data-theme=light] .pill.ok{background:#dcfce7;border-color:#86efac;color:#15803d}
html[data-theme=light] .pill.warn{background:#fef3c7;border-color:#fcd34d;color:#a16207}
html[data-theme=light] .pill.bad{background:#fee2e2;border-color:#fca5a5;color:#b91c1c}
html[data-theme=light] .banner{background:#fef3c7;border-color:#fcd34d;color:#a16207}
html[data-theme=light] .btn.pri,html[data-theme=light] nav.dock button.on{color:#fff}
.card{background:linear-gradient(160deg,var(--g1),var(--g2));border:1px solid var(--gl);box-shadow:var(--shadow),inset 0 1px 0 rgba(255,255,255,.22),inset 0 -1px 0 rgba(255,255,255,.04);backdrop-filter:blur(18px) saturate(175%);-webkit-backdrop-filter:blur(18px) saturate(175%)}
.card::before{content:"";position:absolute;inset:0;border-radius:inherit;pointer-events:none;background:linear-gradient(125deg,rgba(255,255,255,.11),rgba(255,255,255,0) 40%)}
.modal{background:linear-gradient(160deg,var(--m1),var(--m2));border:1px solid var(--gl);backdrop-filter:blur(22px) saturate(170%);-webkit-backdrop-filter:blur(22px) saturate(170%)}
.overlay{background:var(--ovl)}
nav.dock,header.top{background:var(--dock);border-color:var(--gl);backdrop-filter:blur(18px) saturate(175%);-webkit-backdrop-filter:blur(18px) saturate(175%)}
.btn{background:var(--btn);border-color:var(--gl)}
input,select{background:var(--inp);border-color:var(--gl);color:var(--tx)}
.tag{background:var(--tagbg)}
pre.log{background:var(--logbg)}
.copy{background:var(--inp)}
.toast{background:var(--m1);color:var(--tx)}
.toolbar{display:flex;gap:10px;flex-wrap:wrap;margin:6px 0 22px}
.linkbox{display:flex;flex-wrap:wrap;gap:6px;margin:10px 0 4px}
.fsec{grid-column:1/-1;margin:20px 0 4px;padding-top:12px;border-top:1px solid var(--gl);font-weight:700;font-size:12px;letter-spacing:.7px;text-transform:uppercase;color:var(--mut)}
.fsec:first-child{margin-top:4px;border-top:0;padding-top:0}

/* ===== v4: calmer glow, dashboard-style backdrop, clean light theme ===== */
.btn.pri{box-shadow:0 2px 8px -3px rgba(176,107,255,.45)}
.btn.pri:hover{filter:brightness(1.06)}
nav.dock button.on{box-shadow:0 2px 8px -3px rgba(176,107,255,.5)}
.grid .card:hover{transform:none;border-color:rgba(255,255,255,.26);box-shadow:var(--shadow),inset 0 1px 0 rgba(255,255,255,.24)}
.card{box-shadow:0 6px 18px -12px rgba(0,0,0,.7),inset 0 1px 0 rgba(255,255,255,.18)}
.card::before{background:linear-gradient(125deg,rgba(255,255,255,.07),rgba(255,255,255,0) 38%)}
.pill.dim{color:var(--acc2);border-color:rgba(111,183,255,.25);background:rgba(111,183,255,.07);opacity:.8}
.pill.ok{font-weight:600}
/* backdrop: near-black base, navy glow top-left, maroon bottom-right, faint grid */
html{background:#05060b}
#bg{background:radial-gradient(130% 100% at 0% 0%,#0b1033 0%,#05060b 62%)}
#bg i{opacity:.32}
#bg .b1{background:#1d2a8a}
#bg .b2{background:#3a1d7a}
#bg .b3{background:#2b1160}
#bg .b4{background:#5a1226;opacity:.30}
#bg::after{content:"";position:absolute;inset:0;pointer-events:none;background-image:linear-gradient(rgba(255,255,255,.028) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.028) 1px,transparent 1px);background-size:42px 42px;-webkit-mask-image:radial-gradient(90% 80% at 50% 40%,#000 30%,transparent 100%);mask-image:radial-gradient(90% 80% at 50% 40%,#000 30%,transparent 100%)}
/* light theme: clean neutral panel, soft white glass, barely-there tint */
:root[data-theme=light]{--bg:#f3f5fa;--bg2:#ffffff;--line:#d5dbe8;--tx:#141a2e;--mut:#5b6685;--g1:rgba(255,255,255,.78);--g2:rgba(255,255,255,.58);--gl:rgba(20,30,70,.10);--m1:rgba(255,255,255,.96);--m2:rgba(247,249,254,.95);--btn:rgba(20,30,70,.05);--inp:#ffffff;--dock:rgba(255,255,255,.82);--shadow:0 6px 18px -12px rgba(30,45,100,.35)}
html[data-theme=light]{background:#f3f5fa}
html[data-theme=light] #bg{background:radial-gradient(120% 90% at 0% 0%,#eaeefc 0%,#f3f5fa 60%)}
html[data-theme=light] #bg i{opacity:.12}
html[data-theme=light] #bg .b1{background:#7c8cff}html[data-theme=light] #bg .b2{background:#b7a6ff}html[data-theme=light] #bg .b3{background:#9cc7ff}html[data-theme=light] #bg .b4{background:#ffb3d1;opacity:.10}
html[data-theme=light] #bg::after{background-image:linear-gradient(rgba(20,30,70,.045) 1px,transparent 1px),linear-gradient(90deg,rgba(20,30,70,.045) 1px,transparent 1px)}
html[data-theme=light] .card{box-shadow:0 4px 14px -10px rgba(30,45,100,.35),inset 0 1px 0 #fff}
html[data-theme=light] .card::before{background:linear-gradient(125deg,rgba(255,255,255,.55),rgba(255,255,255,0) 40%)}
html[data-theme=light] header.top,html[data-theme=light] nav.dock{border-color:var(--gl)}
html[data-theme=light] .btn{color:var(--tx)}
html[data-theme=light] .btn.pri{color:#fff}
html[data-theme=light] .pill.dim{color:#2563eb;background:rgba(37,99,235,.07);border-color:rgba(37,99,235,.25)}
html[data-theme=light] .big{background:none;-webkit-text-fill-color:var(--tx);color:var(--tx)}
</style>
</head>
<body>
<div id="bg" aria-hidden="true"><i class="b1"></i><i class="b2"></i><i class="b3"></i><i class="b4"></i></div>
<div id="app"></div>
<script nonce="__NONCE__">
'use strict';
(function(){try{var th=localStorage.getItem('theme');if(th==='light'||th==='dark')document.documentElement.setAttribute('data-theme',th)}catch(e){}})();
/* ---------- live background: slow mouse parallax ---------- */
(function(){
  var r=document.documentElement, raf=0, x=0, y=0;
  addEventListener('pointermove',function(e){
    x=(e.clientX/innerWidth-0.5)*2; y=(e.clientY/innerHeight-0.5)*2;
    if(raf) return; raf=requestAnimationFrame(function(){ raf=0; r.style.setProperty('--mx',x.toFixed(3)); r.style.setProperty('--my',y.toFixed(3)); });
  },{passive:true});
})();
/* ---------- i18n ---------- */
const TR = {
en: {
 ev_tab:'Events', sec_general:'General', sec_addr:'Addresses', sec_port:'Ports & interface', sec_perf:'Performance', sec_rel:'Reliability & restart', sec_sec:'Security', f_autorestart:'Auto-restart', h_autorestart:'What systemd does if the tunnel process exits', ar_fail:'On failure (default)', ar_always:'Always', ar_no:'Never', f_restartsec:'Restart delay (seconds)', link_check:'checking link…', link_ok:'link OK', link_down:'peer unreachable', hs:'handshake', no_hs:'no handshake yet', peer_panel:'peer panel', theme:'Theme', upd_title:'Update', upd_hint:'Rebuilds from the latest release and restarts services. Your tunnels, keys and config are kept (a backup is taken first).', upd_cur:'current', upd_new:'latest', upd_now:'Update now', upd_check:'Check for update', upd_running:'update running…', upd_avail:'update available', upd_latest:'Your version is up to date', upd_warn:'Start the update now? The panel restarts during the update and you will have to sign in again.', upd_started:'update started', upd_reconnect:'panel is restarting… reconnecting', overview:'Overview', tunnels:'Tunnels', logs:'Logs', health:'Health', diagnose:'Diagnose', settings:'Settings', login:'Sign in', password:'Password', logout:'Sign out',
 diag_title:'Tunnel doctor', diag_hint:'Checks the whole tunnel path and names the setting at fault. Paste the OTHER host’s setup link for a two-sided check (ports, ICMP id, key and spoofed-IP pairing).', peer_link:'Peer setup link (optional)', run_diag:'Run diagnosis', mtu_for:'test tunnel:', mtu_test:'MTU test', mtu_path:'path MTU', mtu_rec:'recommended', mtu_cur:'current', mtu_apply:'Apply recommended',
 cpu:'CPU', mem:'Memory', disk:'Disk', load:'Load / uptime', uptime:'Uptime', restarts:'Auto-restarts', rss:'RAM', conns:'Connections', rx:'RX', tx:'TX',
 active:'active', inactive:'stopped', failed:'failed', activating:'starting', monitor_down:'The monitor service is not running - metrics and history are unavailable.',
 events:'Recent events', none:'Nothing yet', details:'Details', start:'Start', stop:'Stop', restart:'Restart', del:'Delete', edit:'Edit', test:'Link test', key:'Key & link', link:'Setup link',
 create:'Create tunnel', import:'Import link', cancel:'Cancel', save:'Save', close:'Close', confirm_del:'Delete tunnel "%s"? Its service and config are removed.',
 f_name:'Tunnel name', f_transport:'Transport', h_transport:'spoof = UDP+ICMP forged source · tcp = standard non-spoofed TCP', f_real:'Real IP', f_spoof:'Spoofed IP', f_pool:'Spoofed IP pool (comma-separated, optional)', f_peerpool:'Peer spoofed IP pool (optional)',
 h_peerpool:'Every pool address the peer may use, otherwise its packets are dropped (allowed_peers).', f_iface:'Interface', f_port:'Data port', f_icmp:'ICMP ID (0-65535 or 0x..)',
 f_socks:'SOCKS5 port', f_tun:'Tunnel count', f_mtu:'MTU', f_cwnd:'Initial CWND', f_retries:'Max retries', h_retries:'retransmits before giving up (1-100)', f_rto:'Min RTO (ms)', h_rto:'retransmit-timeout floor; raise on lossy/high-latency links (10-60000)', f_key:'Pre-shared key (blank = generate)', gen:'Generate', server:'server', client:'client',
 auto:'auto-detect', saved:'Saved', created:'Tunnel created', link_hint:'Give this link to the other side: Tunnels > Import link.', fp:'Fingerprint', show:'Show',
 paste_link:'Paste a shadowspoof:// link', apply:'Apply', pw_confirm:'Enter the panel password to reveal the key', reveal:'Reveal',
 level:'Level', search:'Search', lines:'Lines', auto_refresh:'Auto-refresh', run:'Run check', host:'Host', port:'Port', running:'Running...', avg:'Average', handshake_ok:'handshakes OK',
 wd:'Periodic restart (watchdog)', wd_hint:'Independent of crash recovery (Restart=on-failure).', chg_pw:'Change password', old_pw:'Current password', new_pw:'New password (10+ chars)',
 peer_cfg:'Peer server (auto-sync)', peer_hint:'Pair the two panels with the same shared token. Tunnel edits are then pushed to the peer automatically. Use HTTPS between panels.', peer_url:'Peer panel URL', peer_token:'Shared token', peer_token_ph:'paste the token from the other panel', peer_pair:'Pair', peer_gen:'Generate token', peer_check:'Check peer', peer_unpair:'Unpair', peer_paired:'Paired', peer_token_hint:'Copy this token to the OTHER panel (Settings > Peer), then set each panelu2019s Peer URL.', panel_cfg:'Web panel address', panel_cfg_hint:'Changing the port/address restarts the panel — you will reconnect on the new address.', panel_bind:'Bind address', panel_port:'Port', panel_save:'Save & restart panel', panel_warn:'Change the panel address and restart now? You will need to reconnect.', panel_disable:'Disable panel', panel_dis_warn:'Stop the web panel and turn off autostart? This session will end; re-enable it with: shadowtun panel enable', panel_disabled:'panel is being disabled…',
 lang:'Language', copied:'Copied', copy:'Copy', not_listening:'SOCKS5 not listening', last_est:'Last handshake', ago:'ago', never:'never', build:'Build', role:'Role',
 note_key:'The pre-shared key authenticates every packet (HMAC). Both sides must use the identical key.', srv_test_hint:'Listens for client packets for 10 s. Press Run here, then run the test on the client at the same time.', no_tunnels:'No tunnels yet.', warnings:'Warnings'
},
fa: {
 ev_tab:'رویدادها', sec_general:'عمومی', sec_addr:'آدرس‌ها', sec_port:'پورت و اینترفیس', sec_perf:'کارایی', sec_rel:'پایداری و ری‌استارت', sec_sec:'امنیت', f_autorestart:'ری‌استارت خودکار', h_autorestart:'اگر پروسهٔ تونل بسته شد systemd چه کند', ar_fail:'هنگام خطا (پیش‌فرض)', ar_always:'همیشه', ar_no:'هرگز', f_restartsec:'تأخیر ری‌استارت (ثانیه)', link_check:'در حال بررسی ارتباط…', link_ok:'ارتباط برقرار', link_down:'طرف مقابل در دسترس نیست', hs:'هندشیک', no_hs:'هنوز هندشیکی نشده', peer_panel:'پنل مقابل', theme:'تم', upd_title:'آپدیت', upd_hint:'از آخرین نسخه دوباره build می‌کند و سرویس‌ها را ری‌استارت می‌کند. تونل‌ها، کلیدها و کانفیگ حفظ می‌شود (قبلش بکاپ گرفته می‌شود).', upd_cur:'فعلی', upd_new:'آخرین', upd_now:'آپدیت کن', upd_check:'بررسی آپدیت', upd_running:'در حال آپدیت…', upd_avail:'آپدیت موجود است', upd_latest:'نسخه شما به‌روز است', upd_warn:'آپدیت همین حالا شروع شود؟ پنل وسط آپدیت ری‌استارت می‌شود و باید دوباره وارد شوی.', upd_started:'آپدیت شروع شد', upd_reconnect:'پنل در حال ری‌استارت است… اتصال مجدد', overview:'نمای کلی', tunnels:'تونل‌ها', logs:'لاگ‌ها', health:'سلامت', diagnose:'عیب‌یابی', settings:'تنظیمات', login:'ورود', password:'رمز عبور', logout:'خروج',
 diag_title:'دکتر تونل', diag_hint:'کل مسیر تونل را بررسی می‌کند و تنظیمِ اشتباه را نام می‌برد. برای بررسی دوطرفه، لینکِ راه‌اندازیِ طرف مقابل را بچسبانید (پورت‌ها، ICMP id، کلید و جفت‌شدنِ IP جعلی).', peer_link:'لینک راه‌اندازی طرف مقابل (اختیاری)', run_diag:'اجرای عیب‌یابی', mtu_for:'تست MTU برای:', mtu_test:'تست MTU', mtu_path:'MTU مسیر', mtu_rec:'پیشنهادی', mtu_cur:'فعلی', mtu_apply:'اعمال پیشنهادی',
 cpu:'پردازنده', mem:'حافظه', disk:'دیسک', load:'بار / آپ‌تایم', uptime:'آپ‌تایم', restarts:'ری‌استارت خودکار', rss:'رم', conns:'اتصال‌ها', rx:'دریافت', tx:'ارسال',
 active:'فعال', inactive:'متوقف', failed:'خراب', activating:'در حال شروع', monitor_down:'سرویس مانیتور اجرا نیست؛ آمار و تاریخچه در دسترس نیست.',
 events:'رویدادهای اخیر', none:'هنوز چیزی نیست', details:'جزئیات', start:'شروع', stop:'توقف', restart:'ری‌استارت', del:'حذف', edit:'ویرایش', test:'تست لینک', key:'کلید و لینک', link:'لینک راه‌اندازی',
 create:'ساخت تونل', import:'وارد کردن لینک', cancel:'انصراف', save:'ذخیره', close:'بستن', confirm_del:'تونل «%s» حذف شود؟ سرویس و کانفیگ آن پاک می‌شود.',
 f_name:'نام تونل', f_transport:'نوع انتقال', h_transport:'spoof = UDP+ICMP با منبع جعلی · tcp = TCP استاندارد بدون جعل', f_real:'IP واقعی', f_spoof:'IP جعلی', f_pool:'استخر IP جعلی (با کاما، اختیاری)', f_peerpool:'استخر IP جعلی طرف مقابل (اختیاری)',
 h_peerpool:'همهٔ IPهایی که طرف مقابل ممکن است استفاده کند؛ وگرنه بسته‌هایش دور ریخته می‌شود (allowed_peers).', f_iface:'اینترفیس', f_port:'پورت دیتا', f_icmp:'ICMP ID ‏(۰ تا ۶۵۵۳۵ یا 0x..)',
 f_socks:'پورت SOCKS5', f_tun:'تعداد تونل', f_mtu:'MTU', f_cwnd:'CWND اولیه', f_retries:'حداکثر تلاش مجدد', h_retries:'تعداد ارسال مجدد پیش از انصراف (۱ تا ۱۰۰)', f_rto:'حداقل RTO (ms)', h_rto:'کف زمان‌بندی ارسال مجدد؛ در شبکه‌های پرافت/پرتأخیر بالاتر بگذارید (۱۰ تا ۶۰۰۰۰)', f_key:'کلید pre-shared (خالی = ساخت خودکار)', gen:'ساخت', server:'سرور', client:'کلاینت',
 auto:'تشخیص خودکار', saved:'ذخیره شد', created:'تونل ساخته شد', link_hint:'این لینک را به طرف مقابل بدهید: تونل‌ها > وارد کردن لینک.', fp:'اثر انگشت', show:'نمایش',
 paste_link:'لینک shadowspoof:// را بچسبانید', apply:'اعمال', pw_confirm:'برای نمایش کلید، رمز پنل را وارد کنید', reveal:'نمایش',
 level:'سطح', search:'جستجو', lines:'تعداد خط', auto_refresh:'به‌روزرسانی خودکار', run:'اجرای بررسی', host:'هاست', port:'پورت', running:'در حال اجرا...', avg:'میانگین', handshake_ok:'هندشیک موفق',
 wd:'ری‌استارت دوره‌ای (watchdog)', wd_hint:'مستقل از بازیابی خطا (Restart=on-failure).', chg_pw:'تغییر رمز', old_pw:'رمز فعلی', new_pw:'رمز جدید (حداقل ۱۰ کاراکتر)',
 peer_cfg:'سرور طرف مقابل (سینک خودکار)', peer_hint:'دو پنل را با یک توکنِ مشترک جفت کن. بعد از آن، ویرایش‌های تونل خودکار به طرف مقابل push می‌شود. بینشان HTTPS استفاده کن.', peer_url:'آدرس پنلِ طرف مقابل', peer_token:'توکن مشترک', peer_token_ph:'توکن پنلِ دیگر را بچسبان', peer_pair:'جفت‌کردن', peer_gen:'ساخت توکن', peer_check:'بررسی طرف مقابل', peer_unpair:'قطع جفت', peer_paired:'جفت‌شده', peer_token_hint:'این توکن را در پنلِ دیگر وارد کن (تنظیمات > طرف مقابل)، بعد آدرس Peer هر دو را تنظیم کن.', panel_cfg:'آدرس وب‌پنل', panel_cfg_hint:'تغییر پورت/آدرس پنل را ری‌استارت می‌کند — روی آدرس جدید دوباره وصل می‌شوی.', panel_bind:'آدرس Bind', panel_port:'پورت', panel_save:'ذخیره و ری‌استارت پنل', panel_warn:'آدرس پنل عوض و همین حالا ری‌استارت شود؟ باید دوباره وصل شوی.', panel_disable:'غیرفعال‌کردن پنل', panel_dis_warn:'وب‌پنل متوقف و autostart خاموش شود؟ این نشست بسته می‌شود؛ دوباره فعال‌کردن: shadowtun panel enable', panel_disabled:'در حال غیرفعال‌کردن پنل…',
 lang:'زبان', copied:'کپی شد', copy:'کپی', not_listening:'SOCKS5 در حال شنیدن نیست', last_est:'آخرین هندشیک', ago:'پیش', never:'هرگز', build:'نسخه', role:'نقش',
 note_key:'کلید پیش‌اشتراکی هر بسته را احراز هویت می‌کند (HMAC). هر دو طرف باید کلید یکسان داشته باشند.', srv_test_hint:'۱۰ ثانیه به بسته‌های کلاینت گوش می‌دهد. همین‌جا اجرا را بزنید و هم‌زمان تست را روی کلاینت اجرا کنید.', no_tunnels:'هنوز تونلی نیست.', warnings:'هشدارها'
}};
const S = {csrf:'', meta:null, ov:null, view:'overview', lang:'', logs:{name:'', level:'', q:'', n:300, auto:true}, modal:0, timer:null, logTimer:null};
S.lang = localStorage.getItem('lang') || ((navigator.language||'').toLowerCase().startsWith('fa') ? 'fa' : 'en');
const t = k => (TR[S.lang][k] ?? TR.en[k] ?? k);

/* ---------- helpers ---------- */
function h(tag, attrs, ...kids){
  const e=document.createElement(tag);
  for(const [k,v] of Object.entries(attrs||{})){
    if(v===false||v==null) continue;
    if(k==='class') e.className=v; else if(k==='text') e.textContent=v;
    else if(k.startsWith('on')) e.addEventListener(k.slice(2),v);
    else if(k==='value'||k==='checked'||k==='disabled'||k==='selected') e[k]=v;
    else e.setAttribute(k,v===true?'':v);
  }
  for(const c of kids.flat(Infinity)){ if(c==null||c===false) continue; e.append(c.nodeType?c:document.createTextNode(String(c))); }
  return e;
}
const fmtB=n=>{n=+n||0;const u=['B','KB','MB','GB','TB'];let i=0;while(n>=1024&&i<4){n/=1024;i++}return (i?n.toFixed(1):Math.round(n))+' '+u[i]};
const fmtR=n=>fmtB(n)+'/s';
const fmtD=s=>{s=Math.floor(+s||0);const d=Math.floor(s/86400),hh=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);return d?`${d}d ${hh}h`:hh?`${hh}h ${m}m`:m?`${m}m ${s%60}s`:`${s}s`};
const fmtT=ts=>new Date(ts*1000).toLocaleTimeString([], {hour12:false});
function spark(vals,cls){
  const ns='http://www.w3.org/2000/svg',W=120,H=30,svg=document.createElementNS(ns,'svg');
  svg.setAttribute('viewBox',`0 0 ${W} ${H}`);svg.setAttribute('preserveAspectRatio','none');svg.setAttribute('class','spark '+(cls||''));
  if(!vals||vals.length<2) return svg;
  let max=1e-9;for(const v of vals) if(v>max) max=v;
  const n=vals.length,pts=vals.map((v,i)=>`${(i/(n-1)*W).toFixed(1)},${(H-2-(v/max)*(H-4)).toFixed(1)}`).join(' ');
  const pl=document.createElementNS(ns,'polyline');pl.setAttribute('points',pts);pl.setAttribute('fill','none');svg.appendChild(pl);return svg;
}
async function api(method,path,body){
  const o={method,headers:{'Content-Type':'application/json'},credentials:'same-origin'};
  if(method!=='GET') o.headers['X-CSRF-Token']=S.csrf;
  if(body!==undefined) o.body=JSON.stringify(body);
  const r=await fetch(path,o);let j={};try{j=await r.json()}catch(e){}
  if(r.status===401&&path!=='/api/login'){stopTimers();renderLogin();throw Object.assign(new Error('login'),{handled:true})}
  if(!r.ok) throw Object.assign(new Error(j.error||('HTTP '+r.status)),{data:j});
  return j;
}
function toast(msg,bad){const e=h('div',{class:'toast'+(bad?' bad':''),text:msg});document.body.append(e);setTimeout(()=>e.remove(),bad?6000:2800)}
async function copy(text){try{await navigator.clipboard.writeText(text)}catch(e){const i=h('input',{value:text});document.body.append(i);i.select();document.execCommand('copy');i.remove()}toast(t('copied'))}
function toggleTheme(){const r=document.documentElement,nx=r.getAttribute('data-theme')==='light'?'dark':'light';r.setAttribute('data-theme',nx);try{localStorage.setItem('theme',nx)}catch(e){}renderShell()}
function stopTimers(){clearInterval(S.timer);clearInterval(S.logTimer);S.timer=S.logTimer=null}
function fill(el,...kids){el.replaceChildren(...kids.flat(Infinity).filter(c=>c!=null&&c!==false))}
function applyLang(){document.documentElement.lang=S.lang;document.documentElement.dir=S.lang==='fa'?'rtl':'ltr'}

/* ---------- modal ---------- */
function openModal(content){
  closeModal();S.modal=1;
  const ov=h('div',{class:'overlay',id:'ovl',onclick:e=>{if(e.target===ov)closeModal()}},h('div',{class:'modal'},content));
  document.body.append(ov);return ov;
}
function closeModal(){const o=document.getElementById('ovl');if(o)o.remove();S.modal=0}

/* ---------- login ---------- */
function renderLogin(){
  applyLang();closeModal();
  const root=document.getElementById('app');root.replaceChildren();
  const user=h('input',{type:'text',name:'username',autocomplete:'username',value:'admin',class:'sr',tabindex:'-1','aria-hidden':'true'});
  const pw=h('input',{type:'password',name:'password',id:'pw',autocomplete:'current-password',placeholder:t('password'),required:true});
  const err=h('div',{class:'err'});
  const btn=h('button',{class:'btn pri',type:'submit',text:t('login')});
  const form=h('form',{method:'post',action:'#',autocomplete:'on'},user,h('label',{class:'f'},h('span',{text:t('password')}),pw),err,btn);
  form.addEventListener('submit',async e=>{e.preventDefault();err.textContent='';btn.disabled=true;
    try{const r=await api('POST','/api/login',{password:pw.value});S.csrf=r.csrf;boot()}catch(x){err.textContent=x.message;btn.disabled=false}});
  root.append(h('div',{class:'loginwrap'},h('div',{class:'login'},h('div',{class:'logo'},h('b',{text:'Shadow'}),' Spoof'),h('div',{class:'card'},form))));
  pw.focus();
}

/* ---------- shell ---------- */
async function boot(){
  try{
    const s=await api('GET','/api/session');S.csrf=s.csrf;
    S.meta=await api('GET','/api/meta');
  }catch(e){if(!e.handled)renderLogin();return}
  renderShell();
}
function renderShell(){
  applyLang();
  const root=document.getElementById('app');root.replaceChildren();
  const tabs=['overview','tunnels','events','logs','health','diagnose','settings'];
  root.append(
    h('header',{class:'top'},h('div',{class:'logo'},h('b',{text:'Shadow'}),' Spoof'),h('span',{class:'tag',text:S.meta.role||'?'}),h('div',{class:'sp'}),h('button',{class:'btn sm',title:'theme',onclick:toggleTheme,text:(document.documentElement.getAttribute('data-theme')==='light'?'\u263E':'\u2600')}),h('button',{class:'btn sm',onclick:()=>{S.lang=S.lang==='fa'?'en':'fa';localStorage.setItem('lang',S.lang);renderShell()},text:S.lang==='fa'?'EN':'FA'})),
    h('div',{class:'wrap',id:'main'}),
    h('nav',{class:'dock'},tabs.map(v=>h('button',{class:S.view===v?'on':'',onclick:()=>{S.view=v;renderShell()},text:t(v==='events'?'ev_tab':v)})))
  );
  stopTimers();showView();
}
function showView(){
  const m=document.getElementById('main');if(!m) return;
  if(S.view==='logs') return viewLogs(m);
  if(S.view==='health') return viewHealth(m);
  if(S.view==='diagnose') return viewDiagnose(m);
  if(S.view==='settings') return viewSettings(m);
  const tick=async()=>{ if(S.modal) return; try{S.ov=await api('GET','/api/overview')}catch(e){return} refreshPings(); const sy=window.scrollY; (S.view==='tunnels'?viewTunnels:S.view==='events'?viewEvents:viewOverview)(m); window.scrollTo(0,sy)};
  tick();S.timer=setInterval(tick,3000);
}

/* ---------- overview ---------- */
function statCard(label,val,sub,vals,cls){return h('div',{class:'card'},h('div',{class:'lbl',text:label}),h('div',{class:'big',text:val}),h('div',{class:'lbl',text:sub||'\u00a0'}),spark(vals,cls))}
function pill(a){const m={active:'ok',failed:'bad',activating:'warn',inactive:''};return h('span',{class:'pill '+(m[a]||'warn'),text:t(a)})}
function viewOverview(m){
  const o=S.ov,sy=o.system||{},sh=o.sys_history||{};
  fill(m,
    !o.monitor_up&&h('div',{class:'banner',text:t('monitor_down')}),
    h('div',{class:'grid'},
      statCard(t('cpu'),(sy.cpu??0)+'%','',sh.cpu,'pink'),
      statCard(t('mem'),sy.mem_total?Math.round(100*sy.mem_used/sy.mem_total)+'%':'-',fmtB(sy.mem_used)+' / '+fmtB(sy.mem_total),sh.mem),
      statCard(t('disk'),sy.disk_total?Math.round(100*sy.disk_used/sy.disk_total)+'%':'-',fmtB(sy.disk_used)+' / '+fmtB(sy.disk_total)),
      statCard(t('load'),(Array.isArray(sy.load)&&sy.load.length?sy.load[0].toFixed(2):'-'),fmtD(sy.uptime))),
    h('h2',{text:t('tunnels')}),
    o.tunnels.length?h('div',{class:'grid'},o.tunnels.map(tc)):h('div',{class:'card',text:t('no_tunnels')})
  );
}
function viewEvents(m){
  fill(m,h('h2',{text:t('events')}),h('div',{class:'card'},evList(S.ov.events,100)));
}
function evList(evs,max){
  if(!evs||!evs.length) return h('div',{class:'lbl',text:t('none')});
  return evs.slice().reverse().slice(0,max||25).map(e=>h('div',{class:'ev '+e.level},h('time',{class:'mono',text:fmtT(e.ts)}),h('span',{class:'tag',text:e.inst}),h('span',{class:'m mono',text:e.msg})));
}
let PING={},PINGAT={};
function refreshPings(){
  const now=Date.now();
  for(const x of (S.ov&&S.ov.tunnels)||[]){
    if(now-(PINGAT[x.name]||0)<9000) continue;
    PINGAT[x.name]=now;
    api('GET','/api/tunnels/'+x.name+'/ping').then(r=>{PING[x.name]=r}).catch(()=>{PING[x.name]={err:true}});
  }
}
function linkBox(x){
  const pg=PING[x.name],now=S.ov.now,hs=x.last_established;
  const chip=(c,txt)=>h('span',{class:'pill '+c,text:txt});
  if(!pg) return h('div',{class:'linkbox'},chip('warn',t('link_check')));
  const reach=pg.ping_ms!=null||pg.tcp_ms!=null||(hs&&now-hs<600);
  const parts=[chip(reach?'ok':'bad',reach?t('link_ok'):t('link_down')),
    chip(pg.ping_ms!=null?'ok':'warn',pg.ping_ms!=null?'ping '+pg.ping_ms+' ms':'ping \u2014')];
  if(pg.tcp_ms!=null) parts.push(chip('','tcp '+pg.tcp_ms+' ms'));
  parts.push(chip(hs?'ok':'warn',hs?t('hs')+' '+fmtD(now-hs)+' '+t('ago'):t('no_hs')));
  if(pg.peer_panel) parts.push(chip(pg.peer_panel.ok?'dim':'bad',t('peer_panel')+(pg.peer_panel.ok?' '+pg.peer_panel.ms+' ms':' \u2715')));
  return h('div',{class:'linkbox'},parts);
}
function tc(x,full){
  const c=x.config||{},hs=x.history||{},l5=x.log5||{info:0,warn:0,error:0};
  const kv=(k,v)=>h('div',{},h('span',{class:'lbl',text:k}),h('span',{class:'v',text:v}));
  const acts=[
    h('button',{class:'btn sm',onclick:()=>act(x.name,x.active==='active'?'restart':'start'),text:x.active==='active'?t('restart'):t('start')}),
    x.active==='active'&&h('button',{class:'btn sm',onclick:()=>act(x.name,'stop'),text:t('stop')}),
    h('button',{class:'btn sm',onclick:()=>{S.logs.name=x.name;S.view='logs';renderShell()},text:t('logs')})
  ];
  if(full) acts.push(
    h('button',{class:'btn sm',onclick:()=>formModal('edit',x),text:t('edit')}),
    h('button',{class:'btn sm',onclick:()=>linkModal(x),text:t('link')}),
    h('button',{class:'btn sm',onclick:()=>keyModal(x),text:t('key')}),
    h('button',{class:'btn sm',onclick:()=>testModal(x),text:t('test')}),
    x.name!=='main'&&h('button',{class:'btn sm dng',onclick:()=>del(x),text:t('del')}));
  return h('div',{class:'card'},
    h('div',{class:'row'},h('b',{text:x.name}),h('span',{class:'tag',text:x.role}),h('div',{class:'sp'}),pill(x.active)),
    h('div',{class:'lbl mono',text:`${c.real_ip||'?'} ⇄ ${c.peer_real_ip||'?'}  ·  UDP ${c.data_port||'?'} · ICMP ${c.icmp_id??'?'}`}),
    linkBox(x),
    h('div',{class:'kv'},
      kv(t('uptime'),fmtD(x.uptime)),kv(t('restarts'),x.restarts),kv(t('cpu'),(x.cpu??0)+'%'),kv(t('rss'),fmtB(x.rss)),
      kv(t('conns'),x.conns??0),x.role==='client'?kv('SOCKS5','127.0.0.1:'+(c.socks5_port||'?')):kv(t('f_tun'),c.tunnel_count),
      kv(t('rx'),fmtR(x.rx)),kv(t('tx'),fmtR(x.tx)),
      kv(t('last_est'),x.last_established?fmtD(S.ov.now-x.last_established)+' '+t('ago'):t('never')),
      kv('log 5m',`${l5.info} / ${l5.warn} / ${l5.error}`)),
    x.listening===false&&x.active==='active'&&h('div',{class:'pill bad',text:t('not_listening')}),
    h('div',{class:'two'},spark(hs.rx,''),spark(hs.conns,'grn')),
    h('div',{class:'row'},acts));
}
async function act(name,a){try{await api('POST',`/api/tunnels/${name}/${a}`);toast('OK');S.ov=await api('GET','/api/overview');showView()}catch(e){if(!e.handled)toast(e.message,1)}}
async function del(x){if(!confirm(t('confirm_del').replace('%s',x.name)))return;try{await api('DELETE','/api/tunnels/'+x.name);toast('OK');showView()}catch(e){if(!e.handled)toast(e.message,1)}}

/* ---------- tunnels ---------- */
function viewTunnels(m){
  const o=S.ov;
  m.replaceChildren(
    h('div',{class:'toolbar'},h('button',{class:'btn pri',onclick:()=>formModal('create'),text:'+ '+t('create')}),h('button',{class:'btn',onclick:importModal,text:t('import')})),
    h('div',{class:'grid'},o.tunnels.length?o.tunnels.map(x=>tc(x,true)):h('div',{class:'card',text:t('no_tunnels')})));
}
function fieldDefs(role){
  const me=t(role),peer=t(role==='client'?'server':'client');
  return [
   {sec:'sec_general'},
   {k:'name',l:t('f_name'),create:true},
   {k:'transport',l:t('f_transport'),hint:t('h_transport'),opts:[['spoof','UDP + ICMP (spoofed)'],['tcp','TCP (standard)']]},
   {sec:'sec_addr'},
   {k:'real_ip',l:`${t('f_real')} (${me})`},{k:'peer_real_ip',l:`${t('f_real')} (${peer})`},
   {k:'spoofed_ip',l:`${t('f_spoof')} (${me})`},{k:'peer_spoofed_ip',l:`${t('f_spoof')} (${peer})`},
   {k:'spoofed_ip_pool',l:t('f_pool'),list:true},
   {k:'allowed_peers',l:t('f_peerpool'),list:true,hint:t('h_peerpool')},
   {sec:'sec_port'},
   {k:'data_port',l:t('f_port')},{k:'icmp_id',l:t('f_icmp')},{k:'interface',l:t('f_iface'),select:true},
   role==='client'&&{k:'socks5_port',l:t('f_socks')},
   {sec:'sec_perf'},
   {k:'mtu',l:t('f_mtu')},{k:'initial_cwnd',l:t('f_cwnd')},
   {k:'max_retries',l:t('f_retries'),hint:t('h_retries')},{k:'rto_min_ms',l:t('f_rto'),hint:t('h_rto')},
   {k:'tunnel_count',l:t('f_tun')},
   {sec:'sec_rel'},
   {k:'auto_restart',l:t('f_autorestart'),hint:t('h_autorestart'),opts:[['on-failure',t('ar_fail')],['always',t('ar_always')],['no',t('ar_no')]]},
   {k:'restart_sec',l:t('f_restartsec')},
   {sec:'sec_sec'},
   {k:'pre_shared_key',l:t('f_key'),key:true}
  ].filter(Boolean);
}
function formModal(mode,x,prefill){
  const role=S.meta.role,defs=fieldDefs(role),d=S.meta.defaults,cfg=(x&&x.config)||{},inputs={},errs={};
  const init=k=>{
    if(prefill&&prefill[k]!=null) return Array.isArray(prefill[k])?prefill[k].join(','):String(prefill[k]);
    if(mode==='edit'){const v=cfg[k];return Array.isArray(v)?v.join(','):(v==null?'':String(v))}
    if(k==='real_ip') return S.meta.detect_ip||''; if(k in d) return String(d[k]); if(k==='interface') return 'auto'; return '';
  };
  const body=h('div',{});
  const rows=[];
  for(const f of defs){
    if(f.sec){rows.push(h('div',{class:'fsec',text:t(f.sec)}));continue}
    if(f.create&&mode==='edit') continue;
    let inp;
    if(f.opts){inp=h('select',{},f.opts.map(o=>h('option',{value:o[0],text:o[1]})));inp.value=init(f.k)||f.opts[0][0];if(![...inp.options].some(o=>o.value===inp.value))inp.value=f.opts[0][0]}
    else if(f.select){inp=h('select',{},h('option',{value:'auto',text:t('auto')}),S.meta.ifaces.map(i=>h('option',{value:i,text:i})));inp.value=init(f.k)||'auto';if(![...inp.options].some(o=>o.value===inp.value))inp.add(new Option(inp.value,inp.value)),inp.value=init(f.k)}
    else inp=h('input',{value:mode==='edit'&&f.key?'':init(f.k),autocomplete:'off',spellcheck:'false',class:'mono'});
    inputs[f.k]=inp;errs[f.k]=h('div',{class:'err'});
    rows.push(h('label',{class:'f'},h('span',{text:f.l}),f.key?h('div',{class:'row'},inp,h('button',{class:'btn sm',type:'button',onclick:async()=>{inp.value=(await api('POST','/api/keygen',{})).key},text:t('gen')})):inp,f.hint&&h('div',{class:'hint',text:f.hint}),errs[f.k]));
  }
  const globalErr=h('div',{class:'err'});
  const save=h('button',{class:'btn pri',text:t('save')});
  save.addEventListener('click',async()=>{
    const data={};for(const f of defs){if(f.sec||(f.create&&mode==='edit'))continue;data[f.k]=inputs[f.k].value.trim()}
    for(const k in errs) errs[k].textContent='';globalErr.textContent='';save.disabled=true;
    try{
      const r=mode==='edit'?await api('PUT','/api/tunnels/'+x.name,data):await api('POST','/api/tunnels',data);
      closeModal();toast(t(mode==='edit'?'saved':'created')+(r.warnings&&r.warnings.length?' - '+r.warnings.join('; '):''));
      if(mode==='create'&&r.link) keyModal({name:r.name,role},r);
      S.ov=await api('GET','/api/overview');showView();
    }catch(e){
      if(e.handled)return;
      const er=(e.data&&e.data.errors)||{};for(const k in er) if(errs[k]) errs[k].textContent=er[k];
      globalErr.textContent=e.message;
    }finally{save.disabled=false}
  });
  openModal([h('h3',{text:mode==='edit'?`${t('edit')}: ${x.name}`:t('create')}),h('div',{class:'two'},rows),globalErr,h('div',{class:'row'},save,h('button',{class:'btn',onclick:closeModal,text:t('cancel')}))]);
}
function importModal(){
  const ta=h('input',{class:'mono',placeholder:'shadowspoof://...'}),err=h('div',{class:'err'});
  const go=async()=>{try{const r=await api('POST','/api/link/parse',{link:ta.value});closeModal();formModal('create',null,r.fields)}catch(e){if(!e.handled)err.textContent=e.message}};
  openModal([h('h3',{text:t('import')}),h('label',{class:'f'},h('span',{text:t('paste_link')}),ta),err,h('div',{class:'row'},h('button',{class:'btn pri',onclick:go,text:t('apply')}),h('button',{class:'btn',onclick:closeModal,text:t('cancel')}))]);
}
function keyView(r){
  return [h('div',{class:'lbl',text:t('f_key')}),h('div',{class:'copy mono',text:r.key}),h('div',{class:'row'},h('button',{class:'btn sm',onclick:()=>copy(r.key),text:t('copy')}),h('span',{class:'lbl',text:`${t('fp')}: ${r.fp}`})),
    h('div',{class:'lbl',text:'Link'}),h('div',{class:'copy mono',text:r.link}),h('div',{class:'row'},h('button',{class:'btn sm',onclick:()=>copy(r.link),text:t('copy')})),
    h('div',{class:'hint',text:t('link_hint')}),h('div',{class:'hint',text:t('note_key')})];
}
async function linkModal(x){
  let r; try{ r=await api('GET','/api/tunnels/'+x.name+'/link'); }catch(e){ if(!e.handled)toast(e.message,1); return; }
  openModal([h('h3',{text:t('link')+': '+x.name}),
    h('div',{class:'hint',text:t('link_hint')}),
    h('div',{class:'copy mono',text:r.link}),
    h('div',{class:'hint',text:t('fp')+': '+(r.fp||'?')}),
    h('div',{class:'row'},
      h('button',{class:'btn pri',text:t('copy'),onclick:()=>{try{navigator.clipboard.writeText(r.link);toast(t('copied'))}catch(e){toast(t('copied'))}}}),
      h('button',{class:'btn',onclick:closeModal,text:t('close')}))]);
}
function keyModal(x,known){
  if(known&&known.key) return openModal([h('h3',{text:`${t('key')}: ${x.name}`}),keyView(known),h('button',{class:'btn',onclick:closeModal,text:t('close')})]);
  const pw=h('input',{type:'password'}),err=h('div',{class:'err'}),out=h('div',{});
  const go=async()=>{try{const r=await api('POST',`/api/tunnels/${x.name}/secret`,{password:pw.value});pw.value='';fill(out,keyView(r))}catch(e){if(!e.handled)err.textContent=e.message}};
  pw.addEventListener('keydown',e=>{if(e.key==='Enter')go()});
  openModal([h('h3',{text:`${t('key')}: ${x.name}`}),h('label',{class:'f'},h('span',{text:t('pw_confirm')}),pw),err,out,h('div',{class:'row'},h('button',{class:'btn pri',onclick:go,text:t('reveal')}),h('button',{class:'btn',onclick:closeModal,text:t('close')}))]);
  pw.focus();
}
function testModal(x){
  const client=x.role==='client';
  const host=h('input',{value:'example.com',class:'mono'}),port=h('input',{value:'80',class:'mono'}),out=h('div',{});
  const go=async()=>{
    out.replaceChildren(h('div',{class:'lbl',text:t('running')+(client?' (~20s)':' (10s)')}));
    try{
      const r=await api('POST',`/api/tunnels/${x.name}/test`,{host:host.value,port:port.value,secs:10});
      const sym=v=>v===true?'✓':v===false?'✕':'i',cls=v=>v===true?'ok':v===false?'fail':'info';
      out.replaceChildren(
        h('div',{class:'pill '+({ok:'ok',warn:'warn',fail:'bad'}[r.verdict]),text:r.summary}),
        ...r.steps.map(z=>h('div',{class:'chk'},h('div',{class:'i '+cls(z.ok),text:sym(z.ok)}),h('div',{},h('div',{text:z.title}),z.detail&&h('div',{class:'hint',text:z.detail})))));
    }catch(e){if(!e.handled)out.replaceChildren(h('div',{class:'err',text:e.message}))}
  };
  openModal([h('h3',{text:`${t('test')}: ${x.name}`}),
    client?h('div',{class:'two'},h('label',{class:'f'},h('span',{text:t('host')}),host),h('label',{class:'f'},h('span',{text:t('port')}),port)):h('div',{class:'hint',text:t('srv_test_hint')}),
    h('div',{class:'row'},h('button',{class:'btn pri',onclick:go,text:t('run')}),h('button',{class:'btn',onclick:closeModal,text:t('close')})),out]);
}

/* ---------- logs ---------- */
async function viewLogs(m){
  S.ov=await api('GET','/api/overview').catch(()=>S.ov);
  const names=(S.ov.tunnels||[]).map(x=>x.name);
  if(!names.includes(S.logs.name)) S.logs.name=names[0]||'';
  const pane=h('pre',{class:'log mono'});
  const sel=h('select',{},names.map(n=>h('option',{value:n,text:n})));sel.value=S.logs.name;
  const lvl=h('select',{},['','INFO','WARN','ERROR','DEBUG'].map(v=>h('option',{value:v,text:v||'ALL'})));lvl.value=S.logs.level;
  const q=h('input',{value:S.logs.q,placeholder:t('search'),class:'mono'});
  const n=h('select',{},[100,300,1000].map(v=>h('option',{value:v,text:v})));n.value=S.logs.n;
  const auto=h('input',{type:'checkbox',checked:S.logs.auto});
  const load=async()=>{
    if(!S.logs.name) return;
    try{
      const r=await api('GET',`/api/tunnels/${S.logs.name}/logs?n=${S.logs.n}&level=${S.logs.level}&q=${encodeURIComponent(S.logs.q)}`);
      const atBottom=pane.scrollTop+pane.clientHeight>=pane.scrollHeight-30;
      pane.replaceChildren(...r.rows.map(x=>h('div',{class:'lv-'+x.level},h('span',{class:'t',text:fmtT(x.ts)+' '}),x.msg)));
      if(atBottom) pane.scrollTop=pane.scrollHeight;
    }catch(e){}
  };
  const upd=()=>{S.logs.name=sel.value;S.logs.level=lvl.value;S.logs.q=q.value;S.logs.n=+n.value;S.logs.auto=auto.checked;load()};
  [sel,lvl,n,auto].forEach(e=>e.addEventListener('change',upd));q.addEventListener('input',()=>{clearTimeout(q._t);q._t=setTimeout(upd,300)});
  m.replaceChildren(
    h('div',{class:'two'},h('label',{class:'f'},h('span',{text:t('tunnels')}),sel),h('label',{class:'f'},h('span',{text:t('level')}),lvl),h('label',{class:'f'},h('span',{text:t('search')}),q),h('label',{class:'f'},h('span',{text:t('lines')}),n)),
    h('label',{class:'row'},auto,h('span',{text:t('auto_refresh')})),pane,
    h('h2',{text:t('events')}),h('div',{class:'card'},evList(S.ov.events)));
  await load();pane.scrollTop=pane.scrollHeight;
  S.logTimer=setInterval(()=>{if(S.logs.auto&&!S.modal)load()},2000);
}

/* ---------- health ---------- */
function viewHealth(m){
  const out=h('div',{class:'card'});
  const run=async()=>{out.replaceChildren(h('div',{class:'lbl',text:t('running')}));
    try{const r=await api('GET','/api/health');out.replaceChildren(...r.checks.map(c=>h('div',{class:'chk'},h('div',{class:'i '+c.level,text:{ok:'✓',warn:'!',fail:'✕',info:'i'}[c.level]}),h('div',{},h('div',{text:c.title}),c.hint&&h('div',{class:'hint',text:c.hint})))))}catch(e){}};
  m.replaceChildren(h('button',{class:'btn pri',onclick:run,text:t('run')}),h('div',{class:'lbl',text:'\u00a0'}),out);run();
}

/* ---------- diagnose (tunnel doctor) ---------- */
function viewDiagnose(m){
  const sev={ok:'\u2713',warn:'!',fail:'\u2715',info:'i'};
  const link=h('input',{class:'mono',placeholder:'shadowspoof://\u2026',autocapitalize:'off',autocomplete:'off',spellcheck:'false'});
  const out=h('div',{class:'card'});
  const run=async()=>{
    out.replaceChildren(h('div',{class:'lbl',text:t('running')}));
    try{
      const r=await api('POST','/api/diagnose',{name:'main',link:(link.value||'').trim()});
      const s=r.summary||{};
      const head=h('div',{class:'dhead'},
        h('span',{class:'pill '+(s.fail?'bad':s.warn?'warn':'ok'),text:(s.fail||0)+' \u2715'}),
        h('span',{class:'pill warn',text:(s.warn||0)+' !'}),
        h('span',{class:'pill ok',text:(s.ok||0)+' \u2713'}));
      const rows=(r.findings||[]).map(c=>h('div',{class:'chk'},
        h('div',{class:'i '+c.level,text:sev[c.level]||'i'}),
        h('div',{class:'ctext'},
          h('div',{class:'row'},h('span',{text:c.title}),c.field&&h('span',{class:'tag',text:c.field})),
          c.detail&&h('div',{class:'hint',text:c.detail}),
          c.fix&&h('div',{class:'hint fix',text:'\u2192 '+c.fix}))));
      out.replaceChildren(head,...rows);
    }catch(e){if(!e.handled)out.replaceChildren(h('div',{class:'err',text:e.message}))}
  };
  const mout=h('div',{class:'hint'});
  const tnames=(S.ov&&S.ov.tunnels||[]).map(x=>x.name); if(!tnames.length) tnames.push('main');
  const tsel=h('select',{},tnames.map(n=>h('option',{value:n,text:n})));
  const mtu=async()=>{
    mout.textContent=t('running');
    const nm=tsel.value||'main';
    try{
      const r=await api('POST','/api/mtu',{name:nm});
      mout.replaceChildren(
        h('div',{},t('mtu_path')+': '+r.path_mtu+'  \u00b7  '+t('mtu_rec')+': '+r.recommended_mtu+'  \u00b7  '+t('mtu_cur')+': '+(r.current_mtu||'-')),
        h('div',{class:'row'},h('button',{class:'btn sm',text:t('mtu_apply'),onclick:async()=>{try{await api('PUT','/api/tunnels/'+nm,{mtu:r.recommended_mtu});toast(t('saved'))}catch(e){if(!e.handled)toast(e.message,1)}}})));
    }catch(e){if(!e.handled)mout.textContent=e.message}
  };
  m.replaceChildren(
    h('div',{class:'card'},
      h('b',{text:t('diag_title')}),
      h('div',{class:'hint',text:t('diag_hint')}),
      h('label',{class:'f'},h('span',{text:t('peer_link')}),link),
      h('div',{class:'row'},
        h('button',{class:'btn pri',onclick:run,text:t('run_diag')})),
      h('div',{class:'lbl',text:'\u00a0'}),
      h('div',{class:'row'},
        h('span',{class:'lbl',text:t('mtu_for')}),tsel,
        h('button',{class:'btn',onclick:mtu,text:t('mtu_test')})),
      mout),
    h('div',{class:'lbl',text:'\u00a0'}),
    out);
  run();
}

/* ---------- settings ---------- */
async function viewSettings(m){
  const st=await api('GET','/api/settings').catch(()=>({watchdog:'off'}));
  // update card
  const ubuild=h('div',{class:'hint',text:t('running')});
  const ulog=h('pre',{class:'log ulog'});
  const ubtn=h('button',{class:'btn pri',text:t('upd_now')});
  const ucheck=h('button',{class:'btn',text:t('upd_check')});
  const uref=async(chk)=>{
    try{
      const r=await api('GET','/api/update/status'+(chk===false?'?check=0':''));
      const st=r.running?t('upd_running'):r.error?r.error:r.available?t('upd_avail'):t('upd_latest');
      ubuild.textContent=t('upd_cur')+': '+(r.current||'?')+(r.latest?'  ·  '+t('upd_new')+': '+r.latest:'')+'  ·  '+st;
      ulog.textContent=r.log||'';ulog.scrollTop=ulog.scrollHeight;
      ubtn.disabled=!r.available||!!r.running;
      if(r.running){clearInterval(S.timer);S.timer=setInterval(()=>uref(false),3000)} else if(S.timer){clearInterval(S.timer);S.timer=null}
    }catch(e){ubuild.textContent=t('upd_reconnect');clearInterval(S.timer);S.timer=setInterval(()=>uref(false),4000)}
  };
  ubtn.onclick=async()=>{if(!confirm(t('upd_warn')))return;try{await api('POST','/api/update',{});toast(t('upd_started'));uref(false)}catch(e){if(!e.handled)toast(e.message,1)}};
  ucheck.onclick=()=>uref(true);
  uref(true);
  // peer server pairing + status + auto-sync
  const pr=await api('GET','/api/peer').catch(()=>({paired:false,peer_url:''}));
  const purl=h('input',{value:pr.peer_url||'',placeholder:'https://<peer-ip>:7788'});
  const ptok=h('input',{placeholder:t('peer_token_ph')});
  const pstat=h('div',{class:'hint',text:t('peer_paired')+': '+(pr.paired?'✓':'—')});
  const pgen=h('button',{class:'btn',text:t('peer_gen'),onclick:async()=>{try{const r=await api('POST','/api/peer',{generate:true});if(r.sync_token)openModal([h('h3',{text:t('peer_token')}),h('div',{class:'hint',text:t('peer_token_hint')}),h('div',{class:'copy mono',text:r.sync_token}),h('button',{class:'btn',onclick:closeModal,text:t('close')})]);toast(t('saved'))}catch(e){if(!e.handled)toast(e.message,1)}}});
  const ppair=h('button',{class:'btn pri',text:t('peer_pair'),onclick:async()=>{try{const body={peer_url:purl.value.trim()};if(ptok.value.trim())body.sync_token=ptok.value.trim();await api('POST','/api/peer',body);ptok.value='';toast(t('saved'))}catch(e){if(!e.handled)toast(e.message,1)}}});
  const pcheck=h('button',{class:'btn',text:t('peer_check'),onclick:async()=>{pstat.textContent=t('running');try{const r=await api('GET','/api/peer/status');pstat.replaceChildren(h('div',{},'✓ '+(r.host||'')+' ('+(r.role||'')+')  ·  build '+(r.build||'?')),...(r.tunnels||[]).map(x=>h('div',{class:'hint'},x.name+': '+(x.active||'?')+'  ·  '+x.transport+'  ·  port '+(x.data_port||'?'))));}catch(e){if(!e.handled)pstat.replaceChildren(h('div',{class:'err',text:e.message}))}}});
  const punpair=h('button',{class:'btn dng',text:t('peer_unpair'),onclick:async()=>{try{await api('POST','/api/peer',{unpair:true});toast(t('saved'))}catch(e){if(!e.handled)toast(e.message,1)}}});
  const wd=h('select',{},['off','30m','1h','6h','12h','24h'].map(v=>h('option',{value:v,text:v})));wd.value=st.watchdog;
  const wdBtn=h('button',{class:'btn',text:t('apply'),onclick:async()=>{try{await api('POST','/api/settings/watchdog',{value:wd.value});toast(t('saved'))}catch(e){if(!e.handled)toast(e.message,1)}}});
  const o=h('input',{type:'password',autocomplete:'current-password'}),n=h('input',{type:'password',autocomplete:'new-password'}),perr=h('div',{class:'err'});
  const pwBtn=h('button',{class:'btn',text:t('save'),onclick:async()=>{perr.textContent='';try{await api('POST','/api/settings/password',{old:o.value,new:n.value});o.value=n.value='';toast(t('saved'))}catch(e){if(!e.handled)perr.textContent=e.message}}});
  // web-panel address / TLS / enable
  const pbind=h('input',{value:st.bind||'127.0.0.1'});
  const pport=h('input',{value:st.port||7777,inputmode:'numeric'});
  const ptls=h('select',{},[['off','HTTP'],['on','HTTPS (TLS)']].map(a=>h('option',{value:a[0],text:a[1]})));ptls.value=st.tls?'on':'off';
  const psave=h('button',{class:'btn',text:t('panel_save'),onclick:async()=>{if(!confirm(t('panel_warn')))return;try{const r=await api('POST','/api/settings/panel',{bind:pbind.value.trim(),port:+pport.value,tls:ptls.value==='on'});toast(r.note||t('saved'))}catch(e){if(!e.handled)toast(e.message,1)}}});
  const pdis=h('button',{class:'btn dng',text:t('panel_disable'),onclick:async()=>{if(!confirm(t('panel_dis_warn')))return;try{await api('POST','/api/settings/panel/toggle',{on:false});toast(t('panel_disabled'))}catch(e){if(!e.handled)toast(e.message,1)}}});
  const b=(S.meta.build||{});
  m.replaceChildren(
    h('div',{class:'card'},h('b',{text:t('upd_title')}),h('div',{class:'hint',text:t('upd_hint')}),ubuild,h('div',{class:'row'},ubtn,ucheck),ulog),
    h('div',{class:'lbl',text:'\u00a0'}),
    h('div',{class:'card'},h('b',{text:t('peer_cfg')}),h('div',{class:'hint',text:t('peer_hint')}),
      h('label',{class:'f'},h('span',{text:t('peer_url')}),purl),
      h('label',{class:'f'},h('span',{text:t('peer_token')}),ptok),
      h('div',{class:'row'},ppair,pgen,pcheck,punpair),
      pstat),
    h('div',{class:'lbl',text:' '}),
    h('div',{class:'card'},h('b',{text:t('panel_cfg')}),h('div',{class:'hint',text:t('panel_cfg_hint')}),
      h('div',{class:'two'},h('label',{class:'f'},h('span',{text:t('panel_bind')}),pbind),h('label',{class:'f'},h('span',{text:t('panel_port')}),pport)),
      h('label',{class:'f'},h('span',{text:'TLS'}),ptls),
      h('div',{class:'row'},psave,pdis)),
    h('div',{class:'lbl',text:'\u00a0'}),
    h('div',{class:'card'},h('b',{text:t('wd')}),h('div',{class:'hint',text:t('wd_hint')}),h('div',{class:'row'},wd,wdBtn)),
    h('div',{class:'lbl',text:'\u00a0'}),
    h('div',{class:'card'},h('b',{text:t('chg_pw')}),h('label',{class:'f'},h('span',{text:t('old_pw')}),o),h('label',{class:'f'},h('span',{text:t('new_pw')}),n),perr,pwBtn),
    h('div',{class:'lbl',text:'\u00a0'}),
    h('div',{class:'card'},h('div',{class:'kv'},h('div',{},h('span',{class:'lbl',text:t('role')}),h('span',{class:'v',text:S.meta.role})),h('div',{},h('span',{class:'lbl',text:t('build')}),h('span',{class:'v mono',text:(b.commit||'?').slice(0,12)})),h('div',{},h('span',{class:'lbl',text:'Panel'}),h('span',{class:'v',text:`${st.bind||'?'}:${st.port||'?'} ${st.tls?'TLS':'HTTP'}`}))),
      h('div',{class:'row'},h('button',{class:'btn',text:t('logout'),onclick:async()=>{try{await api('POST','/api/logout',{})}catch(e){}stopTimers();renderLogin()}}))));
}

/* ---------- start ---------- */
applyLang();
api('GET','/api/session').then(()=>boot()).catch(e=>{if(!e.handled)renderLogin()});
</script>
</body>
</html>
'''


class Req(object):
    pass


class Handler(BaseHTTPRequestHandler):
    server_version = "ShadowPanel"
    sys_version = ""
    timeout = 30
    protocol_version = "HTTP/1.1"

    def setup(self):
        if getattr(self.server, "tls", False):
            self.request.settimeout(10)
            self.request.do_handshake()
        BaseHTTPRequestHandler.setup(self)

    def log_message(self, fmt, *args):
        pass

    def _headers(self, code, ctype, length, extra=None, nonce=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        if nonce:
            self.send_header("Content-Security-Policy",
                             "default-src 'none'; script-src 'nonce-%s'; style-src 'nonce-%s'; connect-src 'self'; "
                             "img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'" % (nonce, nonce))
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers()

    def _json(self, code, obj, extra=None):
        body = json.dumps(obj).encode()
        self._headers(code, "application/json", len(body), extra)
        self.wfile.write(body)

    def _cookie(self):
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "cs_session":
                return v
        return ""

    def _dispatch(self, method):
        u = urlparse(self.path)
        path = u.path
        if method == "GET" and path in ("/", "/index.html"):
            nonce = secrets.token_urlsafe(16)
            body = INDEX_HTML.replace("__NONCE__", nonce).encode()
            self._headers(200, "text/html; charset=utf-8", len(body), nonce=nonce)
            self.wfile.write(body)
            return
        if not path.startswith("/api/"):
            self._json(404, {"error": "not found"})
            return
        ip = self.client_address[0]
        req = Req()
        req.query = parse_qs(u.query)
        req.token = self._cookie()
        req.json = {}
        if method in ("POST", "PUT", "DELETE"):
            n = int(self.headers.get("Content-Length") or 0)
            if n > 65536:
                self._json(413, {"error": "body too large"})
                return
            raw = self.rfile.read(n) if n else b""
            if raw:
                try:
                    req.json = json.loads(raw.decode())
                    if not isinstance(req.json, dict):
                        raise ValueError
                except ValueError:
                    self._json(400, {"error": "invalid JSON"})
                    return
        try:
            if path == "/api/login" and method == "POST":
                return self._login(ip, req)
            # Peer-sync channel: authenticated by a shared token, not a session.
            if path.startswith("/api/sync/"):
                want = str(load_panel().get("sync_token") or "")
                tok = self.headers.get("X-Sync-Token") or ""
                if not want or not hmac.compare_digest(tok, want):
                    self._json(401, {"error": "sync auth failed"})
                    return
                if method == "GET" and path == "/api/sync/overview":
                    self._json(200, api_sync_overview(req)); return
                if method == "POST" and path == "/api/sync/apply":
                    self._json(200, api_sync_apply(req)); return
                self._json(404, {"error": "not found"}); return
            sess = get_session(req.token)
            if not sess:
                self._json(401, {"error": "login required"})
                return
            if method != "GET":
                origin = self.headers.get("Origin")
                if origin and urlparse(origin).netloc != self.headers.get("Host"):
                    self._json(403, {"error": "bad origin"})
                    return
                if not hmac.compare_digest(self.headers.get("X-CSRF-Token") or "", sess["csrf"]):
                    self._json(403, {"error": "bad CSRF token"})
                    return
            self._json(200, self._route(method, path, req, sess))
        except ApiError as e:
            body = {"error": e.msg}
            body.update(e.extra)
            self._json(e.status, body)
        except Exception as e:
            sys.stderr.write("panel error on %s %s: %r\n" % (method, path, e))
            self._json(500, {"error": "internal error"})

    def _login(self, ip, req):
        if locked_out(ip):
            self._json(429, {"error": "too many attempts, try again in a few minutes"})
            return
        pw = str(req.json.get("password", ""))
        if check_pw(pw, load_panel().get("pw", {})):
            FAILS.pop(ip, None)
            tok, csrf = new_session(ip)
            cookie = "cs_session=%s; HttpOnly; SameSite=Strict; Path=/; Max-Age=86400%s" % (
                tok, "; Secure" if getattr(self.server, "tls", False) else "")
            self._json(200, {"ok": True, "csrf": csrf}, [("Set-Cookie", cookie)])
        else:
            note_fail(ip)
            sys.stderr.write("panel: failed login from %s\n" % ip)
            time.sleep(0.5)
            self._json(401, {"error": "wrong password"})

    def _route(self, method, path, req, sess):
        if method == "GET":
            if path == "/api/session":
                return {"csrf": sess["csrf"]}
            if path == "/api/overview":
                return api_overview(req)
            if path == "/api/meta":
                return api_meta(req)
            if path == "/api/health":
                return api_health(req)
            if path == "/api/settings":
                return api_settings_get(req)
            if path == "/api/peer":
                return api_peer_get(req)
            if path == "/api/peer/status":
                return api_peer_status(req)
            if path == "/api/update/status":
                return api_update_status(req)
            m = re.match(r"^/api/tunnels/([a-z0-9-]+)/logs$", path)
            if m:
                return api_logs(req, m.group(1))
            m = re.match(r"^/api/tunnels/([a-z0-9-]+)/link$", path)
            if m:
                return api_tunnel_link(req, m.group(1))
            m = re.match(r"^/api/tunnels/([a-z0-9-]+)/ping$", path)
            if m:
                return api_tunnel_ping(req, m.group(1))
        elif method == "POST":
            if path == "/api/logout":
                with SESS_LOCK:
                    SESSIONS.pop(req.token, None)
                return {"ok": True}
            if path == "/api/keygen":
                return api_keygen(req)
            if path == "/api/tunnels":
                return api_create(req)
            if path == "/api/link/parse":
                return api_link_parse(req)
            if path == "/api/diagnose":
                return api_diagnose(req)
            if path == "/api/mtu":
                return api_mtu(req)
            if path == "/api/settings/watchdog":
                return api_watchdog(req)
            if path == "/api/settings/password":
                return api_password(req)
            if path == "/api/settings/panel":
                return api_panel_cfg(req)
            if path == "/api/settings/panel/toggle":
                return api_panel_toggle(req)
            if path == "/api/peer":
                return api_peer_set(req)
            if path == "/api/update":
                return api_update_start(req)
            m = re.match(r"^/api/tunnels/([a-z0-9-]+)/(start|stop|restart)$", path)
            if m:
                return api_action(req, m.group(1), m.group(2))
            m = re.match(r"^/api/tunnels/([a-z0-9-]+)/secret$", path)
            if m:
                return api_secret(req, m.group(1))
            m = re.match(r"^/api/tunnels/([a-z0-9-]+)/test$", path)
            if m:
                return api_test(req, m.group(1))
        elif method == "PUT":
            m = re.match(r"^/api/tunnels/([a-z0-9-]+)$", path)
            if m:
                return api_edit(req, m.group(1))
        elif method == "DELETE":
            m = re.match(r"^/api/tunnels/([a-z0-9-]+)$", path)
            if m:
                return api_delete(req, m.group(1))
        raise ApiError(404, "not found")

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_PUT(self):
        self._dispatch("PUT")

    def do_DELETE(self):
        self._dispatch("DELETE")


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64

    def handle_error(self, request, client_address):
        pass


def cmd_panel():
    cfg = load_panel()
    if not cfg.get("pw"):
        sys.exit("panel: no password configured (run: shadowtun panel passwd)")
    bind, port = cfg.get("bind", "127.0.0.1"), int(cfg.get("port", 7777))
    srv = Server((bind, port), Handler)
    srv.tls = False
    if cfg.get("tls"):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(os.path.join(ETC, "panel.crt"), os.path.join(ETC, "panel.key"))
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True, do_handshake_on_connect=False)
        srv.tls = True
    signal.signal(signal.SIGTERM, lambda *a: threading.Thread(target=srv.shutdown, daemon=True).start())
    sys.stderr.write("panel listening on %s://%s:%d\n" % ("https" if srv.tls else "http", bind, port))
    sys.stderr.flush()
    srv.serve_forever()


# ------------------------------------------------------------------ CLI views --
def human(n):
    n = float(n)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or u == "TB":
            return ("%.0f %s" if u == "B" else "%.1f %s") % (n, u)
        n /= 1024


def dur(s):
    s = int(s)
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    return ("%dd " % d if d else "") + ("%dh " % h if h or d else "") + "%dm %ds" % (m, s)


def cmd_monitor_view():
    C = {"r": "\033[31m", "g": "\033[32m", "y": "\033[33m", "b": "\033[36m", "d": "\033[2m", "0": "\033[0m"}
    try:
        while True:
            st = load_state()
            out = []
            if not st or time.time() - st.get("ts", 0) > 30:
                out.append(C["r"] + "monitor service is not running (systemctl start shadow-spoof-monitor)" + C["0"])
            else:
                s = st["system"]
                out.append("%sShadow Spoof monitor%s  role=%s  cpu %.0f%%  mem %s/%s  load %s  up %s" % (
                    C["b"], C["0"], st["role"], s["cpu"], human(s["mem_used"]), human(s["mem_total"]),
                    " ".join("%.2f" % x for x in s["load"]), dur(s["uptime"])))
                out.append("")
                out.append("%-14s %-10s %-10s %6s %9s %6s %12s %12s %s" % (
                    "TUNNEL", "STATE", "UPTIME", "CPU%", "RSS", "CONNS", "RX/s", "TX/s", "LOG(5m) i/w/e"))
                for n, i in st["instances"].items():
                    col = C["g"] if i["active"] == "active" else C["r"]
                    l5 = i["log5"]
                    out.append("%-14s %s%-10s%s %-10s %6.1f %9s %6d %12s %12s %d/%s%d%s/%s%d%s" % (
                        n, col, i["active"], C["0"], dur(i["uptime"]), i["cpu"], human(i["rss"]), i["conns"],
                        human(i["rx"]), human(i["tx"]), l5["info"], C["y"], l5["warn"], C["0"], C["r"], l5["error"], C["0"]))
                    if i.get("listening") is False and i["active"] == "active":
                        out.append("    %s! SOCKS5 port not listening%s" % (C["r"], C["0"]))
                out.append("")
                out.append(C["d"] + "recent events" + C["0"])
                for ev in st["events"][-12:]:
                    col = {"error": C["r"], "warn": C["y"]}.get(ev["level"], C["0"])
                    out.append("  %s %s%-5s%s [%s] %s" % (time.strftime("%H:%M:%S", time.localtime(ev["ts"])), col,
                                                         ev["level"], C["0"], ev["inst"], ev["msg"][:110]))
            sys.stdout.write("\033[H\033[2J" + "\n".join(out) + "\n\n(Ctrl-C to quit)\n")
            sys.stdout.flush()
            time.sleep(1)
    except KeyboardInterrupt:
        pass


def cmd_log_view(minlevel):
    role = get_role()
    if not role:
        sys.exit("not installed")
    minl = LEVEL_ORDER.get((minlevel or "info").upper(), 2)
    col = {"ERROR": "\033[31m", "WARN": "\033[33m", "INFO": "\033[0m", "DEBUG": "\033[2m", "TRACE": "\033[2m"}
    p = subprocess.Popen([JOURNALCTL, "-f", "-n", "50", "--no-pager", "-q", "-o", "json",
                          "-u", "shadow-spoof-%s.service" % role, "-u", "shadow-spoof-%s@*.service" % role],
                         stdout=subprocess.PIPE, text=True)
    try:
        for line in p.stdout:
            e = journal_entry(line)
            if not e:
                continue
            ts, msg, prio, unit = e
            lvl, _ = classify(msg, prio)
            if LEVEL_ORDER[lvl] < minl:
                continue
            sys.stdout.write("%s %s%-5s\033[0m [%s] %s\n" % (time.strftime("%H:%M:%S", time.localtime(ts)), col[lvl],
                                                              lvl, unit_to_name(unit) or "?", msg.strip()))
            sys.stdout.flush()
    except KeyboardInterrupt:
        pass
    finally:
        p.terminate()


# --------------------------------------------------------------------- admin --
def panel_url(cfg):
    host = cfg.get("bind", "127.0.0.1")
    if host in ("0.0.0.0", "::"):
        host = detect_ip() or "SERVER_IP"
    return "%s://%s:%s" % ("https" if cfg.get("tls") else "http", host, cfg.get("port", 7777))


def cmd_admin(argv):
    ap = argparse.ArgumentParser(prog="shadow-panel admin")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("init")
    a.add_argument("--bind", default="127.0.0.1")
    a.add_argument("--port", type=int, default=7777)
    a.add_argument("--tls", type=int, default=0)
    sub.add_parser("passwd")  # new password from stdin
    sub.add_parser("passwd-random")
    sub.add_parser("info")
    s = sub.add_parser("set")
    s.add_argument("key", choices=["bind", "port", "tls"])
    s.add_argument("value")
    args = ap.parse_args(argv)
    cfg = load_panel()
    if args.cmd == "init":
        cfg.update({"bind": args.bind, "port": args.port, "tls": bool(args.tls)})
        save_panel(cfg)
    elif args.cmd == "passwd":
        pw = sys.stdin.readline().rstrip("\n")
        if len(pw) < 10:
            sys.exit("password must be at least 10 characters")
        cfg["pw"] = hash_pw(pw)
        save_panel(cfg)
    elif args.cmd == "passwd-random":
        pw = secrets.token_urlsafe(14)
        cfg["pw"] = hash_pw(pw)
        save_panel(cfg)
        print(pw)
    elif args.cmd == "info":
        print(panel_url(cfg))
    elif args.cmd == "set":
        if args.key == "port":
            p = as_int(args.value, 1, 65535)
            if not p:
                sys.exit("invalid port")
            cfg["port"] = p
        elif args.key == "bind":
            if not v_ip(args.value):
                sys.exit("invalid IPv4 address")
            cfg["bind"] = args.value
        else:
            cfg["tls"] = args.value in ("1", "on", "true", "yes")
        save_panel(cfg)


# ------------------------------------------------------------- CLI helpers ----
def _pick_inst(name):
    insts = instances()
    if not insts:
        sys.exit("not installed")
    if not name:
        return insts[0]
    for i in insts:
        if i.name == name:
            return i
    sys.exit("no such tunnel: %s (have: %s)" % (name, ", ".join(i.name for i in insts)))


def cmd_test(argv):
    ap = argparse.ArgumentParser(prog="shadowtun test")
    ap.add_argument("-t", "--tunnel", default="")
    ap.add_argument("--host", default="example.com")
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--secs", type=int, default=10)
    a = ap.parse_args(argv)
    inst = _pick_inst(a.tunnel)
    if inst.role == "server":
        print("Server test: capturing for %ds. Run 'shadowtun test' on the CLIENT now.\n" % a.secs)
    else:
        print("Testing tunnel '%s' via %s:%d (takes ~20 s)...\n" % (inst.name, a.host, a.port))
    r = run_test(inst, a.host, a.port, a.secs)
    sym = {True: "\033[32m PASS \033[0m", False: "\033[31m FAIL \033[0m", None: "\033[33m INFO \033[0m"}
    for st in r["steps"]:
        print("[%s] %s" % (sym[st["ok"]], st["title"]))
        if st["detail"]:
            print("         %s" % st["detail"])
    col = {"ok": "\033[32m", "warn": "\033[33m", "fail": "\033[31m"}[r["verdict"]]
    print("\n%s=> %s\033[0m" % (col, r["summary"]))
    sys.exit(0 if r["verdict"] == "ok" else 1)


def cmd_cfg(argv):
    ap = argparse.ArgumentParser(prog="shadowtun set")
    ap.add_argument("action", choices=["set", "edit", "show"])
    ap.add_argument("-t", "--tunnel", default="")
    ap.add_argument("pairs", nargs="*")
    a = ap.parse_args(argv)
    inst = _pick_inst(a.tunnel)
    if a.action == "show":
        print(read_text(inst.path), end="")
        return
    try:
        if a.action == "set":
            data = {}
            for pr in a.pairs:
                if "=" not in pr:
                    sys.exit("expected key=value, got: %s" % pr)
                k, v = pr.split("=", 1)
                k = k.strip()
                if k not in ("real_ip", "peer_real_ip", "spoofed_ip", "peer_spoofed_ip", "spoofed_ip_pool", "allowed_peers",
                             "data_port", "icmp_id", "tunnel_count", "mtu", "initial_cwnd", "interface", "socks5_port",
                             "pre_shared_key"):
                    sys.exit("unknown field: %s" % k)
                data[k] = v.strip().strip('"')
            if not data:
                sys.exit("nothing to set")
            active, warn = apply_edit(inst, data, "edited with shadowctl")
        else:
            editor = os.environ.get("VISUAL") or os.environ.get("EDITOR") or next(
                (e for e in ("nano", "vi") if subprocess.call(["which", e], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0), "vi")
            fd, tmp = tempfile.mkstemp(prefix="shadow-edit-", suffix=".toml")
            os.close(fd)
            try:
                with open(tmp, "w") as f:
                    f.write(read_text(inst.path))
                while True:
                    subprocess.call(editor.split() + [tmp])
                    data = parse_toml(read_text(tmp))
                    clean, errs = validate(inst.role, data, inst.name, inst.cfg())
                    if not errs:
                        break
                    print("\nInvalid configuration:")
                    for k, v in errs.items():
                        print("  %s: %s" % (k, v))
                    if input("\n[Enter] edit again, [q] discard: ").strip().lower() == "q":
                        print("discarded")
                        return
                active, warn = apply_edit(inst, data, "edited with shadowctl")
            finally:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
    except ApiError as e:
        print("error: %s" % e.msg)
        for k, v in (e.extra.get("errors") or {}).items():
            print("  %s: %s" % (k, v))
        sys.exit(1)
    for w in warn:
        print("warning: %s" % w)
    print("saved; service is %s" % active)


def cmd_link(argv):
    if argv and argv[0] == "parse":
        try:
            d = parse_link(sys.stdin.readline())
        except Exception as e:
            sys.exit("invalid link: %s" % e)
        print("role\t%s" % d["role"])
        for k in ("real_ip", "peer_real_ip", "spoofed_ip", "peer_spoofed_ip", "data_port", "icmp_id",
                  "tunnel_count", "mtu", "initial_cwnd", "pre_shared_key"):
            if k in d:
                print("%s\t%s" % (k, d[k]))
        print("spoofed_pool\t%s" % ",".join(d.get("spoofed_ip_pool", [])))
        print("peer_pool\t%s" % ",".join(d.get("allowed_peers", [])))
        return
    name = argv[1] if len(argv) > 1 and argv[0] == "make" else (argv[0] if argv else "")
    inst = _pick_inst(name if name != "make" else "")
    print(make_link(inst.name, inst.role, inst.cfg()))


def cmd_diagnose(argv):
    ap = argparse.ArgumentParser(prog="shadowtun diagnose")
    ap.add_argument("-t", "--tunnel", default="main")
    ap.add_argument("--link", default="")
    args = ap.parse_args(argv)

    class _Req:
        pass
    req = _Req()
    req.json = {"name": args.tunnel, "link": args.link}
    try:
        r = api_diagnose(req)
    except ApiError as e:
        sys.exit("diagnose: %s" % e)

    tty = sys.stdout.isatty()
    C = {"ok": "\033[32m", "warn": "\033[33m", "fail": "\033[31m", "info": "\033[36m", "0": "\033[0m"} if tty \
        else {k: "" for k in ("ok", "warn", "fail", "info", "0")}
    sym = {"ok": "✓", "warn": "!", "fail": "✕", "info": "i"}
    for f in r["findings"]:
        lvl = f["level"]
        line = "%s%s%s %s" % (C.get(lvl, ""), sym.get(lvl, "i"), C["0"], f["title"])
        if f.get("field"):
            line += "  [%s]" % f["field"]
        print(line)
        if f.get("detail"):
            print("    " + f["detail"])
        if f.get("fix"):
            print("    %s→ %s%s" % (C["info"], f["fix"], C["0"]))
    s = r["summary"]
    print("\n%d fail · %d warn · %d ok" % (s.get("fail", 0), s.get("warn", 0), s.get("ok", 0)))
    sys.exit(1 if s.get("fail", 0) else 0)


def cmd_mtu(argv):
    ap = argparse.ArgumentParser(prog="shadowtun mtu")
    ap.add_argument("-t", "--tunnel", default="main")
    args = ap.parse_args(argv)

    class _R:
        pass
    req = _R()
    req.json = {"name": args.tunnel}
    try:
        r = api_mtu(req)
    except ApiError as e:
        sys.exit("mtu: %s" % e)
    print("peer %s: path MTU %d  ->  recommended tunnel mtu %d  (current %s)"
          % (r["peer"], r["path_mtu"], r["recommended_mtu"], r.get("current_mtu")))
    print("apply with:  shadowtun -t %s set mtu=%d" % (args.tunnel, r["recommended_mtu"]))


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    cmd = sys.argv[1]
    if cmd == "panel":
        cmd_panel()
    elif cmd == "monitor":
        cmd_monitor()
    elif cmd == "monitor-view":
        cmd_monitor_view()
    elif cmd == "log-view":
        cmd_log_view(sys.argv[2] if len(sys.argv) > 2 else "info")
    elif cmd == "admin":
        cmd_admin(sys.argv[2:])
    elif cmd == "test":
        cmd_test(sys.argv[2:])
    elif cmd == "cfg":
        cmd_cfg(sys.argv[2:])
    elif cmd == "link":
        cmd_link(sys.argv[2:])
    elif cmd == "mtu":
        cmd_mtu(sys.argv[2:])
    elif cmd == "diagnose":
        cmd_diagnose(sys.argv[2:])
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
SHADOW_PANEL_PY_EOF
  chmod 0755 "$PANEL_PY.new"; chown root:root "$PANEL_PY.new"
  if ! cmp -s "$PANEL_PY.new" "$PANEL_PY" 2>/dev/null; then PANEL_CHANGED=1; fi
  mv -f "$PANEL_PY.new" "$PANEL_PY"
  python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' || die "python >= 3.8 is required"
}

link_prefill() { # let the operator paste the setup link produced by the other side
  [[ $NONINTERACTIVE == 1 ]] && return 0
  local link out k v
  echo >&2
  printf 'Paste the shadowspoof:// setup link from the other side (Enter = type values manually): ' >&2
  IFS= read -r link <"$TTY_IN" || return 0
  link=${link//[[:space:]]/}
  [[ -z $link ]] && return 0
  if ! out=$(printf '%s\n' "$link" | "${PY3[@]}" link parse 2>&1); then warn "$out"; return 0; fi
  if [[ $(printf '%s\n' "$out" | sed -n 's/^role\t//p') != "$ROLE" ]]; then
    warn "this link is meant for the other role; ignoring it"; return 0
  fi
  while IFS=$'\t' read -r k v; do
    case $k in
      real_ip|peer_real_ip|spoofed_ip|peer_spoofed_ip|data_port|icmp_id|tunnel_count|mtu|initial_cwnd)
        printf -v "SHADOW_${k^^}" '%s' "$v"; export "SHADOW_${k^^}" ;;
      pre_shared_key) SHADOW_PRE_SHARED_KEY=$v; export SHADOW_PRE_SHARED_KEY ;;
      spoofed_pool)   SHADOW_SPOOFED_POOL=$v; export SHADOW_SPOOFED_POOL ;;
      peer_pool)      SHADOW_PEER_POOL=$v; export SHADOW_PEER_POOL ;;
    esac
  done <<<"$out"
  ok "Loaded the link - you will only be asked for values that are local to this host."
}

ensure_panel_cert() {
  [[ -f $ETC_DIR/panel.crt && -f $ETC_DIR/panel.key ]] && return 0
  command -v openssl >/dev/null || die "openssl is required for HTTPS (install it or choose HTTP)"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
    -subj "/CN=shadow-spoof" -keyout "$ETC_DIR/panel.key" -out "$ETC_DIR/panel.crt" >/dev/null 2>&1
  chmod 0600 "$ETC_DIR/panel.key"; chmod 0644 "$ETC_DIR/panel.crt"
}

ask_panel() {
  PANEL_ENABLE=1
  if [[ -f $PANEL_JSON ]]; then
    PANEL_KEEP=1
    if [[ $NONINTERACTIVE == 1 ]]; then [[ ${SHADOW_PANEL_RECONFIGURE:-0} == 1 ]] && PANEL_KEEP=0
    elif ! ask_yn "Web panel is already configured. Keep its settings?" y; then PANEL_KEEP=0; fi
    (( PANEL_KEEP )) && return 0
  fi
  if [[ ${SHADOW_PANEL-} == 0 ]]; then PANEL_ENABLE=0; return 0; fi
  if [[ $NONINTERACTIVE != 1 ]]; then
    echo >&2
    ask_yn "Install the web panel (monitor tunnels, create/edit tunnels, run tests)?" y || { PANEL_ENABLE=0; return 0; }
  fi
  local panel_bind panel_port
  ask panel_bind "Panel listen address (127.0.0.1 = local only, 0.0.0.0 = all interfaces)" "127.0.0.1" v_ipv4 "IPv4 address"
  ask panel_port "Panel port" "7777" v_port "1-65535"
  PANEL_BIND=$panel_bind; PANEL_PORT=$((10#$panel_port)); PANEL_TLS=0
  if [[ $PANEL_BIND != 127.* ]]; then
    if [[ -n ${SHADOW_PANEL_TLS-} ]]; then [[ $SHADOW_PANEL_TLS == 1 ]] && PANEL_TLS=1
    elif ask_yn "Serve the panel over HTTPS with a self-signed certificate?" y; then PANEL_TLS=1; fi
    warn "The panel is reachable from the network: open TCP/$PANEL_PORT only to addresses you trust."
  fi
}

write_aux_units() {
  local py; py=$(command -v python3)
  cat >"$UNIT_DIR/shadow-spoof-monitor.service" <<UNIT
[Unit]
Description=Shadow Spoof monitor (metrics and log sampler)
After=shadow-spoof-$ROLE.service

[Service]
Type=simple
User=$SVC_USER
Group=$SVC_USER
SupplementaryGroups=systemd-journal
ExecStart=$py $PANEL_PY monitor
Restart=always
RestartSec=3
Environment=PYTHONDONTWRITEBYTECODE=1
RuntimeDirectory=shadow-spoof
RuntimeDirectoryMode=0755
RuntimeDirectoryPreserve=yes
ReadWritePaths=$STATE_DIR/monitor
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallArchitectures=native
CapabilityBoundingSet=
UMask=0022

[Install]
WantedBy=multi-user.target
UNIT
  cat >"$UNIT_DIR/shadow-spoof-panel.service" <<UNIT
[Unit]
Description=Shadow Spoof web panel
Wants=network-online.target
After=network-online.target shadow-spoof-monitor.service

[Service]
Type=simple
ExecStart=$py $PANEL_PY panel
Restart=always
RestartSec=3
Environment=PYTHONDONTWRITEBYTECODE=1
# Runs as root because it manages systemd units and the config files; confined as far as that allows.
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=$ETC_DIR $UNIT_DIR
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6
RestrictNamespaces=yes
RestrictRealtime=yes
LockPersonality=yes
SystemCallArchitectures=native
UMask=0077

[Install]
WantedBy=multi-user.target
UNIT
  chmod 0644 "$UNIT_DIR/shadow-spoof-monitor.service" "$UNIT_DIR/shadow-spoof-panel.service"
}

setup_panel() {
  write_aux_units
  systemctl daemon-reload
  # monitor: always (feeds `shadowtun monitor` and the panel)
  systemctl enable shadow-spoof-monitor.service >/dev/null 2>&1
  if systemctl is-active --quiet shadow-spoof-monitor.service; then
    (( PANEL_CHANGED )) && systemctl restart shadow-spoof-monitor.service
  else systemctl start shadow-spoof-monitor.service; fi
  ok "Monitor service running (shadowtun monitor)"
  if (( ! PANEL_ENABLE )); then return 0; fi

  if (( ! PANEL_KEEP )); then
    "${PY3[@]}" admin init --bind "$PANEL_BIND" --port "$PANEL_PORT" --tls "$PANEL_TLS"
    if [[ -n ${SHADOW_PANEL_PASSWORD-} ]]; then
      printf '%s\n' "$SHADOW_PANEL_PASSWORD" | "${PY3[@]}" admin passwd || die "SHADOW_PANEL_PASSWORD must be at least 10 characters"
      PANEL_PW_SHOWN=$SHADOW_PANEL_PASSWORD
    else
      PANEL_PW_SHOWN=$("${PY3[@]}" admin passwd-random)
    fi
  fi
  if grep -q '"tls": true' "$PANEL_JSON"; then ensure_panel_cert; fi
  systemctl enable shadow-spoof-panel.service >/dev/null 2>&1
  if systemctl is-active --quiet shadow-spoof-panel.service; then
    if (( PANEL_CHANGED || ! PANEL_KEEP )); then systemctl restart shadow-spoof-panel.service; fi
  else systemctl start shadow-spoof-panel.service; fi
  sleep 1
  systemctl is-active --quiet shadow-spoof-panel.service || { journalctl -u shadow-spoof-panel.service -n 20 --no-pager >&2 || true; die "panel failed to start"; }
  ok "Web panel running at $("${PY3[@]}" admin info)"
}

setup_watchdog() {
  local want=${SHADOW_WATCHDOG-}
  if [[ -z $want ]]; then
    if [[ -r $ETC_DIR/watchdog ]]; then want=$(<"$ETC_DIR/watchdog")
    elif [[ $NONINTERACTIVE == 1 ]]; then want=off
    else
      echo >&2
      while :; do
        printf 'Periodic restart watchdog [off/30m/1h/6h/12h/24h] (off): ' >&2
        IFS= read -r want <"$TTY_IN" || die "input closed"; want=${want:-off}
        case $want in off|30m|1h|6h|12h|24h) break;; esac
      done
    fi
  fi
  "$SHADOWCTL" watchdog "$want" >/dev/null
  ok "Watchdog: $want"
}

verify_config() { # validate $CONF with the built binary before (re)starting the service
  local bin=$BIN_DIR/shadow-spoof-$ROLE out rc
  [[ -x $bin ]] || return 0
  out=$("$bin" --config "$CONF" --check-config 2>&1); rc=$?
  case $rc in
    0) ok "Configuration accepted by the parser ($bin --check-config)";
       # surface any non-fatal warnings the binary printed
       printf '%s\n' "$out" | grep -i 'WARN' >&2 || true ;;
    1) printf '%s\n' "$out" >&2
       die "the generated config was rejected by the parser - fix $CONF and re-run" ;;
    *) warn "installed binary does not support --check-config; skipping pre-start validation" ;;
  esac
}

start_service() {
  local unit=shadow-spoof-$ROLE.service
  verify_config
  systemctl daemon-reload
  systemctl enable "$unit" >/dev/null 2>&1
  if systemctl is-active --quiet "$unit"; then
    if (( ${BINARY_CHANGED:-0} || ${RECONFIGURED:-0} )); then info "Restarting $unit"; systemctl restart "$unit"; fi
  else
    info "Starting $unit"; systemctl start "$unit"
  fi
  sleep 2
  if ! systemctl is-active --quiet "$unit"; then
    journalctl -u "$unit" -n 30 --no-pager >&2 || true
    die "$unit is not running - see the log above"
  fi
  if [[ $ROLE == client ]]; then
    local p; p=$(cfg_get socks5_port)
    local i; for i in 1 2 3 4 5 6 7 8 9 10; do
      ss -H -ltn "sport = :$p" | awk '{print $4}' | grep -qx "127.0.0.1:$p" && { ok "SOCKS5 listening on 127.0.0.1:$p"; break; }
      sleep 0.5
    done
  fi
  ok "$unit is active"
}

summary() {
  echo >&2
  ok "Installation complete ($ROLE @ ${BUILD_REF:0:12})"
  echo "  shadowtun status | tunnels | test | monitor | logs | config edit | set k=v | watchdog <v>" >&2
  if [[ $ROLE == client ]]; then
    echo "  shadowtun socks-port <PORT>   change the local SOCKS5 port" >&2
    echo "  Test the tunnel end to end:  shadowtun test" >&2
  else
    echo "  Make sure the firewall passes inbound UDP/$(cfg_get data_port) and ICMP echo from the client." >&2
    echo "  Then run  shadowtun test  on the server AND on the client at the same time." >&2
  fi
  warn "pre_shared_key is validated but not yet enforced on the wire (packets are not authenticated); interface is now bound via SO_BINDTODEVICE."
}

final_report() { # printed last, to the terminal only (never to logs)
  local out=/dev/stdout key link
  { : >/dev/tty; } 2>/dev/null && out=/dev/tty
  key=$(<"$PSK_FILE")
  link=$("${PY3[@]}" link make main 2>/dev/null || true)
  {
    echo
    echo "=================================================================="
    echo " PRE-SHARED KEY  (show again any time:  shadowtun token)"
    echo
    echo "   $key"
    echo
    echo "   fingerprint: $(key_fingerprint "$key")"
    if [[ -n $link ]]; then
      echo
      echo " SETUP LINK for the other side (contains the key and all matching values)."
      local other=server; [[ $ROLE == server ]] && other=client
      echo " Paste it into the $other installer, or panel > Tunnels > Import link:"
      echo
      echo "   $link"
    fi
    if (( PANEL_ENABLE )) && [[ -f $PANEL_JSON ]]; then
      echo
      echo " WEB PANEL: $("${PY3[@]}" admin info)"
      if [[ -n $PANEL_PW_SHOWN ]]; then echo "   password: $PANEL_PW_SHOWN   (shown once)"
      else echo "   password: unchanged  (reset with: shadowtun panel passwd)"; fi
      if [[ $("${PY3[@]}" admin info) == *//127.0.0.1:* ]]; then
        echo "   local only - from your PC:  ssh -L 7777:127.0.0.1:$(sed -n 's/.*"port": *\([0-9]*\).*/\1/p' "$PANEL_JSON") root@<this-server>"
      fi
    fi
    echo "=================================================================="
    echo
  } >"$out"
}

migrate_legacy() { # move a pre-rename candy-spoof install to the shadow-spoof layout
  local old_etc=/etc/candy-spoof old_state=/var/lib/candy-spoof old_lib=/usr/local/lib/candy-spoof
  [[ -d $old_etc && ! -e $ETC_DIR ]] || return 0
  warn "Legacy 'candy-spoof' install found - migrating to 'shadow-spoof' (config, keys and tunnels are preserved)"
  local u
  for u in $(systemctl list-unit-files --no-legend 'candy-spoof-*' 2>/dev/null | awk '{print $1}'); do
    systemctl disable --now "$u" >/dev/null 2>&1 || true
  done
  rm -f  /etc/systemd/system/candy-spoof-*.service /etc/systemd/system/candy-spoof-*.timer 2>/dev/null || true
  rm -rf /etc/systemd/system/candy-spoof-*.service.d 2>/dev/null || true
  systemctl daemon-reload 2>/dev/null || true
  mkdir -p "$(dirname "$ETC_DIR")"; mv "$old_etc" "$ETC_DIR"
  if [[ -d $old_state ]]; then rm -rf "$STATE_DIR"; mkdir -p "$(dirname "$STATE_DIR")"; mv "$old_state" "$STATE_DIR"; fi
  rm -f  /usr/local/bin/candy-spoof-client /usr/local/bin/candy-spoof-server \
         /usr/local/bin/candyctl /usr/local/bin/candyshadow 2>/dev/null || true
  rm -rf "$old_lib" 2>/dev/null || true
  ok "Migrated $old_etc -> $ETC_DIR"
}

main() {
  parse_args "$@"
  require_root "$@"
  require_env
  setup_tty
  migrate_legacy
  choose_role
  install_deps
  ensure_user
  build_and_install
  install_panel_files
  ask_panel
  configure
  write_service_unit
  install_shadowctl
  install_shadowtun
  setup_watchdog
  start_service
  setup_panel
  summary
  final_report
}

if [[ -z ${BASH_SOURCE[0]-} || ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
