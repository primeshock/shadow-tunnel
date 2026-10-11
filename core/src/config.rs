//! Configuration types for Shadow Spoof.
//!
//! Both client and server share this configuration schema. Load with
//! `Config::from_file("config/client.toml")`.

use std::net::Ipv4Addr;
use serde::Deserialize;

/// Top-level configuration loaded from a TOML file.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// The real (physical) IPv4 address of this node.
    pub real_ip: Ipv4Addr,

    /// The real IPv4 address of the remote peer.
    pub peer_real_ip: Ipv4Addr,

    /// Transport mode: "spoof" (default: UDP data + ICMP control over raw
    /// sockets with a forged source IP) or "tcp" (a standard, non-spoofed TCP
    /// connection between the two real IPs).  The spoof-only fields below are
    /// ignored in "tcp" mode.
    #[serde(default = "default_transport")]
    pub transport: String,

    /// The spoofed source IP this node puts in outgoing packets (spoof mode).
    #[serde(default = "unspecified_ip")]
    pub spoofed_ip: Ipv4Addr,

    /// The spoofed source IP the peer uses (expected in incoming packets).
    #[serde(default = "unspecified_ip")]
    pub peer_spoofed_ip: Ipv4Addr,

    /// Optional pool of spoofed IPs for rotation.  If empty, `spoofed_ip` is
    /// always used.
    #[serde(default)]
    pub spoofed_ip_pool: Vec<Ipv4Addr>,

    /// UDP destination port used for the data channel.
    pub data_port: u16,

    /// ICMP echo identifier used to distinguish Shadow Spoof control packets
    /// from regular ping traffic (spoof mode).
    #[serde(default)]
    pub icmp_id: u16,

    /// Whitelist of peer real IPs whose packets are accepted. In addition to
    /// `peer_real_ip`, any address in this list is trusted.
    #[serde(default)]
    pub allowed_peers: Vec<Ipv4Addr>,

    /// Number of independent parallel tunnels to maintain.
    #[serde(default = "default_tunnel_count")]
    pub tunnel_count: usize,

    /// Pre-shared key (hex string) used to authenticate packets.  Both sides
    /// must share the same key.
    pub pre_shared_key: String,

    /// Network interface name to bind raw sockets to (e.g. "eth0", "ens3").
    /// Spoof mode only; ignored in "tcp" mode.
    #[serde(default)]
    pub interface: String,

    /// Port for the local SOCKS5 proxy (client only, ignored on server).
    #[serde(default = "default_socks5_port")]
    pub socks5_port: u16,

    /// Maximum payload size per tunnel packet (bytes, default 1380).
    #[serde(default = "default_mtu")]
    pub mtu: usize,

    /// Initial congestion window in packets.
    #[serde(default = "default_cwnd")]
    pub initial_cwnd: f64,

    /// Maximum number of times a packet is retransmitted before it is given up
    /// on.  Raising it helps on very lossy links at the cost of latency; the
    /// default preserves the historical behaviour.  Does not change how many
    /// packets are sent in the common (no-loss) case.
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,

    /// Floor for the retransmission timeout, in milliseconds.  Raising it avoids
    /// spurious retransmissions on high-latency/jittery censored links; the
    /// default preserves the historical behaviour.
    #[serde(default = "default_rto_min_ms")]
    pub rto_min_ms: u64,
}

fn default_transport() -> String { "spoof".into() }
fn unspecified_ip() -> Ipv4Addr { Ipv4Addr::UNSPECIFIED }
fn default_tunnel_count() -> usize { 4 }
fn default_socks5_port() -> u16 { 1080 }
fn default_mtu() -> usize { 1380 }
fn default_cwnd() -> f64 { 10.0 }
// These mirror the historical constants in arq.rs (MAX_RETRIES) and
// congestion.rs (RttEstimator::MIN_RTO_MS) so defaults change no behaviour.
fn default_max_retries() -> u32 { 8 }
fn default_rto_min_ms() -> u64 { 200 }

/// Robustness knobs applied to each tunnel's ARQ/congestion state.  Keeping
/// these in one `Copy` struct avoids threading several parameters through every
/// tunnel constructor.  Defaults preserve the historical behaviour.
#[derive(Debug, Clone, Copy)]
pub struct Tuning {
    pub max_retries: u32,
    pub rto_min_ms: u64,
}

impl Default for Tuning {
    fn default() -> Self {
        Self { max_retries: default_max_retries(), rto_min_ms: default_rto_min_ms() }
    }
}

/// Error raised when a loaded [`Config`] fails semantic validation.
///
/// Kept separate from the I/O and TOML-syntax errors produced by
/// [`Config::from_file`] so that callers (and operators reading the logs) can
/// tell a *missing/invalid value* apart from a *malformed file*.
#[derive(Debug, thiserror::Error)]
#[error("invalid configuration: {0}")]
pub struct ValidationError(pub String);

impl Config {
    /// Load configuration from a TOML file.
    ///
    /// This performs I/O and TOML parsing only.  Call [`Config::validate`] (or
    /// use [`Config::load`]) to additionally check the values for sanity.
    pub fn from_file(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Cannot read config '{}': {}", path, e))?;
        toml::from_str(&content)
            .map_err(|e| anyhow::anyhow!("Invalid config '{}': {}", path, e))
    }

    /// Load and validate configuration from a TOML file.
    ///
    /// `client` selects client-specific checks (e.g. the SOCKS5 port).
    pub fn load(path: &str, client: bool) -> anyhow::Result<Self> {
        let cfg = Self::from_file(path)?;
        cfg.validate(client)
            .map_err(|e| anyhow::anyhow!("Config '{}': {}", path, e))?;
        Ok(cfg)
    }

    /// Check the loaded values for sanity, returning a [`ValidationError`] that
    /// names the offending field.  Non-fatal oddities are reported via
    /// [`Config::warnings`] instead.
    pub fn validate(&self, client: bool) -> Result<(), ValidationError> {
        let err = |m: String| Err(ValidationError(m));

        match self.transport.as_str() {
            "spoof" | "tcp" => {}
            other => return err(format!(
                "transport must be \"spoof\" or \"tcp\" (got {:?})", other
            )),
        }
        if self.pre_shared_key.trim().is_empty() {
            return err("pre_shared_key must not be empty (both peers must share \
                        the same key)".into());
        }
        if self.data_port == 0 {
            return err("data_port must be between 1 and 65535".into());
        }
        if client && self.socks5_port == 0 {
            return err("socks5_port must be between 1 and 65535 on the client".into());
        }
        // The raw-socket interface and the spoofed-source addresses only matter
        // in spoof mode; tcp mode uses an ordinary kernel socket.
        if self.is_spoof() {
            if self.interface.trim().is_empty() {
                return err("interface must name the network device to bind raw \
                            sockets to (e.g. \"eth0\") in spoof mode".into());
            }
            if self.spoofed_ip.is_unspecified() || self.peer_spoofed_ip.is_unspecified() {
                return err("spoofed_ip and peer_spoofed_ip are required in spoof \
                            mode".into());
            }
        }
        if self.tunnel_count == 0 {
            return err("tunnel_count must be at least 1".into());
        }
        // The protocol header is 20 bytes and rides inside a UDP or ICMP
        // payload; anything below ~1 byte of payload is useless, and values
        // above a jumbo IP payload cannot be represented.
        if self.mtu == 0 || self.mtu > 65_000 {
            return err(format!(
                "mtu must be between 1 and 65000 (got {})",
                self.mtu
            ));
        }
        if !(self.initial_cwnd.is_finite() && self.initial_cwnd >= 1.0) {
            return err(format!(
                "initial_cwnd must be a finite number >= 1.0 (got {})",
                self.initial_cwnd
            ));
        }
        if !(1..=100).contains(&self.max_retries) {
            return err(format!(
                "max_retries must be between 1 and 100 (got {})",
                self.max_retries
            ));
        }
        if !(10..=60_000).contains(&self.rto_min_ms) {
            return err(format!(
                "rto_min_ms must be between 10 and 60000 (got {})",
                self.rto_min_ms
            ));
        }
        Ok(())
    }

    /// The robustness knobs applied to each tunnel.
    pub fn tuning(&self) -> Tuning {
        Tuning { max_retries: self.max_retries, rto_min_ms: self.rto_min_ms }
    }

    /// True when the raw-socket, source-spoofing transport is selected (default).
    pub fn is_spoof(&self) -> bool { self.transport != "tcp" }

    /// True when the standard-socket TCP transport is selected.
    pub fn is_tcp(&self) -> bool { self.transport == "tcp" }

    /// Non-fatal configuration observations, suitable for logging at startup.
    /// These never block startup but help operators spot mistakes and surface
    /// currently-unenforced settings honestly (see the project's known
    /// limitations).
    pub fn warnings(&self) -> Vec<String> {
        let mut w = Vec::new();

        // The installer generates a hex key of >= 32 chars; flag anything that
        // does not look like one so a hand-edited key mismatch is noticed.
        let key = self.pre_shared_key.trim();
        let looks_hex = !key.is_empty() && key.bytes().all(|b| b.is_ascii_hexdigit());
        if !looks_hex || key.len() < 32 {
            w.push(format!(
                "pre_shared_key does not look like the expected >=32-char hex \
                 string (len {}); both peers must use the identical key",
                key.len()
            ));
        }

        // The remaining notes are about the spoof data path; they do not apply
        // to the tcp transport.
        if self.is_spoof() {
            // `pick_spoofed_ip` uses ONLY the pool when it is non-empty, so a
            // pool that omits `spoofed_ip` silently stops that address from
            // being used.
            if !self.spoofed_ip_pool.is_empty() && !self.spoofed_ip_pool.contains(&self.spoofed_ip) {
                w.push(format!(
                    "spoofed_ip {} is not in spoofed_ip_pool; when a pool is set \
                     only pool addresses are used",
                    self.spoofed_ip
                ));
            }
            // Be honest about fields parsed but not wired into the data path.
            // Each SOCKS5 connection already opens its own independent tunnel,
            // so tunnel_count has no effect; packet-level duplication is
            // deliberately not implemented.
            if self.tunnel_count != 1 {
                w.push(format!(
                    "tunnel_count = {} has no effect: each connection already uses \
                     its own tunnel and per-packet redundancy is not implemented",
                    self.tunnel_count
                ));
            }
        }

        w
    }

    /// Returns true if `ip` is a trusted peer address.
    pub fn is_peer_allowed(&self, ip: &Ipv4Addr) -> bool {
        *ip == self.peer_real_ip
            || *ip == self.peer_spoofed_ip
            || self.allowed_peers.contains(ip)
    }

    /// Pick a (possibly random) spoofed source IP from the configured pool.
    /// Falls back to `spoofed_ip` when the pool is empty.
    pub fn pick_spoofed_ip(&self) -> Ipv4Addr {
        if self.spoofed_ip_pool.is_empty() {
            return self.spoofed_ip;
        }
        use rand::seq::SliceRandom;
        *self
            .spoofed_ip_pool
            .choose(&mut rand::thread_rng())
            .unwrap_or(&self.spoofed_ip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal, valid configuration as TOML.  Tests mutate individual lines
    /// to exercise the parser and the validator.
    fn valid_toml() -> String {
        let hex_key = "a".repeat(32);
        format!(
            r#"
real_ip         = "10.0.0.1"
peer_real_ip    = "203.0.113.1"
spoofed_ip      = "8.8.4.4"
peer_spoofed_ip = "1.2.3.4"
data_port       = 51820
icmp_id         = 0x4321
pre_shared_key  = "{hex_key}"
interface       = "eth0"
mtu             = 1380
initial_cwnd    = 10.0
"#
        )
    }

    fn parse(toml: &str) -> Config {
        toml::from_str(toml).expect("config should parse")
    }

    #[test]
    fn parses_minimal_config_with_defaults() {
        let cfg = parse(&valid_toml());
        assert_eq!(cfg.tunnel_count, 4); // default
        assert_eq!(cfg.socks5_port, 1080); // default
        assert!(cfg.spoofed_ip_pool.is_empty());
        assert_eq!(cfg.icmp_id, 0x4321);
        // New tuning knobs default to the historical constants.
        assert_eq!(cfg.max_retries, 8);
        assert_eq!(cfg.rto_min_ms, 200);
        assert_eq!(cfg.tuning().max_retries, 8);
        cfg.validate(true).expect("minimal config should be valid");
    }

    #[test]
    fn defaults_to_spoof_transport() {
        let cfg = parse(&valid_toml());
        assert_eq!(cfg.transport, "spoof");
        assert!(cfg.is_spoof() && !cfg.is_tcp());
    }

    #[test]
    fn tcp_transport_config_is_minimal_and_valid() {
        // A tcp config may omit interface, spoofed_ip, peer_spoofed_ip, icmp_id.
        let toml = format!(
            r#"
transport       = "tcp"
real_ip         = "10.0.0.1"
peer_real_ip    = "203.0.113.1"
data_port       = 443
socks5_port     = 1080
pre_shared_key  = "{}"
"#,
            "a".repeat(32)
        );
        let cfg = parse(&toml);
        assert!(cfg.is_tcp());
        cfg.validate(true).expect("tcp config should be valid without spoof fields");
        // The spoof-only warnings must not fire in tcp mode.
        assert!(cfg.warnings().iter().all(|w| !w.contains("tunnel_count")));
    }

    #[test]
    fn spoof_mode_still_requires_interface_and_spoofed_ips() {
        // Dropping interface from a spoof config is rejected.
        let no_iface = valid_toml().replace("interface       = \"eth0\"", "");
        assert!(parse(&no_iface).validate(false).is_err());
    }

    #[test]
    fn rejects_unknown_transport() {
        let cfg = parse(&format!("{}\ntransport = \"quic\"\n", valid_toml()));
        assert!(cfg.validate(false).is_err());
    }

    #[test]
    fn rejects_out_of_range_tuning() {
        let base = valid_toml();
        assert!(parse(&format!("{base}\nmax_retries = 0\n")).validate(false).is_err());
        assert!(parse(&format!("{base}\nrto_min_ms = 1\n")).validate(false).is_err());
        // In-range values are accepted and carried into Tuning.
        let ok = parse(&format!("{base}\nmax_retries = 12\nrto_min_ms = 800\n"));
        ok.validate(false).expect("in-range tuning is valid");
        assert_eq!(ok.tuning().max_retries, 12);
        assert_eq!(ok.tuning().rto_min_ms, 800);
    }

    #[test]
    fn parse_error_is_distinct_from_validation_error() {
        // A malformed file fails at parse time ...
        assert!(toml::from_str::<Config>("real_ip = \"not-an-ip\"").is_err());
        // ... while a parseable-but-nonsensical value fails validation.
        let cfg = parse(&valid_toml().replace("data_port       = 51820", "data_port = 0"));
        assert!(cfg.validate(false).is_err());
    }

    #[test]
    fn empty_psk_is_rejected() {
        let cfg = parse(
            &valid_toml().replace(&format!("\"{}\"", "a".repeat(32)), "\"\""),
        );
        let msg = cfg.validate(false).unwrap_err().to_string();
        assert!(msg.contains("pre_shared_key"), "got: {msg}");
    }

    #[test]
    fn zero_tunnel_count_and_mtu_are_rejected() {
        let base = valid_toml();
        let t0 = parse(&format!("{base}\ntunnel_count = 0\n"));
        assert!(t0.validate(false).is_err());
        let m0 = parse(&base.replace("mtu             = 1380", "mtu = 0"));
        assert!(m0.validate(false).is_err());
    }

    #[test]
    fn client_requires_nonzero_socks_port() {
        let cfg = parse(&format!("{}\nsocks5_port = 0\n", valid_toml()));
        // Fails only in client mode; the server ignores socks5_port.
        assert!(cfg.validate(true).is_err());
        assert!(cfg.validate(false).is_ok());
    }

    #[test]
    fn warns_about_pool_without_spoofed_ip_and_nonhex_key() {
        let cfg = parse(
            &valid_toml()
                .replace(&format!("\"{}\"", "a".repeat(32)), "\"short-non-hex\"")
                .replace(
                    "spoofed_ip      = \"8.8.4.4\"",
                    "spoofed_ip      = \"8.8.4.4\"\nspoofed_ip_pool = [\"1.1.1.1\"]",
                ),
        );
        let warnings = cfg.warnings().join("\n");
        assert!(warnings.contains("pre_shared_key"), "got: {warnings}");
        assert!(warnings.contains("spoofed_ip_pool"), "got: {warnings}");
    }
}
