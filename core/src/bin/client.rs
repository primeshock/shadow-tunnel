//! Shadow Spoof **client** binary.
//!
//! Starts a local SOCKS5 proxy and connects it to the remote Shadow Spoof server
//! via a spoofed UDP/ICMP tunnel.
//!
//! Usage:
//!   cargo run --bin client -- --config config/client.toml

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;

use shadow_spoof::config::Config;
use shadow_spoof::raw_socket::{RawReceiver, RawSender};
use shadow_spoof::socks5::run_socks5;
use shadow_spoof::tunnel::{PeerAddr, TunnelManager};

#[derive(Parser, Debug)]
#[command(name = "client", about = "Shadow Spoof client (SOCKS5 proxy)")]
struct Args {
    /// Path to the TOML configuration file.
    #[arg(short, long, default_value = "config/client.toml")]
    config: String,

    /// Override log level (e.g. debug, info, warn).
    #[arg(short, long)]
    log_level: Option<String>,

    /// Load and validate the configuration, print any warnings, then exit
    /// without opening any sockets.  Exit code 0 means the config is accepted.
    #[arg(long)]
    check_config: bool,
    /// Print the runtime features this binary supports (one per line) and
    /// exit.  The panel checks this before relying on live reload.
    #[arg(long)]
    capabilities: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if args.capabilities {
        println!("live-tuning\nstats");
        return Ok(());
    }

    // Initialise logging.
    let level = args
        .log_level
        .as_deref()
        .unwrap_or("info");
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(level)).init();

    let cfg = Arc::new(Config::load(&args.config, /* client = */ true)?);
    for warning in cfg.warnings() {
        log::warn!("config: {}", warning);
    }

    if args.check_config {
        log::info!("config '{}' is valid", args.config);
        return Ok(());
    }

    // TCP transport: a standard, non-spoofed socket path (no raw sockets).
    if cfg.is_tcp() {
        log::info!(
            "Shadow Spoof client starting | transport=tcp | real={} peer={}:{}",
            cfg.real_ip, cfg.peer_real_ip, cfg.data_port
        );
        spawn_reload_handler(None, args.config.clone(), true, cfg.clone());
        return shadow_spoof::tcp::run_tcp_client(cfg).await;
    }

    log::info!(
        "Shadow Spoof client starting | real={} spoof={} peer={} iface={}",
        cfg.real_ip,
        cfg.spoofed_ip,
        cfg.peer_real_ip,
        cfg.interface
    );

    // Build the raw socket sender.
    let sender = RawSender::spawn(&cfg.interface)?;

    // Build the raw socket receiver (listens for UDP data + ICMP control).
    let mut allowed = cfg.allowed_peers.clone();
    allowed.push(cfg.peer_real_ip);
    allowed.push(cfg.peer_spoofed_ip);
    let key = shadow_spoof::packet::derive_key(&cfg.pre_shared_key);
    let mut receiver =
        RawReceiver::spawn(cfg.data_port, cfg.icmp_id, allowed, &cfg.interface, key)?;

    // Build the tunnel manager.
    let peer_addr = PeerAddr {
        local_spoof: cfg.pick_spoofed_ip(),
        peer_real:   cfg.peer_real_ip,
        data_port:   cfg.data_port,
        icmp_id:     cfg.icmp_id,
        is_server:   false,
    };
    let manager = TunnelManager::new(sender, peer_addr, cfg.clone());
    manager.spawn_stats_reporter(Duration::from_secs(10));
    spawn_reload_handler(Some(manager.clone()), args.config.clone(), true, cfg.clone());

    // ── Background task: process incoming packets ─────────────────────────────
    let mgr2 = manager.clone();
    tokio::spawn(async move {
        loop {
            if let Some(incoming) = receiver.recv().await {
                // The server never initiates tunnels, so SYN packets are
                // unexpected on the client side – just log and ignore.
                if let Err(e) = mgr2
                    .handle_incoming(incoming.src_ip, incoming.pkt)
                    .await
                {
                    log::warn!("handle_incoming: {}", e);
                }
            }
        }
    });

    // ── Background task: periodic housekeeping (retransmit, heartbeat) ───────
    let mgr3 = manager.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(100));
        loop {
            interval.tick().await;
            if let Err(e) = mgr3.tick().await {
                log::warn!("tick: {}", e);
            }
        }
    });

    // ── Foreground: SOCKS5 proxy ──────────────────────────────────────────────
    run_socks5(cfg, manager).await?;

    Ok(())
}

/// Reload tuning knobs on SIGHUP without dropping tunnels.  Installing the
/// handler also stops SIGHUP from terminating the process (its default
/// action), so a stray `systemctl reload`/`kill -HUP` is harmless.
fn spawn_reload_handler(manager: Option<TunnelManager>, path: String, client: bool, current: Arc<Config>) {
    tokio::spawn(async move {
        let mut hup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
            Ok(s) => s,
            Err(e) => { log::warn!("reload: cannot install SIGHUP handler: {}", e); return; }
        };
        let mut current = current;
        while hup.recv().await.is_some() {
            let Some(mgr) = manager.as_ref() else {
                log::info!("reload: the tcp transport has no live-tunable settings; restart to apply changes");
                continue;
            };
            match Config::load(&path, client) {
                Ok(new) => {
                    let t = new.tuning();
                    mgr.apply_tuning(t).await;
                    log::info!("reload: tuning applied max_retries={} rto_min_ms={}", t.max_retries, t.rto_min_ms);
                    if !current.differs_only_in_tuning(&new) {
                        log::warn!("reload: settings other than max_retries/rto_min_ms changed; they take effect after a restart");
                    }
                    let mut keep = (*current).clone();
                    keep.max_retries = new.max_retries;
                    keep.rto_min_ms = new.rto_min_ms;
                    current = Arc::new(keep);
                }
                Err(e) => log::warn!("reload: config rejected, keeping current tuning: {}", e),
            }
        }
    });
}
