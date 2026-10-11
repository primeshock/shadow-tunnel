//! Candy-Spoof **client** binary.
//!
//! Starts a local SOCKS5 proxy and connects it to the remote Candy-Spoof server
//! via a spoofed UDP/ICMP tunnel.
//!
//! Usage:
//!   cargo run --bin client -- --config config/client.toml

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;

use candy_spoof::config::Config;
use candy_spoof::raw_socket::{RawReceiver, RawSender};
use candy_spoof::socks5::run_socks5;
use candy_spoof::tunnel::{PeerAddr, TunnelManager};

#[derive(Parser, Debug)]
#[command(name = "client", about = "Candy-Spoof client (SOCKS5 proxy)")]
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
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

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

    log::info!(
        "Candy-Spoof client starting | real={} spoof={} peer={} iface={}",
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
    let key = candy_spoof::packet::derive_key(&cfg.pre_shared_key);
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
