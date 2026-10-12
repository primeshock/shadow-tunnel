//! Shadow Spoof **server** binary.
//!
//! Listens for incoming tunnel connections from clients and forwards each
//! SOCKS5 CONNECT session to the requested TCP destination.
//!
//! Usage:
//!   cargo run --bin server -- --config config/server.toml

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use clap::Parser;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use shadow_spoof::config::Config;
use shadow_spoof::raw_socket::{RawReceiver, RawSender};
use shadow_spoof::tunnel::{PeerAddr, TunnelManager};

#[derive(Parser, Debug)]
#[command(name = "server", about = "Shadow Spoof server (tunnel endpoint)")]
struct Args {
    /// Path to the TOML configuration file.
    #[arg(short, long, default_value = "config/server.toml")]
    config: String,

    /// Override log level.
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

    let level = args.log_level.as_deref().unwrap_or("info");
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(level)).init();

    let cfg = Arc::new(Config::load(&args.config, /* client = */ false)?);
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
            "Shadow Spoof server starting | transport=tcp | listen 0.0.0.0:{}",
            cfg.data_port
        );
        return shadow_spoof::tcp::run_tcp_server(cfg).await;
    }

    log::info!(
        "Shadow Spoof server starting | real={} spoof={} peer={} iface={}",
        cfg.real_ip,
        cfg.spoofed_ip,
        cfg.peer_real_ip,
        cfg.interface
    );

    let sender = RawSender::spawn(&cfg.interface)?;

    let mut allowed = cfg.allowed_peers.clone();
    allowed.push(cfg.peer_real_ip);
    allowed.push(cfg.peer_spoofed_ip);
    let key = shadow_spoof::packet::derive_key(&cfg.pre_shared_key);
    let mut receiver =
        RawReceiver::spawn(cfg.data_port, cfg.icmp_id, allowed, &cfg.interface, key)?;

    let peer_addr = PeerAddr {
        local_spoof: cfg.pick_spoofed_ip(),
        peer_real:   cfg.peer_real_ip,
        data_port:   cfg.data_port,
        icmp_id:     cfg.icmp_id,
        is_server:   true,
    };
    let manager = TunnelManager::new(sender, peer_addr, cfg.clone());

    // ── Periodic housekeeping ────────────────────────────────────────────────
    let mgr_tick = manager.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(100));
        loop {
            interval.tick().await;
            if let Err(e) = mgr_tick.tick().await {
                log::warn!("tick: {}", e);
            }
        }
    });

    // ── Main receive loop ────────────────────────────────────────────────────
    loop {
        let incoming = match receiver.recv().await {
            Some(p) => p,
            None    => break,
        };

        if !cfg.is_peer_allowed(&incoming.src_ip) {
            log::trace!("dropping packet from disallowed IP {}", incoming.src_ip);
            continue;
        }

        match manager
            .handle_incoming(incoming.src_ip, incoming.pkt)
            .await
        {
            Ok(Some((syn_pkt, src_ip))) => {
                // New tunnel request – accept it and spawn a session handler.
                let mgr2 = manager.clone();
                let cfg2 = cfg.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_new_tunnel(syn_pkt, src_ip, mgr2, cfg2).await {
                        log::warn!("session error: {}", e);
                    }
                });
            }
            Ok(None) => {}
            Err(e) => log::warn!("handle_incoming: {}", e),
        }
    }

    Ok(())
}

// ── New-tunnel handler ────────────────────────────────────────────────────────

/// Accept a SYN, wait for the first DATA packet containing the CONNECT
/// destination, open a TCP connection to that destination, and relay data.
async fn handle_new_tunnel(
    syn:     shadow_spoof::packet::ShadowPacket,
    src_ip:  std::net::Ipv4Addr,
    manager: TunnelManager,
    cfg:     Arc<Config>,
) -> Result<()> {
    let (tunnel_id, mut app_rx, net_tx) = manager
        .accept_syn(syn, src_ip)
        .await
        .context("accept_syn")?;

    // First message from the client is the CONNECT destination.
    let first_msg = tokio::time::timeout(Duration::from_secs(15), app_rx.recv())
        .await
        .context("timeout waiting for CONNECT meta")?
        .context("tunnel closed before CONNECT meta")?;

    let meta = String::from_utf8_lossy(&first_msg);
    let (target_host, target_port) = parse_connect_meta(&meta)?;

    log::info!(
        "tunnel {} forwarding to {}:{}",
        tunnel_id,
        target_host,
        target_port
    );

    // Open TCP connection to the target. A failure here reflects whatever
    // destination the tunneled client asked for (often a third party's
    // unreachable/offline service) rather than a fault in the tunnel itself,
    // so it is logged at info level and does not surface as a "session
    // error" warning - that classification is reserved for actual tunnel
    // protocol problems (handshake/auth/framing).
    let target_addr = format!("{}:{}", target_host, target_port);
    let tcp_stream = match TcpStream::connect(&target_addr).await {
        Ok(s) => s,
        Err(e) => {
            log::info!(
                "tunnel {} could not reach requested destination {}: {}",
                tunnel_id, target_addr, e
            );
            return Ok(());
        }
    };

    let (mut tcp_r, mut tcp_w) = tcp_stream.into_split();
    let mtu = cfg.mtu;

    // Tunnel → TCP
    let t_to_tcp = tokio::spawn(async move {
        loop {
            match app_rx.recv().await {
                Some(data) => {
                    if tcp_w.write_all(&data).await.is_err() { break; }
                }
                None => break,
            }
        }
    });

    // TCP → tunnel
    let net_tx2 = net_tx;
    let tcp_to_t = tokio::spawn(async move {
        let mut buf = vec![0u8; mtu];
        loop {
            match tcp_r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let chunk = Bytes::copy_from_slice(&buf[..n]);
                    if net_tx2.send(chunk).await.is_err() { break; }
                }
            }
        }
    });

    tokio::select! {
        _ = t_to_tcp => {}
        _ = tcp_to_t => {}
    }

    manager.close_tunnel(tunnel_id).await;
    Ok(())
}

fn parse_connect_meta(meta: &str) -> Result<(String, u16)> {
    // Expected format: "CONNECT host:port"
    let rest = meta
        .strip_prefix("CONNECT ")
        .context("missing CONNECT prefix in meta")?;
    let (host, port_str) = rest
        .rsplit_once(':')
        .context("missing ':' in CONNECT meta")?;
    let port = port_str
        .trim()
        .parse::<u16>()
        .context("invalid port in CONNECT meta")?;
    Ok((host.to_string(), port))
}
