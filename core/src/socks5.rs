//! SOCKS5 proxy server (client side only).
//!
//! Accepts local TCP connections on `cfg.socks5_port`, performs the SOCKS5
//! handshake, and relays data bidirectionally through a Candy-Spoof tunnel.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::config::Config;
use crate::tunnel::TunnelManager;

// SOCKS5 constants
const SOCKS_VER:          u8 = 0x05;
const NO_AUTH:            u8 = 0x00;
const NO_ACCEPTABLE_AUTH: u8 = 0xFF;
const CMD_CONNECT:        u8 = 0x01;
const ATYP_IPV4:          u8 = 0x01;
const ATYP_DOMAIN:        u8 = 0x03;
const ATYP_IPV6:          u8 = 0x04;
const REP_SUCCESS:        u8 = 0x00;
const REP_GENERAL_FAIL:   u8 = 0x01;
const REP_CMD_UNSUPPORTED:u8 = 0x07;
const REP_ATYP_UNSUPPORTED:u8 = 0x08;

// ── Entry point ───────────────────────────────────────────────────────────────

/// Bind and run the SOCKS5 proxy.  Never returns unless an error occurs.
pub async fn run_socks5(cfg: Arc<Config>, manager: TunnelManager) -> Result<()> {
    let bind = SocketAddr::from(([127, 0, 0, 1], cfg.socks5_port));
    let listener = TcpListener::bind(bind)
        .await
        .with_context(|| format!("bind SOCKS5 port {}", cfg.socks5_port))?;

    log::info!("SOCKS5 proxy listening on {}", bind);

    loop {
        let (stream, peer) = listener.accept().await?;
        let mgr  = manager.clone();
        let cfg2 = cfg.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_client(stream, mgr, cfg2).await {
                log::debug!("SOCKS5 [{}]: {}", peer, e);
            }
        });
    }
}

// ── Per-connection handler ────────────────────────────────────────────────────

async fn handle_client(
    mut stream: TcpStream,
    manager:    TunnelManager,
    cfg:        Arc<Config>,
) -> Result<()> {
    // ── 1. Method negotiation ────────────────────────────────────────────────
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await.context("SOCKS5 greeting")?;
    if header[0] != SOCKS_VER {
        bail!("not SOCKS5 (version byte = {})", header[0]);
    }
    let nmethods = header[1] as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await.context("SOCKS5 methods")?;

    if !methods.contains(&NO_AUTH) {
        stream.write_all(&[SOCKS_VER, NO_ACCEPTABLE_AUTH]).await?;
        bail!("client requires authentication (not supported)");
    }
    stream.write_all(&[SOCKS_VER, NO_AUTH]).await?;

    // ── 2. Request ───────────────────────────────────────────────────────────
    let mut req = [0u8; 4];
    stream.read_exact(&mut req).await.context("SOCKS5 request")?;
    if req[0] != SOCKS_VER {
        bail!("bad version in request: {}", req[0]);
    }
    let cmd  = req[1];
    let atyp = req[3];

    if cmd != CMD_CONNECT {
        socks5_reply(&mut stream, REP_CMD_UNSUPPORTED).await?;
        bail!("unsupported SOCKS5 command {}", cmd);
    }

    let (target_host, target_port) = read_target(&mut stream, atyp).await?;

    log::info!("SOCKS5 CONNECT → {}:{}", target_host, target_port);

    // ── 3. Open tunnel and wait for handshake ────────────────────────────────
    let (tunnel_id, mut app_rx, net_tx) = manager
        .open_tunnel()
        .await
        .context("open tunnel")?;

    // Wait (without polling) for the tunnel to be established (SYN-ACK).
    if !manager.wait_established(tunnel_id, Duration::from_secs(15)).await {
        socks5_reply(&mut stream, REP_GENERAL_FAIL).await?;
        bail!("tunnel {} handshake timed out", tunnel_id);
    }

    // Send CONNECT destination as the first payload so the server knows
    // where to forward the TCP connection.
    let connect_meta = format!("CONNECT {}:{}", target_host, target_port);
    net_tx.send(Bytes::from(connect_meta)).await
        .context("sending CONNECT meta")?;

    // Reply SOCKS5 success to the local application.
    socks5_reply(&mut stream, REP_SUCCESS).await?;

    // ── 4. Bidirectional relay ───────────────────────────────────────────────
    let (mut tcp_r, mut tcp_w) = stream.into_split();
    let mtu = cfg.mtu;

    // TCP → tunnel
    let net_tx2 = net_tx;
    let a_to_t = tokio::spawn(async move {
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

    // Tunnel → TCP
    let t_to_a = tokio::spawn(async move {
        loop {
            match app_rx.recv().await {
                Some(data) => {
                    if tcp_w.write_all(&data).await.is_err() { break; }
                }
                None => break,
            }
        }
    });

    tokio::select! {
        _ = a_to_t => {}
        _ = t_to_a => {}
    }

    manager.close_tunnel(tunnel_id).await;
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

async fn read_target(stream: &mut TcpStream, atyp: u8) -> Result<(String, u16)> {
    match atyp {
        ATYP_IPV4 => {
            let mut addr = [0u8; 4];
            let mut port = [0u8; 2];
            stream.read_exact(&mut addr).await?;
            stream.read_exact(&mut port).await?;
            Ok((std::net::Ipv4Addr::from(addr).to_string(), u16::from_be_bytes(port)))
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut host = vec![0u8; len[0] as usize];
            let mut port = [0u8; 2];
            stream.read_exact(&mut host).await?;
            stream.read_exact(&mut port).await?;
            Ok((String::from_utf8_lossy(&host).into_owned(), u16::from_be_bytes(port)))
        }
        ATYP_IPV6 => {
            socks5_reply(stream, REP_ATYP_UNSUPPORTED).await?;
            bail!("IPv6 SOCKS5 addresses are not supported")
        }
        _ => {
            socks5_reply(stream, REP_ATYP_UNSUPPORTED).await?;
            bail!("unknown SOCKS5 address type {}", atyp)
        }
    }
}

async fn socks5_reply(stream: &mut TcpStream, rep: u8) -> Result<()> {
    // VER  REP  RSV  ATYP  BND.ADDR(4 bytes)  BND.PORT(2 bytes)
    let reply = [SOCKS_VER, rep, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0];
    stream.write_all(&reply).await?;
    Ok(())
}
