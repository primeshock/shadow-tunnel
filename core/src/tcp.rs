//! Standard-socket **TCP transport** (no raw sockets, no source spoofing).
//!
//! An ordinary kernel TCP connection between the two *real* IPs, selected with
//! `transport = "tcp"`.  It is a drop-in alternative to the spoofed UDP+ICMP
//! transport for networks where raw/spoofed packets are filtered.
//!
//! Because TCP already provides reliable, ordered, flow-controlled delivery,
//! this path does **not** use the ARQ / congestion-control / heartbeat
//! machinery of the spoof transport.  It authenticates the session *setup* with
//! the pre-shared key (HMAC, reusing the authenticated [`CandyPacket`] frame)
//! and then splices bytes in both directions.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::config::Config;
use crate::packet::CandyPacket;

const MAX_FRAME: usize = 64 * 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

// ── length-prefixed authenticated frames (session setup only) ──────────────

async fn write_frame(s: &mut TcpStream, data: &[u8]) -> Result<()> {
    if data.len() > MAX_FRAME {
        bail!("frame too large ({} bytes)", data.len());
    }
    s.write_all(&(data.len() as u32).to_be_bytes()).await?;
    s.write_all(data).await?;
    Ok(())
}

async fn read_frame(s: &mut TcpStream) -> Result<Bytes> {
    let mut len = [0u8; 4];
    s.read_exact(&mut len).await?;
    let n = u32::from_be_bytes(len) as usize;
    if n == 0 || n > MAX_FRAME {
        bail!("bad frame length {}", n);
    }
    let mut buf = vec![0u8; n];
    s.read_exact(&mut buf).await?;
    Ok(Bytes::from(buf))
}

/// Send one authenticated control message carrying `text`.
async fn send_ctrl(s: &mut TcpStream, key: &[u8], text: &str) -> Result<()> {
    let pkt = CandyPacket::new_data(0, 0, 0, 0, Bytes::copy_from_slice(text.as_bytes()));
    write_frame(s, &pkt.encode_authenticated(key)).await
}

/// Receive and authenticate one control message, returning its text.
async fn recv_ctrl(s: &mut TcpStream, key: &[u8]) -> Result<String> {
    let frame = read_frame(s).await?;
    let pkt = CandyPacket::decode_authenticated(frame, key)
        .context("authentication failed (wrong pre_shared_key?)")?;
    Ok(String::from_utf8_lossy(&pkt.payload).into_owned())
}

// ── client ─────────────────────────────────────────────────────────────────

/// Run the TCP-transport client: a local SOCKS5 proxy that forwards each
/// connection to the server over a standard TCP connection.
pub async fn run_tcp_client(cfg: Arc<Config>) -> Result<()> {
    let key = crate::packet::derive_key(&cfg.pre_shared_key);
    let bind = SocketAddr::from(([127, 0, 0, 1], cfg.socks5_port));
    let listener = TcpListener::bind(bind)
        .await
        .with_context(|| format!("bind SOCKS5 port {}", cfg.socks5_port))?;
    log::info!(
        "SOCKS5 (tcp transport) listening on {} -> {}:{}",
        bind, cfg.peer_real_ip, cfg.data_port
    );
    loop {
        let (stream, peer) = listener.accept().await?;
        let cfg = cfg.clone();
        let key = key.clone();
        tokio::spawn(async move {
            if let Err(e) = client_conn(stream, cfg, key).await {
                log::debug!("tcp client [{}]: {}", peer, e);
            }
        });
    }
}

async fn client_conn(mut local: TcpStream, cfg: Arc<Config>, key: Vec<u8>) -> Result<()> {
    let (host, port) = socks5_accept(&mut local).await?;
    log::info!("tcp CONNECT -> {}:{}", host, port);

    let server = SocketAddr::from((cfg.peer_real_ip, cfg.data_port));
    let mut up = tokio::time::timeout(HANDSHAKE_TIMEOUT, TcpStream::connect(server))
        .await
        .context("timeout connecting to the server")?
        .with_context(|| format!("connect to server {}", server))?;
    up.set_nodelay(true).ok();

    send_ctrl(&mut up, &key, &format!("CONNECT {}:{}", host, port)).await?;
    let reply = tokio::time::timeout(HANDSHAKE_TIMEOUT, recv_ctrl(&mut up, &key))
        .await
        .context("timeout waiting for the server reply")??;
    if reply != "OK" {
        socks5_reply(&mut local, 0x01).await?; // general failure
        bail!("server refused: {}", reply);
    }
    socks5_reply(&mut local, 0x00).await?; // success

    tokio::io::copy_bidirectional(&mut local, &mut up).await.ok();
    Ok(())
}

// ── server ─────────────────────────────────────────────────────────────────

/// Run the TCP-transport server: accept client connections and forward each to
/// its requested TCP destination.
pub async fn run_tcp_server(cfg: Arc<Config>) -> Result<()> {
    let key = crate::packet::derive_key(&cfg.pre_shared_key);
    let bind = SocketAddr::from((Ipv4Addr::UNSPECIFIED, cfg.data_port));
    let listener = TcpListener::bind(bind)
        .await
        .with_context(|| format!("bind tcp transport port {}", cfg.data_port))?;
    log::info!("tcp transport server listening on {}", bind);
    loop {
        let (stream, peer) = listener.accept().await?;
        let src = match peer {
            SocketAddr::V4(a) => *a.ip(),
            SocketAddr::V6(_) => {
                log::trace!("dropping IPv6 client {}", peer);
                continue;
            }
        };
        if !cfg.is_peer_allowed(&src) {
            log::trace!("dropping connection from disallowed IP {}", src);
            continue;
        }
        let cfg = cfg.clone();
        let key = key.clone();
        tokio::spawn(async move {
            if let Err(e) = server_conn(stream, cfg, key).await {
                log::debug!("tcp server [{}]: {}", peer, e);
            }
        });
    }
}

async fn server_conn(mut client: TcpStream, _cfg: Arc<Config>, key: Vec<u8>) -> Result<()> {
    client.set_nodelay(true).ok();
    let meta = tokio::time::timeout(HANDSHAKE_TIMEOUT, recv_ctrl(&mut client, &key))
        .await
        .context("timeout waiting for CONNECT meta")??;
    let (host, port) = parse_connect_meta(&meta)?;
    log::info!("tcp forwarding to {}:{}", host, port);

    let target = format!("{}:{}", host, port);
    let mut up = match TcpStream::connect(&target).await {
        Ok(s) => s,
        Err(e) => {
            send_ctrl(&mut client, &key, &format!("ERR {}", e)).await.ok();
            bail!("connect to {}: {}", target, e);
        }
    };
    up.set_nodelay(true).ok();
    send_ctrl(&mut client, &key, "OK").await?;

    tokio::io::copy_bidirectional(&mut client, &mut up).await.ok();
    Ok(())
}

fn parse_connect_meta(meta: &str) -> Result<(String, u16)> {
    let rest = meta.strip_prefix("CONNECT ").context("missing CONNECT prefix")?;
    let (host, port) = rest.rsplit_once(':').context("missing ':' in CONNECT meta")?;
    let port = port.trim().parse::<u16>().context("invalid port in CONNECT meta")?;
    Ok((host.to_string(), port))
}

// ── minimal SOCKS5 server (CONNECT, no auth) ────────────────────────────────

const SOCKS_VER: u8 = 0x05;

async fn socks5_accept(stream: &mut TcpStream) -> Result<(String, u16)> {
    let mut hdr = [0u8; 2];
    stream.read_exact(&mut hdr).await.context("SOCKS5 greeting")?;
    if hdr[0] != SOCKS_VER {
        bail!("not SOCKS5 (version {})", hdr[0]);
    }
    let mut methods = vec![0u8; hdr[1] as usize];
    stream.read_exact(&mut methods).await.context("SOCKS5 methods")?;
    if !methods.contains(&0x00) {
        stream.write_all(&[SOCKS_VER, 0xFF]).await?;
        bail!("client requires authentication (unsupported)");
    }
    stream.write_all(&[SOCKS_VER, 0x00]).await?;

    let mut req = [0u8; 4];
    stream.read_exact(&mut req).await.context("SOCKS5 request")?;
    if req[0] != SOCKS_VER {
        bail!("bad version in request: {}", req[0]);
    }
    if req[1] != 0x01 {
        // CONNECT only
        socks5_reply(stream, 0x07).await?;
        bail!("unsupported SOCKS5 command {}", req[1]);
    }
    match req[3] {
        0x01 => {
            let mut a = [0u8; 4];
            let mut p = [0u8; 2];
            stream.read_exact(&mut a).await?;
            stream.read_exact(&mut p).await?;
            Ok((Ipv4Addr::from(a).to_string(), u16::from_be_bytes(p)))
        }
        0x03 => {
            let mut l = [0u8; 1];
            stream.read_exact(&mut l).await?;
            let mut h = vec![0u8; l[0] as usize];
            let mut p = [0u8; 2];
            stream.read_exact(&mut h).await?;
            stream.read_exact(&mut p).await?;
            Ok((String::from_utf8_lossy(&h).into_owned(), u16::from_be_bytes(p)))
        }
        other => {
            socks5_reply(stream, 0x08).await?;
            bail!("unsupported SOCKS5 address type {}", other);
        }
    }
}

async fn socks5_reply(stream: &mut TcpStream, rep: u8) -> Result<()> {
    stream
        .write_all(&[SOCKS_VER, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    Ok(())
}
