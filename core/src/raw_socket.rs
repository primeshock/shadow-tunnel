//! Raw-socket I/O layer.
//!
//! Provides two abstractions:
//!
//! - [`RawSender`] – builds and transmits spoofed IPv4/UDP or IPv4/ICMP packets
//!   via a `SOCK_RAW | IPPROTO_RAW` socket with `IP_HDRINCL`.
//! - [`RawReceiver`] – receives raw IP packets from a `SOCK_RAW | IPPROTO_UDP`
//!   or `SOCK_RAW | IPPROTO_ICMP` socket and demultiplexes them into
//!   `ShadowPacket`s.
//!
//! Both types are bridge objects between the blocking raw-socket world and the
//! async Tokio world.  Each spawns background `std::thread`s that communicate
//! with the Tokio task graph through `tokio::sync::mpsc` channels.

use std::net::Ipv4Addr;
use std::os::unix::io::RawFd;

use anyhow::{Context, Result};
use bytes::Bytes;
use pnet_packet::icmp::{
    echo_request::MutableEchoRequestPacket, IcmpCode, IcmpPacket, IcmpTypes,
};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::{Ipv4Flags, MutableIpv4Packet};
use pnet_packet::udp::MutableUdpPacket;
use pnet_packet::Packet;
use tokio::sync::mpsc;

use crate::packet::ShadowPacket;

// ── Constants ────────────────────────────────────────────────────────────────

const IP_HDR_LEN: usize = 20;
const UDP_HDR_LEN: usize = 8;
const ICMP_ECHO_HDR_LEN: usize = 8;

/// IP TTL for spoofed packets.
const SPOOF_TTL: u8 = 64;

// ── Outgoing packet descriptor ────────────────────────────────────────────────

/// A request to transmit a single spoofed packet.
#[derive(Debug)]
pub enum OutPacket {
    /// Send a UDP packet carrying `payload` on the data channel.
    Udp {
        src_ip:   Ipv4Addr,
        dst_ip:   Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        payload:  Bytes,
    },
    /// Send an ICMP Echo Request carrying `payload` on the control channel.
    Icmp {
        src_ip:  Ipv4Addr,
        dst_ip:  Ipv4Addr,
        id:      u16,
        seq:     u16,
        payload: Bytes,
    },
    /// Send an ICMP Echo Reply (server → client) on the control channel.
    IcmpReply {
        src_ip:  Ipv4Addr,
        dst_ip:  Ipv4Addr,
        id:      u16,
        seq:     u16,
        payload: Bytes,
    },
}

/// A received packet that has been validated and parsed.
#[derive(Debug)]
pub struct InPacket {
    /// True source IP (from the IP header).
    pub src_ip: Ipv4Addr,
    /// Parsed Shadow Spoof application packet.
    pub pkt:    ShadowPacket,
}

// ── RawSender ────────────────────────────────────────────────────────────────

/// Sends spoofed IPv4 packets using a background thread.
///
/// Clone the inner `mpsc::Sender` to send packets from multiple tasks.
pub struct RawSender {
    tx: mpsc::Sender<OutPacket>,
}

impl RawSender {
    /// Spawn the background sender thread and return a `RawSender` handle.
    ///
    /// `interface` is the network device the raw socket is bound to (see
    /// [`bind_to_device`]).
    pub fn spawn(interface: &str) -> Result<Self> {
        let fd = create_raw_send_socket(interface)?;
        let (tx, mut rx) = mpsc::channel::<OutPacket>(4096);

        // Dedicated blocking sender thread. This avoids expensive per-packet
        // spawn_blocking scheduling overhead under high packet rates.
        std::thread::Builder::new()
            .name("raw-send".into())
            .spawn(move || {
                while let Some(out) = rx.blocking_recv() {
                    if let Err(e) = send_out_packet(fd, out) {
                        log::warn!("raw-send error: {}", e);
                    }
                }
                unsafe { libc::close(fd) };
            })
            .context("spawn raw send thread")?;

        Ok(Self { tx })
    }

    /// Enqueue an [`OutPacket`] for transmission.
    pub async fn send(&self, pkt: OutPacket) -> Result<()> {
        self.tx.send(pkt).await.context("raw sender closed")
    }
}

// ── RawReceiver ───────────────────────────────────────────────────────────────

/// Receives and parses incoming raw IP packets in a background thread.
pub struct RawReceiver {
    rx: mpsc::Receiver<InPacket>,
}

impl RawReceiver {
    /// Spawn background threads for UDP and ICMP reception and return a
    /// combined `RawReceiver`.
    ///
    /// `icmp_id` – the ICMP identifier to match (filters out foreign pings).
    /// `allowed` – set of peer IPs whose packets are trusted.
    pub fn spawn(
        data_port:   u16,
        icmp_id:     u16,
        allowed:     Vec<Ipv4Addr>,
        interface:   &str,
        key:         Vec<u8>,
    ) -> Result<Self> {
        let (tx, rx) = mpsc::channel::<InPacket>(4096);

        let udp_fd   = create_raw_recv_socket(libc::IPPROTO_UDP as libc::c_int, interface)?;
        let icmp_fd  = create_raw_recv_socket(libc::IPPROTO_ICMP as libc::c_int, interface)?;

        // UDP receive thread
        {
            let tx2      = tx.clone();
            let allowed2 = allowed.clone();
            let key2     = key.clone();
            std::thread::Builder::new()
                .name("raw-recv-udp".into())
                .spawn(move || {
                    udp_recv_loop(udp_fd, data_port, &allowed2, &key2, tx2);
                })
                .context("spawn udp recv thread")?;
        }

        // ICMP receive thread
        {
            let tx2      = tx;
            let allowed2 = allowed;
            let key2     = key;
            std::thread::Builder::new()
                .name("raw-recv-icmp".into())
                .spawn(move || {
                    icmp_recv_loop(icmp_fd, icmp_id, &allowed2, &key2, tx2);
                })
                .context("spawn icmp recv thread")?;
        }

        Ok(Self { rx })
    }

    /// Await the next validated incoming packet.
    pub async fn recv(&mut self) -> Option<InPacket> {
        self.rx.recv().await
    }
}

// ── Socket creation helpers ───────────────────────────────────────────────────

fn create_raw_send_socket(interface: &str) -> Result<RawFd> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .context("socket(AF_INET, SOCK_RAW, IPPROTO_RAW) failed – CAP_NET_RAW required");
    }
    // Tell the kernel we are supplying the IP header ourselves.
    let one: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_HDRINCL,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of_val(&one) as libc::socklen_t,
        );
    }
    if let Err(e) = bind_to_device(fd, interface) {
        unsafe { libc::close(fd) };
        return Err(e);
    }
    Ok(fd)
}

fn create_raw_recv_socket(proto: libc::c_int, interface: &str) -> Result<RawFd> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, proto) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .context("socket(AF_INET, SOCK_RAW, …) failed – CAP_NET_RAW required");
    }
    if let Err(e) = bind_to_device(fd, interface) {
        unsafe { libc::close(fd) };
        return Err(e);
    }
    Ok(fd)
}

/// Bind a raw socket to a named network device.
///
/// The `interface` config field documents that raw sockets are bound to a
/// specific device; previously the field was parsed but never applied, so the
/// kernel chose the egress/ingress interface by routing and every NIC's traffic
/// was delivered to the receive sockets.  On Linux this uses `SO_BINDTODEVICE`.
///
/// On non-Linux targets (e.g. a developer's macOS machine) `SO_BINDTODEVICE`
/// does not exist, so binding is skipped with a warning – the production target
/// is Linux.  An empty interface name is treated as "no binding".
#[cfg(target_os = "linux")]
fn bind_to_device(fd: RawFd, interface: &str) -> Result<()> {
    if interface.is_empty() {
        return Ok(());
    }
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            interface.as_ptr() as *const libc::c_void,
            interface.len() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!(
                "SO_BINDTODEVICE to interface '{}' failed – check that the \
                 interface exists and the process has CAP_NET_RAW",
                interface
            )
        });
    }
    log::debug!("raw socket bound to interface '{}'", interface);
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn bind_to_device(_fd: RawFd, interface: &str) -> Result<()> {
    if !interface.is_empty() {
        log::warn!(
            "interface '{}' is configured but SO_BINDTODEVICE is only supported \
             on Linux; raw sockets are not bound to a device on this platform",
            interface
        );
    }
    Ok(())
}

// ── Packet transmission ───────────────────────────────────────────────────────

fn send_out_packet(fd: RawFd, out: OutPacket) -> Result<()> {
    match out {
        OutPacket::Udp { src_ip, dst_ip, src_port, dst_port, payload } => {
            let raw = build_udp_packet(src_ip, dst_ip, src_port, dst_port, &payload);
            raw_sendto(fd, &raw, dst_ip)
        }
        OutPacket::Icmp { src_ip, dst_ip, id, seq, payload } => {
            let raw = build_icmp_echo(src_ip, dst_ip, id, seq, &payload, false);
            raw_sendto(fd, &raw, dst_ip)
        }
        OutPacket::IcmpReply { src_ip, dst_ip, id, seq, payload } => {
            let raw = build_icmp_echo(src_ip, dst_ip, id, seq, &payload, true);
            raw_sendto(fd, &raw, dst_ip)
        }
    }
}

fn raw_sendto(fd: RawFd, data: &[u8], dst: Ipv4Addr) -> Result<()> {
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    addr.sin_family = libc::AF_INET as libc::sa_family_t;
    addr.sin_port   = 0;
    addr.sin_addr   = libc::in_addr { s_addr: u32::from(dst).to_be() };

    let n = unsafe {
        libc::sendto(
            fd,
            data.as_ptr() as *const libc::c_void,
            data.len(),
            0,
            &addr as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if n < 0 {
        return Err(std::io::Error::last_os_error()).context("sendto failed");
    }
    Ok(())
}

// ── Packet reception loops ────────────────────────────────────────────────────

fn udp_recv_loop(
    fd:        RawFd,
    data_port: u16,
    allowed:   &[Ipv4Addr],
    key:       &[u8],
    tx:        mpsc::Sender<InPacket>,
) {
    let mut buf = vec![0u8; 65535];
    loop {
        let (n, src_ip) = match raw_recvfrom(fd, &mut buf) {
            Ok(v)  => v,
            Err(e) => { log::warn!("udp recvfrom: {}", e); continue; }
        };
        let data = &buf[..n];

        // Validate source IP against whitelist
        if !is_allowed(src_ip, allowed) {
            continue;
        }

        // A raw IPv4 datagram is at least a 20-byte header; guard before
        // indexing so a short/zero-length read cannot panic this thread.
        if data.len() < IP_HDR_LEN {
            continue;
        }
        // Parse IP header (variable-length)
        let ihl = ((data[0] & 0x0f) as usize) * 4;
        if ihl < IP_HDR_LEN || data.len() < ihl + UDP_HDR_LEN {
            continue;
        }
        let udp_data = &data[ihl..];

        // Check destination port
        let dst_port = u16::from_be_bytes([udp_data[2], udp_data[3]]);
        if dst_port != data_port {
            continue;
        }

        // UDP payload starts at offset 8
        if udp_data.len() < UDP_HDR_LEN {
            continue;
        }
        let payload = bytes::Bytes::copy_from_slice(&udp_data[UDP_HDR_LEN..]);
        match ShadowPacket::decode_authenticated(payload, key) {
            Ok(pkt) => {
                let _ = tx.blocking_send(InPacket { src_ip, pkt });
            }
            Err(e) => log::trace!("udp decode: {}", e),
        }
    }
}

fn icmp_recv_loop(
    fd:      RawFd,
    icmp_id: u16,
    allowed: &[Ipv4Addr],
    key:     &[u8],
    tx:      mpsc::Sender<InPacket>,
) {
    let mut buf = vec![0u8; 65535];
    loop {
        let (n, src_ip) = match raw_recvfrom(fd, &mut buf) {
            Ok(v)  => v,
            Err(e) => { log::warn!("icmp recvfrom: {}", e); continue; }
        };
        let data = &buf[..n];

        if !is_allowed(src_ip, allowed) {
            continue;
        }

        // Guard before indexing the IP header (see udp_recv_loop).
        if data.len() < IP_HDR_LEN {
            continue;
        }
        // Parse IP header
        let ihl = ((data[0] & 0x0f) as usize) * 4;
        if ihl < IP_HDR_LEN || data.len() < ihl + ICMP_ECHO_HDR_LEN {
            continue;
        }
        let icmp_data = &data[ihl..];

        // Type must be 8 (echo request) or 0 (echo reply)
        let icmp_type = icmp_data[0];
        if icmp_type != 8 && icmp_type != 0 {
            continue;
        }

        // Match our ICMP identifier
        let id = u16::from_be_bytes([icmp_data[4], icmp_data[5]]);
        if id != icmp_id {
            continue;
        }

        let payload = bytes::Bytes::copy_from_slice(&icmp_data[ICMP_ECHO_HDR_LEN..]);
        match ShadowPacket::decode_authenticated(payload, key) {
            Ok(pkt) => {
                let _ = tx.blocking_send(InPacket { src_ip, pkt });
            }
            Err(e) => log::trace!("icmp decode: {}", e),
        }
    }
}

fn raw_recvfrom(fd: RawFd, buf: &mut [u8]) -> Result<(usize, Ipv4Addr)> {
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut addrlen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let n = unsafe {
        libc::recvfrom(
            fd,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
            0,
            &mut addr as *mut libc::sockaddr_in as *mut libc::sockaddr,
            &mut addrlen,
        )
    };
    if n < 0 {
        return Err(std::io::Error::last_os_error()).context("recvfrom failed");
    }
    let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
    Ok((n as usize, ip))
}

fn is_allowed(ip: Ipv4Addr, allowed: &[Ipv4Addr]) -> bool {
    allowed.contains(&ip)
}

// ── Packet builders ───────────────────────────────────────────────────────────

/// Build a spoofed IPv4/UDP packet.
pub fn build_udp_packet(
    src_ip:   Ipv4Addr,
    dst_ip:   Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload:  &[u8],
) -> Vec<u8> {
    let udp_total = UDP_HDR_LEN + payload.len();
    let ip_total  = IP_HDR_LEN + udp_total;

    let mut buf = vec![0u8; ip_total];

    // Fill UDP header (starts at byte 20)
    {
        let udp_buf = &mut buf[IP_HDR_LEN..];
        let mut pkt = MutableUdpPacket::new(udp_buf).unwrap();
        pkt.set_source(src_port);
        pkt.set_destination(dst_port);
        pkt.set_length(udp_total as u16);
        pkt.set_payload(payload);
        let cksum = pnet_packet::udp::ipv4_checksum(&pkt.to_immutable(), &src_ip, &dst_ip);
        pkt.set_checksum(cksum);
    }

    fill_ipv4_header(&mut buf, src_ip, dst_ip, IpNextHeaderProtocols::Udp, ip_total);
    buf
}

/// Build a spoofed IPv4/ICMP echo request (or reply) packet.
pub fn build_icmp_echo(
    src_ip:  Ipv4Addr,
    dst_ip:  Ipv4Addr,
    id:      u16,
    seq:     u16,
    payload: &[u8],
    reply:   bool,
) -> Vec<u8> {
    let icmp_total = ICMP_ECHO_HDR_LEN + payload.len();
    let ip_total   = IP_HDR_LEN + icmp_total;

    let mut buf = vec![0u8; ip_total];

    {
        let icmp_buf = &mut buf[IP_HDR_LEN..];
        let mut pkt  = MutableEchoRequestPacket::new(icmp_buf).unwrap();
        pkt.set_icmp_type(if reply { IcmpTypes::EchoReply } else { IcmpTypes::EchoRequest });
        pkt.set_icmp_code(IcmpCode::new(0));
        pkt.set_identifier(id);
        pkt.set_sequence_number(seq);
        pkt.set_payload(payload);
        // Compute ICMP checksum over the full ICMP portion.
        let cksum = pnet_packet::icmp::checksum(
            &IcmpPacket::new(pkt.packet()).unwrap(),
        );
        pkt.set_checksum(cksum);
    }

    fill_ipv4_header(&mut buf, src_ip, dst_ip, IpNextHeaderProtocols::Icmp, ip_total);
    buf
}

fn fill_ipv4_header(
    buf:      &mut [u8],
    src_ip:   Ipv4Addr,
    dst_ip:   Ipv4Addr,
    protocol: pnet_packet::ip::IpNextHeaderProtocol,
    ip_total: usize,
) {
    let mut pkt = MutableIpv4Packet::new(buf).unwrap();
    pkt.set_version(4);
    pkt.set_header_length(5); // 5 × 4 = 20 bytes
    pkt.set_dscp(0);
    pkt.set_ecn(0);
    pkt.set_total_length(ip_total as u16);
    pkt.set_identification(rand::random());
    pkt.set_flags(Ipv4Flags::DontFragment);
    pkt.set_fragment_offset(0);
    pkt.set_ttl(SPOOF_TTL);
    pkt.set_next_level_protocol(protocol);
    pkt.set_source(src_ip);
    pkt.set_destination(dst_ip);
    pkt.set_checksum(0); // zero before computing
    let cksum = pnet_packet::ipv4::checksum(&pkt.to_immutable());
    pkt.set_checksum(cksum);
}
