//! Tunnel state machine and manager.
//!
//! A [`Tunnel`] represents a single logical bidirectional stream between client
//! and server.  It owns an [`SrArq`] and a [`CongestionControl`] instance.
//!
//! [`TunnelManager`] multiplexes/demultiplexes packets across all active tunnels
//! (keyed by `tunnel_id`), drives ARQ/CC, and provides the async interface used
//! by both the client (SOCKS5) and server (TCP proxy) code.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Result};
use bytes::Bytes;
use dashmap::DashMap;
use tokio::sync::{mpsc, Mutex, Notify};

use crate::arq::{SrArq, MAX_WINDOW};
use crate::congestion::CongestionControl;
use crate::config::{Config, Tuning};
use crate::packet::{ShadowPacket, PacketKind};
use crate::raw_socket::{OutPacket, RawSender};
use crate::stats::Stats;

const HEARTBEAT_IDLE_TIMEOUT: Duration = Duration::from_secs(5);
const HEARTBEAT_MIN_INTERVAL: Duration = Duration::from_secs(2);

// ── Tunnel state ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelState {
    SynSent,
    SynReceived,
    Established,
    Closing,
    Closed,
}

/// Internal state for a single tunnel.
struct Tunnel {
    id:          u32,
    state:       TunnelState,
    arq:         SrArq,
    cc:          CongestionControl,
    /// Deliver received application data to the owner of this tunnel.
    app_tx:      mpsc::Sender<Bytes>,
    last_active: Instant,
    last_heartbeat_sent: Instant,
    /// Notified whenever the send window opens (ACK received / window update).
    window_notify: Arc<Notify>,
    /// Notified when the tunnel transitions to Established.
    established_notify: Arc<Notify>,
}

impl Tunnel {
    fn new(
        id:           u32,
        state:        TunnelState,
        init_seq:     u32,
        init_recv:    u32,
        app_tx:       mpsc::Sender<Bytes>,
        initial_cwnd: f64,
        tuning:       Tuning,
    ) -> Self {
        let mut arq = SrArq::new(init_seq, init_recv);
        arq.set_max_retries(tuning.max_retries);
        let mut cc = CongestionControl::new(initial_cwnd);
        cc.set_rto_min_ms(tuning.rto_min_ms as f64);
        Self {
            id,
            state,
            arq,
            cc,
            app_tx,
            last_active: Instant::now(),
            last_heartbeat_sent: Instant::now(),
            window_notify:      Arc::new(Notify::new()),
            established_notify: Arc::new(Notify::new()),
        }
    }

    fn touch(&mut self) { self.last_active = Instant::now(); }

    fn is_idle(&self, timeout: Duration) -> bool {
        Instant::now().duration_since(self.last_active) > timeout
    }

    fn can_send(&self) -> bool {
        self.arq.can_send()
            && self.arq.in_flight() < self.cc.effective_window()
    }

    fn record_rtt(&mut self, rtt_ms: f64) {
        self.cc.on_ack(Some(rtt_ms));
        self.arq.update_rto(self.cc.rtt.rto);
    }

    fn on_loss(&mut self) {
        self.cc.on_timeout();
        self.arq.update_rto(self.cc.rtt.rto);
    }

    fn apply_syn_ack(&mut self, syn_ack: &ShadowPacket) -> bool {
        if self.state != TunnelState::SynSent {
            return false;
        }
        // Peer SYN consumes one sequence number, so peer DATA starts at seq+1.
        self.arq.set_recv_base(syn_ack.seq.wrapping_add(1));
        self.arq.set_send_window(syn_ack.window as u32);
        self.state = TunnelState::Established;
        true
    }

    fn make_data_packet(&mut self, payload: Bytes) -> ShadowPacket {
        const UNASSIGNED_SEQ: u32 = u32::MAX;
        let ack    = self.arq.recv_base();
        let window = (MAX_WINDOW.saturating_sub(self.arq.in_flight())) as u16;
        let mut pkt = ShadowPacket::new_data(self.id, UNASSIGNED_SEQ, ack, window, payload);
        let _seq = self.arq.enqueue(&mut pkt); // assigns sequence and buffers retransmit copy
        pkt
    }
}

// ── Remote addressing ─────────────────────────────────────────────────────────

/// The addressing information needed to build spoofed outgoing packets.
#[derive(Debug, Clone)]
pub struct PeerAddr {
    /// Source IP we spoof on outgoing packets.
    pub local_spoof: Ipv4Addr,
    /// Destination IP of the peer (their real address).
    pub peer_real:   Ipv4Addr,
    /// UDP destination port for the data channel.
    pub data_port:   u16,
    /// ICMP echo identifier for the control channel.
    pub icmp_id:     u16,
    /// Whether this endpoint is running in server mode.
    pub is_server:   bool,
}

// ── TunnelManager ─────────────────────────────────────────────────────────────

/// Inner state shared through an `Arc`.
struct Inner {
    tunnels:               DashMap<u32, Arc<Mutex<Tunnel>>>,
    /// Per-tunnel Notify fired when the tunnel reaches Established state.
    established_notifiers: DashMap<u32, Arc<Notify>>,
    sender:  RawSender,
    addr:    PeerAddr,
    cfg:     Arc<Config>,
    /// HMAC key bytes derived once from `cfg.pre_shared_key`.
    key:     Vec<u8>,
    /// ARQ/congestion robustness knobs.  Behind a lock so a config reload
    /// (SIGHUP) can change them without restarting the process.
    tuning:  std::sync::RwLock<Tuning>,
    /// Interval counters reported by `spawn_stats_reporter`.
    stats:   Stats,
}

/// Manages all active tunnels.  Cheaply cloneable (`Arc` inside).
#[derive(Clone)]
pub struct TunnelManager(Arc<Inner>);

impl TunnelManager {
    pub fn new(sender: RawSender, addr: PeerAddr, cfg: Arc<Config>) -> Self {
        let key = crate::packet::derive_key(&cfg.pre_shared_key);
        let tuning = cfg.tuning();
        Self(Arc::new(Inner {
            tunnels:               DashMap::new(),
            established_notifiers: DashMap::new(),
            sender,
            addr,
            cfg,
            key,
            tuning: std::sync::RwLock::new(tuning),
            stats:  Stats::default(),
        }))
    }

    // ── Tunnel lifecycle ──────────────────────────────────────────────────────

    /// Open a new client-side tunnel.
    ///
    /// Returns:
    /// - `app_rx`  – receive application data delivered from the peer
    /// - `net_tx`  – send application data into the tunnel
    pub async fn open_tunnel(&self) -> Result<(u32, mpsc::Receiver<Bytes>, mpsc::Sender<Bytes>)> {
        let id:      u32 = rand::random();
        let syn_seq: u32 = rand::random();

        let (app_tx, app_rx) = mpsc::channel::<Bytes>(1024);
        let (net_tx, net_rx) = mpsc::channel::<Bytes>(1024);

        let tunnel = Tunnel::new(
            id,
            TunnelState::SynSent,
            syn_seq.wrapping_add(1),  // SYN consumes syn_seq, first DATA is syn_seq+1
            0,
            app_tx,
            self.0.cfg.initial_cwnd,
            self.current_tuning(),
        );
        // Grab the notifiers before inserting (to avoid re-locking).
        let window_notify      = tunnel.window_notify.clone();
        let established_notify = tunnel.established_notify.clone();
        self.0.tunnels.insert(id, Arc::new(Mutex::new(tunnel)));

        // Spawn a task that forwards application data to the raw socket.
        self.spawn_send_task(id, net_rx, window_notify);

        // Send the initial SYN on the control channel.
        let syn = ShadowPacket::new_syn(id, syn_seq);
        self.tx_control(syn).await?;

        log::info!("tunnel {} opened (SYN sent)", id);
        // Store the established notifier so is_established can await it.
        self.0.established_notifiers.insert(id, established_notify);
        Ok((id, app_rx, net_tx))
    }

    /// Accept an incoming SYN packet (server side) and create a tunnel.
    ///
    /// Returns the same triple as `open_tunnel`.
    pub async fn accept_syn(
        &self,
        syn:    ShadowPacket,
        src_ip: Ipv4Addr,
    ) -> Result<(u32, mpsc::Receiver<Bytes>, mpsc::Sender<Bytes>)> {
        let id = syn.tunnel_id;

        // Reject duplicate tunnels.
        if self.0.tunnels.contains_key(&id) {
            bail!("duplicate tunnel id {}", id);
        }

        let our_seq: u32 = rand::random();
        let (app_tx, app_rx) = mpsc::channel::<Bytes>(1024);
        let (net_tx, net_rx) = mpsc::channel::<Bytes>(1024);

        let mut tunnel = Tunnel::new(
            id,
            TunnelState::SynReceived,
            our_seq.wrapping_add(1), // SYN-ACK consumes our_seq; first DATA must be seq+1
            syn.seq.wrapping_add(1),
            app_tx,
            self.0.cfg.initial_cwnd,
            self.current_tuning(),
        );
        // Server transitions to Established immediately after SYN-ACK.
        tunnel.state = TunnelState::Established;
        let window_notify = tunnel.window_notify.clone();
        self.0.tunnels.insert(id, Arc::new(Mutex::new(tunnel)));

        self.spawn_send_task(id, net_rx, window_notify);

        let syn_ack = ShadowPacket::new_syn_ack(id, syn.seq, our_seq);
        self.tx_control(syn_ack).await?;

        log::info!("tunnel {} accepted from {}", id, src_ip);
        Ok((id, app_rx, net_tx))
    }

    /// Close a tunnel and notify the peer.
    pub async fn close_tunnel(&self, id: u32) {
        if let Some((_, t)) = self.0.tunnels.remove(&id) {
            let mut t = t.lock().await;
            t.state = TunnelState::Closed;
        }
        self.0.established_notifiers.remove(&id);

        let fin = ShadowPacket::new_fin(id);
        let _ = self.tx_control(fin).await;
    }

    // ── Incoming packet handler ───────────────────────────────────────────────

    /// Route an incoming packet to the appropriate tunnel.
    ///
    /// Returns `Some((tunnel_id, src_ip))` when a SYN is received (server should
    /// call `accept_syn` for that packet).  Returns `None` for all other types.
    pub async fn handle_incoming(
        &self,
        src_ip: Ipv4Addr,
        pkt:    ShadowPacket,
    ) -> Result<Option<(ShadowPacket, Ipv4Addr)>> {
        // SYN packets are not handled internally – hand them back to the caller.
        if pkt.kind == PacketKind::Syn {
            return Ok(Some((pkt, src_ip)));
        }

        let tunnel = match self.0.tunnels.get(&pkt.tunnel_id) {
            Some(t) => t.clone(),
            None => {
                log::trace!("received packet for unknown tunnel {} from {}", pkt.tunnel_id, src_ip);
                return Ok(None);
            }
        };

        let mut t = tunnel.lock().await;

        t.touch();

        match pkt.kind {
            PacketKind::Syn => unreachable!(), // handled above

            PacketKind::SynAck => {
                if t.apply_syn_ack(&pkt) {
                    log::info!("tunnel {} established", pkt.tunnel_id);
                    let tid    = t.id;
                    let notify = t.established_notify.clone();
                    let wnotify = t.window_notify.clone();
                    let ack = ShadowPacket::new_ack(tid, pkt.seq.wrapping_add(1), MAX_WINDOW as u16);
                    drop(t);
                    // Wake the task waiting for establishment.  Use
                    // `notify_one`, not `notify_waiters`: the SYN-ACK can be
                    // processed in the window between `open_tunnel` returning
                    // and `wait_established` actually awaiting `notified()`.
                    // `notify_waiters` only wakes already-registered waiters and
                    // drops the signal if none exist, so the waiter would then
                    // block until its timeout even though the tunnel is already
                    // established.  `notify_one` stores a permit in that case,
                    // so the subsequent `notified()` returns immediately.
                    notify.notify_one();
                    // Window may now be available.
                    wnotify.notify_one();
                    self.tx_control(ack).await?;
                }
            }

            PacketKind::Ack => {
                let acked = t.arq.process_ack(pkt.ack);
                t.arq.set_send_window(pkt.window as u32);
                if acked.is_empty() {
                    t.cc.on_duplicate_ack();
                } else {
                    t.cc.on_ack(None);
                }
                // Notify the send task that window space may have opened.
                t.window_notify.notify_one();
            }

            PacketKind::Nack => {
                if let Some(retransmit) = t.arq.process_nack(pkt.seq) {
                    drop(t);
                    self.0.stats.add_retx_nack(1);
                    self.tx_data(retransmit).await?;
                    return Ok(None);
                }
            }

            PacketKind::Data => {
                let tid = t.id;
                let app_tx = t.app_tx.clone();
                let (deliverable, ack_num, nacks) = t.arq.receive(pkt.clone());

                let window = (MAX_WINDOW.saturating_sub(t.arq.in_flight())) as u16;
                drop(t);

                for payload in deliverable {
                    if app_tx.send(payload).await.is_err() {
                        self.close_tunnel(tid).await;
                        return Ok(None);
                    }
                }

                self.tx_control(ShadowPacket::new_ack(tid, ack_num, window)).await?;
                for missing in nacks {
                    self.tx_control(ShadowPacket::new_nack(tid, missing)).await?;
                }
            }

            PacketKind::Fin => {
                t.state = TunnelState::Closed;
                log::info!("tunnel {} closed by peer", pkt.tunnel_id);
            }

            PacketKind::Heartbeat => {
                let tid  = t.id;
                let hb_ack = ShadowPacket {
                    kind:      PacketKind::HeartbeatAck,
                    tunnel_id: tid,
                    seq:       pkt.seq,
                    ack:       0,
                    window:    0,
                    payload:   pkt.payload,
                };
                drop(t);
                self.tx_control(hb_ack).await?;
            }

            PacketKind::HeartbeatAck => {
                // Measure RTT from the timestamp embedded in the payload.
                if pkt.payload.len() >= 8 {
                    let sent_ms = u64::from_be_bytes(
                        pkt.payload[..8].try_into().unwrap_or([0u8; 8]),
                    ) as f64;
                    let now_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as f64;
                    let rtt = (now_ms - sent_ms).max(0.0);
                    t.record_rtt(rtt);
                    self.0.stats.add_rtt_sample();
                    log::debug!("tunnel {} RTT {:.1} ms", pkt.tunnel_id, rtt);
                }
            }
        }

        Ok(None)
    }

    // ── Periodic tick ─────────────────────────────────────────────────────────

    /// Drive retransmissions and send heartbeats.  Call every ~100 ms.
    pub async fn tick(&self) -> Result<()> {
        let (expired_pkts, heartbeats, _to_remove): (Vec<_>, Vec<_>, Vec<_>) = {
            let mut exp  = Vec::new();
            let mut hbs  = Vec::new();
            let mut dead = Vec::new();
            let now = Instant::now();

            let tunnels: Vec<(u32, Arc<Mutex<Tunnel>>)> = self
                .0
                .tunnels
                .iter()
                .map(|entry| (*entry.key(), entry.value().clone()))
                .collect();

            for (id, tunnel) in tunnels {
                let mut t = tunnel.lock().await;

                if t.state == TunnelState::Closed {
                    dead.push(id);
                    continue;
                }
                let timed_out = t.arq.take_timed_out();
                if !timed_out.is_empty() {
                    t.on_loss();
                    self.0.stats.add_retx_timeout(timed_out.len() as u64);
                    exp.extend(timed_out);
                }
                let gave_up = t.arq.take_gave_up();
                if gave_up > 0 {
                    self.0.stats.add_gave_up(gave_up);
                }
                if t.state == TunnelState::Established
                    && t.is_idle(HEARTBEAT_IDLE_TIMEOUT)
                    && now.duration_since(t.last_heartbeat_sent) >= HEARTBEAT_MIN_INTERVAL
                {
                    t.last_heartbeat_sent = now;
                    hbs.push(ShadowPacket::new_heartbeat(t.id, rand::random()));
                }
            }

            for id in &dead {
                self.0.tunnels.remove(id);
                self.0.established_notifiers.remove(id);
            }
            (exp, hbs, dead)
        };

        for pkt in expired_pkts { self.tx_data(pkt).await?; }
        for hb  in heartbeats   { self.tx_control(hb).await?; }
        Ok(())
    }

    // ── Live tuning & stats ───────────────────────────────────────────────────

    /// The ARQ/congestion knobs new tunnels are created with.
    pub fn current_tuning(&self) -> Tuning {
        *self.0.tuning.read().unwrap_or_else(|e| e.into_inner())
    }

    /// Replace the tuning knobs for new tunnels and apply them to every
    /// existing tunnel, so a reload takes effect without dropping sessions.
    pub async fn apply_tuning(&self, tuning: Tuning) {
        *self.0.tuning.write().unwrap_or_else(|e| e.into_inner()) = tuning;
        let tunnels: Vec<Arc<Mutex<Tunnel>>> =
            self.0.tunnels.iter().map(|e| e.value().clone()).collect();
        for tunnel in tunnels {
            let mut t = tunnel.lock().await;
            t.arq.set_max_retries(tuning.max_retries);
            t.cc.set_rto_min_ms(tuning.rto_min_ms as f64);
        }
    }

    /// Log one `stats:` line per `every` while there is traffic (and at least
    /// once a minute otherwise), with interval counters and the mean
    /// smoothed RTT / RTT variance of tunnels that have an RTT sample.
    /// The line format is parsed by the panel's monitor; keep it stable.
    pub fn spawn_stats_reporter(&self, every: Duration) {
        let this = self.clone();
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(every);
            iv.tick().await;
            let mut last_log = Instant::now();
            loop {
                iv.tick().await;
                let snap = this.0.stats.take();
                let tunnels: Vec<Arc<Mutex<Tunnel>>> =
                    this.0.tunnels.iter().map(|e| e.value().clone()).collect();
                let n = tunnels.len();
                let (mut srtt, mut var, mut k) = (0.0, 0.0, 0u32);
                for tunnel in tunnels {
                    let t = tunnel.lock().await;
                    if t.state == TunnelState::Established {
                        if let Some((s, v)) = t.cc.rtt.sample() {
                            srtt += s;
                            var += v;
                            k += 1;
                        }
                    }
                }
                if snap.is_idle() && n == 0 && last_log.elapsed() < Duration::from_secs(60) {
                    continue;
                }
                last_log = Instant::now();
                let tn = this.current_tuning();
                let (srtt_s, var_s) = if k > 0 {
                    (format!("{:.1}", srtt / k as f64), format!("{:.1}", var / k as f64))
                } else {
                    ("-".to_string(), "-".to_string())
                };
                log::info!(
                    "stats: tunnels={} sent={} retx_timeout={} retx_nack={} gave_up={} \
                     rtt_samples={} srtt_ms={} rttvar_ms={} rto_min_ms={} max_retries={} interval_s={}",
                    n, snap.data_sent, snap.retx_timeout, snap.retx_nack, snap.gave_up,
                    snap.rtt_samples, srtt_s, var_s, tn.rto_min_ms, tn.max_retries,
                    every.as_secs()
                );
            }
        });
    }

    // ── Status helpers ────────────────────────────────────────────────────────

    /// Wait until the tunnel with `id` is in the Established state (or the
    /// supplied deadline elapses).  Uses `Notify` – no polling.
    pub async fn wait_established(&self, id: u32, timeout: Duration) -> bool {
        // If already established, return immediately.
        if self.is_established(id).await { return true; }

        // Retrieve the notifier registered during open_tunnel.
        let notifier = {
            self.0.established_notifiers.get(&id).map(|n| n.clone())
        };
        let Some(notifier) = notifier else { return false; };

        let established = tokio::time::timeout(timeout, notifier.notified())
            .await
            .is_ok()
            && self.is_established(id).await;

        if established {
            self.0.established_notifiers.remove(&id);
        }
        established
    }

    /// True if the tunnel with `id` is in the Established state.
    pub async fn is_established(&self, id: u32) -> bool {
        let Some(tunnel) = self.0.tunnels.get(&id).map(|t| t.clone()) else {
            return false;
        };
        let established = {
            let guard = tunnel.lock().await;
            guard.state == TunnelState::Established
        };
        established
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    /// Spawn a background task that drains `net_rx` and sends each chunk as a
    /// data packet through the tunnel, respecting the congestion window.
    ///
    /// Uses `window_notify` to sleep until the window has room (instead of
    /// polling), avoiding unnecessary CPU usage.
    fn spawn_send_task(
        &self,
        tunnel_id:     u32,
        mut net_rx:    mpsc::Receiver<Bytes>,
        window_notify: Arc<Notify>,
    ) {
        let this = self.clone();
        let mtu  = self.0.cfg.mtu;
        tokio::spawn(async move {
            while let Some(data) = net_rx.recv().await {
                // Fragment large buffers into MTU-sized chunks.
                let mut offset = 0;
                while offset < data.len() {
                    let end   = (offset + mtu).min(data.len());
                    let chunk = data.slice(offset..end);

                    // Wait until the congestion/ARQ window has room.
                    // `Notify::notified()` is consumed by one waiter so this
                    // is race-free: if the window opens between the `can_send`
                    // check and the await, the notification is stored and we
                    // wake immediately.
                    loop {
                        let can = {
                            if let Some(tunnel) = this.0.tunnels.get(&tunnel_id).map(|t| t.clone()) {
                                tunnel.lock().await.can_send()
                            } else {
                                false
                            }
                        };
                        if can { break; }
                        // Block until an ACK arrives and opens the window.
                        window_notify.notified().await;
                    }

                    if let Err(e) = this.enqueue_and_send(tunnel_id, chunk).await {
                        log::debug!("send task tunnel {}: {}", tunnel_id, e);
                        return;
                    }
                    offset = end;
                }
            }
            log::debug!("send task for tunnel {} finished", tunnel_id);
        });
    }

    async fn enqueue_and_send(&self, tunnel_id: u32, payload: Bytes) -> Result<()> {
        let pkt = {
            let tunnel = self
                .0
                .tunnels
                .get(&tunnel_id)
                .map(|t| t.clone())
                .ok_or_else(|| anyhow!("tunnel {} gone", tunnel_id))?;
            let mut t = tunnel.lock().await;
            t.make_data_packet(payload)
        };
        self.0.stats.add_sent(1);
        self.tx_data(pkt).await
    }

    async fn tx_control(&self, pkt: ShadowPacket) -> Result<()> {
        let a   = &self.0.addr;
        let enc = pkt.encode_authenticated(&self.0.key);
        let out = OutPacket::Icmp {
            src_ip:  a.local_spoof,
            dst_ip:  a.peer_real,
            id:      a.icmp_id,
            seq:     (pkt.seq & 0xffff) as u16,
            payload: enc,
        };
        self.0.sender.send(out).await
    }

    async fn tx_data(&self, pkt: ShadowPacket) -> Result<()> {
        let a   = &self.0.addr;
        let enc = pkt.encode_authenticated(&self.0.key);
        let out = OutPacket::Udp {
            src_ip:   a.local_spoof,
            dst_ip:   a.peer_real,
            src_port: a.data_port,
            dst_port: a.data_port,
            payload:  enc,
        };
        self.0.sender.send(out).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn client_syn_ack_updates_recv_base_to_peer_seq_plus_one() {
        const PEER_SEQ: u32 = 777;
        let (app_tx, _app_rx) = mpsc::channel::<Bytes>(1);
        let mut tunnel = Tunnel::new(1, TunnelState::SynSent, 100, 0, app_tx, 10.0, Tuning::default());
        let syn_ack = ShadowPacket::new_syn_ack(1, 99, PEER_SEQ);

        assert_eq!(tunnel.arq.recv_base(), 0);
        assert!(tunnel.apply_syn_ack(&syn_ack));
        assert_eq!(tunnel.arq.recv_base(), PEER_SEQ + 1);
    }

    #[tokio::test]
    async fn make_data_packet_uses_arq_assigned_seq() {
        let (app_tx, _app_rx) = mpsc::channel::<Bytes>(1);
        let mut tunnel = Tunnel::new(42, TunnelState::Established, 1000, 7, app_tx, 10.0, Tuning::default());

        let p1 = tunnel.make_data_packet(Bytes::from_static(b"a"));
        let p2 = tunnel.make_data_packet(Bytes::from_static(b"b"));

        assert_eq!(p1.seq, 1000);
        assert_eq!(p2.seq, 1001);
        assert_eq!(p1.ack, 7);
        assert_eq!(p2.ack, 7);
    }

    #[tokio::test]
    async fn server_first_data_seq_is_syn_ack_seq_plus_one() {
        const TID: u32 = 9;
        const PEER_SEQ: u32 = 555;
        const OUR_SYN_ACK_SEQ: u32 = 777;
        let (app_tx, _app_rx) = mpsc::channel::<Bytes>(1);

        let mut tunnel = Tunnel::new(
            TID,
            TunnelState::Established,
            OUR_SYN_ACK_SEQ.wrapping_add(1),
            PEER_SEQ.wrapping_add(1),
            app_tx,
            10.0,
            Tuning::default(),
        );
        let syn_ack = ShadowPacket::new_syn_ack(TID, PEER_SEQ, OUR_SYN_ACK_SEQ);
        let first_data = tunnel.make_data_packet(Bytes::from_static(b"x"));

        assert_eq!(first_data.seq, syn_ack.seq.wrapping_add(1));
    }
}
