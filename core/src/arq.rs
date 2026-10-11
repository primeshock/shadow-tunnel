//! Selective Repeat ARQ (SR-ARQ) implementation.
//!
//! Provides reliable, ordered delivery on top of an unreliable channel by:
//! - Buffering out-of-order received packets until the window advances
//! - Tracking unacknowledged sent packets and detecting timeouts
//! - Generating NACKs for detected gaps in received sequence space

use std::collections::HashMap;
use std::time::{Duration, Instant};

use bytes::Bytes;

use crate::packet::CandyPacket;

/// Maximum allowed send/receive window size.
pub const MAX_WINDOW: u32 = 128;
/// Maximum number of times a packet will be retransmitted before giving up.
pub const MAX_RETRIES: u32 = 8;
/// Default RTO when no RTT sample is available.
pub const DEFAULT_RTO: Duration = Duration::from_millis(500);

// ── Internal book-keeping ─────────────────────────────────────────────────────

struct SendSlot {
    packet:      CandyPacket,
    sent_at:     Instant,
    retry_count: u32,
}

// ── Public types ──────────────────────────────────────────────────────────────

/// Selective Repeat ARQ state for one tunnel direction.
pub struct SrArq {
    // Sender
    send_base: u32,
    send_next: u32,
    send_win:  u32,
    send_buf:  HashMap<u32, SendSlot>,

    // Receiver
    recv_base: u32,
    recv_buf:  HashMap<u32, CandyPacket>,

    /// Current retransmission timeout.
    pub rto: Duration,

    /// Maximum retransmissions before a packet is dropped (configurable; the
    /// default matches [`MAX_RETRIES`]).
    max_retries: u32,
}

impl SrArq {
    /// Create a new ARQ state.  `init_seq` is the first sequence number the
    /// sender will use; `init_recv` is the first sequence number we expect to
    /// receive.
    pub fn new(init_seq: u32, init_recv: u32) -> Self {
        Self {
            send_base: init_seq,
            send_next: init_seq,
            send_win:  MAX_WINDOW,
            send_buf:  HashMap::new(),
            recv_base: init_recv,
            recv_buf:  HashMap::new(),
            rto:       DEFAULT_RTO,
            max_retries: MAX_RETRIES,
        }
    }

    /// Override the retransmission cap (defaults to [`MAX_RETRIES`]).
    pub fn set_max_retries(&mut self, n: u32) { self.max_retries = n; }

    // ── Sender ────────────────────────────────────────────────────────────────

    /// Returns `true` if the sender window has room for at least one more packet.
    pub fn can_send(&self) -> bool {
        self.in_flight() < self.send_win
    }

    /// Number of packets currently in flight (sent but not yet ACKed).
    pub fn in_flight(&self) -> u32 {
        self.send_next.wrapping_sub(self.send_base)
    }

    /// Assign a sequence number and buffer the packet for potential
    /// retransmission.  Returns the sequence number.
    pub fn enqueue(&mut self, pkt: &mut CandyPacket) -> u32 {
        let seq = self.send_next;
        pkt.seq = seq;
        self.send_buf.insert(seq, SendSlot {
            packet:      pkt.clone(),
            sent_at:     Instant::now(),
            retry_count: 0,
        });
        self.send_next = self.send_next.wrapping_add(1);
        seq
    }

    /// Process a cumulative ACK.  Returns the set of sequence numbers that
    /// were newly acknowledged (useful for RTT sampling).
    pub fn process_ack(&mut self, ack_num: u32) -> Vec<u32> {
        let mut newly_acked = Vec::new();

        // Remove every slot with seq < ack_num (already delivered).
        let keys: Vec<u32> = self.send_buf.keys().copied().collect();
        for seq in keys {
            if seq_before(seq, ack_num) {
                self.send_buf.remove(&seq);
                newly_acked.push(seq);
            }
        }

        if !newly_acked.is_empty() {
            self.send_base = ack_num;
        }
        newly_acked
    }

    /// Process a NACK requesting retransmission of `seq`.  Returns the packet
    /// to resend, or `None` if `seq` is unknown or exhausted retries.
    pub fn process_nack(&mut self, seq: u32) -> Option<CandyPacket> {
        let slot = self.send_buf.get_mut(&seq)?;
        if slot.retry_count >= self.max_retries {
            log::warn!("ARQ: seq {} exceeded max retries – dropping", seq);
            return None;
        }
        slot.retry_count += 1;
        slot.sent_at = Instant::now();
        Some(slot.packet.clone())
    }

    /// Collect all in-flight packets whose RTO has expired.  The caller should
    /// retransmit them and notify the congestion controller.
    pub fn take_timed_out(&mut self) -> Vec<CandyPacket> {
        let now = Instant::now();
        let rto = self.rto;
        let mut expired = Vec::new();
        for slot in self.send_buf.values_mut() {
            if now.duration_since(slot.sent_at) >= rto {
                if slot.retry_count < self.max_retries {
                    slot.retry_count += 1;
                    slot.sent_at = now;
                    expired.push(slot.packet.clone());
                }
            }
        }
        expired
    }

    // ── Receiver ──────────────────────────────────────────────────────────────

    /// Deliver a received data packet.
    ///
    /// Returns:
    /// - `deliverable`: payloads that are now in order and ready for the application
    /// - `ack_num`: the next seq we expect (use in the next ACK packet)
    /// - `nacks`: seq numbers of detected gaps (request retransmission)
    pub fn receive(&mut self, pkt: CandyPacket) -> (Vec<Bytes>, u32, Vec<u32>) {
        let seq = pkt.seq;
        let mut deliverable = Vec::new();
        let mut nacks = Vec::new();

        if seq == self.recv_base {
            // In-order delivery
            deliverable.push(pkt.payload);
            self.recv_base = self.recv_base.wrapping_add(1);

            // Flush any buffered contiguous packets
            while let Some(buffered) = self.recv_buf.remove(&self.recv_base) {
                deliverable.push(buffered.payload);
                self.recv_base = self.recv_base.wrapping_add(1);
            }
        } else if seq_before(self.recv_base, seq) {
            // Future packet – buffer it
            self.recv_buf.entry(seq).or_insert(pkt);

            // Request retransmission of any missing packets in the gap
            let mut gap = self.recv_base;
            while seq_before(gap, seq) {
                if !self.recv_buf.contains_key(&gap) {
                    nacks.push(gap);
                }
                gap = gap.wrapping_add(1);
            }
        }
        // Packets before recv_base are duplicates – ignore.

        (deliverable, self.recv_base, nacks)
    }

    // ── Accessors / mutators ──────────────────────────────────────────────────

    pub fn send_base(&self)          -> u32 { self.send_base }
    pub fn recv_base(&self)          -> u32 { self.recv_base }
    pub fn set_send_window(&mut self, w: u32) { self.send_win = w.min(MAX_WINDOW); }
    pub fn set_recv_base(&mut self, seq: u32) { self.recv_base = seq; }
    pub fn update_rto(&mut self, rto: Duration) { self.rto = rto; }
}

// ── Sequence-number helpers (wrapping arithmetic) ─────────────────────────────

/// Returns `true` if sequence number `a` comes before `b` in the circular
/// sequence space (i.e., the "forward" distance from `a` to `b` is positive
/// and less than 2^31).
fn seq_before(a: u32, b: u32) -> bool {
    let dist = b.wrapping_sub(a);
    dist != 0 && dist < (1u32 << 31)
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::CandyPacket;

    fn data_pkt(seq: u32) -> CandyPacket {
        CandyPacket::new_data(1, seq, 0, 64, bytes::Bytes::from(vec![seq as u8]))
    }

    #[test]
    fn in_order_delivery() {
        let mut arq = SrArq::new(0, 0);
        let (delivered, ack, nacks) = arq.receive(data_pkt(0));
        assert_eq!(delivered.len(), 1);
        assert_eq!(ack, 1);
        assert!(nacks.is_empty());
    }

    #[test]
    fn out_of_order_buffering_and_flush() {
        let mut arq = SrArq::new(0, 0);
        // Receive seq=1 before seq=0
        let (d1, _, nacks1) = arq.receive(data_pkt(1));
        assert!(d1.is_empty());
        assert_eq!(nacks1, vec![0]);

        // Now receive seq=0 – both should be delivered
        let (d0, ack, nacks0) = arq.receive(data_pkt(0));
        assert_eq!(d0.len(), 2);
        assert_eq!(ack, 2);
        assert!(nacks0.is_empty());
    }

    #[test]
    fn ack_advances_window() {
        let mut arq = SrArq::new(0, 0);
        let mut p = data_pkt(0);
        let _seq = arq.enqueue(&mut p);
        assert!(!arq.can_send() || arq.in_flight() == 1);
        let acked = arq.process_ack(1);
        assert_eq!(acked.len(), 1);
        assert_eq!(arq.send_base(), 1);
    }

    #[test]
    fn configurable_max_retries_caps_nack_retransmits() {
        let mut arq = SrArq::new(0, 0);
        arq.set_max_retries(2);
        let mut p = data_pkt(0);
        let seq = arq.enqueue(&mut p);
        // Two retransmits are allowed, the third is refused.
        assert!(arq.process_nack(seq).is_some());
        assert!(arq.process_nack(seq).is_some());
        assert!(arq.process_nack(seq).is_none());
    }

    #[test]
    fn seq_before_wraps() {
        assert!(seq_before(u32::MAX - 1, u32::MAX));
        assert!(seq_before(u32::MAX, 0));
        assert!(!seq_before(5, 3));
    }
}
