//! Interval counters for the spoof transport's ARQ data path.
//!
//! The tunnel manager logs one `stats:` line per interval (see
//! [`crate::tunnel::TunnelManager::spawn_stats_reporter`]) so the panel can
//! act on measured values instead of guesses.  `retx / sent` is a
//! retransmission rate: it rises with real packet loss but also with spurious
//! retransmits when the RTO is too tight for the path's jitter, which is why
//! RTT and RTT variance are reported alongside it.

use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

#[derive(Debug, Default)]
pub struct Stats {
    data_sent:    AtomicU64,
    retx_timeout: AtomicU64,
    retx_nack:    AtomicU64,
    gave_up:      AtomicU64,
    rtt_samples:  AtomicU64,
    /// Authenticated packets received from the peer (any kind). Non-zero means
    /// the peer is alive even when no new session was opened.
    rx_pkts:      AtomicU64,
    /// Application payload bytes sent to / received from the peer.
    bytes_tx:     AtomicU64,
    bytes_rx:     AtomicU64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub data_sent:    u64,
    pub retx_timeout: u64,
    pub retx_nack:    u64,
    pub gave_up:      u64,
    pub rtt_samples:  u64,
    pub rx_pkts:      u64,
    pub bytes_tx:     u64,
    pub bytes_rx:     u64,
}

impl Stats {
    pub fn add_sent(&self, n: u64)         { self.data_sent.fetch_add(n, Relaxed); }
    pub fn add_retx_timeout(&self, n: u64) { self.retx_timeout.fetch_add(n, Relaxed); }
    pub fn add_retx_nack(&self, n: u64)    { self.retx_nack.fetch_add(n, Relaxed); }
    pub fn add_gave_up(&self, n: u64)      { self.gave_up.fetch_add(n, Relaxed); }
    pub fn add_rtt_sample(&self)           { self.rtt_samples.fetch_add(1, Relaxed); }
    pub fn add_rx_pkt(&self)               { self.rx_pkts.fetch_add(1, Relaxed); }
    pub fn add_bytes_tx(&self, n: u64)     { self.bytes_tx.fetch_add(n, Relaxed); }
    pub fn add_bytes_rx(&self, n: u64)     { self.bytes_rx.fetch_add(n, Relaxed); }

    /// Read and reset every counter.
    pub fn take(&self) -> Snapshot {
        Snapshot {
            data_sent:    self.data_sent.swap(0, Relaxed),
            retx_timeout: self.retx_timeout.swap(0, Relaxed),
            retx_nack:    self.retx_nack.swap(0, Relaxed),
            gave_up:      self.gave_up.swap(0, Relaxed),
            rtt_samples:  self.rtt_samples.swap(0, Relaxed),
            rx_pkts:      self.rx_pkts.swap(0, Relaxed),
            bytes_tx:     self.bytes_tx.swap(0, Relaxed),
            bytes_rx:     self.bytes_rx.swap(0, Relaxed),
        }
    }
}

impl Snapshot {
    pub fn retransmits(&self) -> u64 { self.retx_timeout + self.retx_nack }

    pub fn is_idle(&self) -> bool {
        self.data_sent == 0 && self.retransmits() == 0 && self.gave_up == 0
            && self.rx_pkts == 0 && self.bytes_rx == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn take_resets_counters() {
        let s = Stats::default();
        s.add_sent(10);
        s.add_retx_timeout(2);
        s.add_retx_nack(1);
        s.add_gave_up(1);
        s.add_rtt_sample();
        s.add_rx_pkt();
        s.add_bytes_tx(1200);
        s.add_bytes_rx(800);
        let a = s.take();
        assert_eq!(a, Snapshot { data_sent: 10, retx_timeout: 2, retx_nack: 1, gave_up: 1, rtt_samples: 1,
                                 rx_pkts: 1, bytes_tx: 1200, bytes_rx: 800 });
        assert_eq!(a.retransmits(), 3);
        assert!(s.take().is_idle());
    }
}
