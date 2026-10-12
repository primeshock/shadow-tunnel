//! TCP-like congestion control.
//!
//! Implements:
//! - Slow-start: exponential window growth until `ssthresh`
//! - Congestion avoidance: additive increase (~+1 per RTT)
//! - Fast retransmit / fast recovery on triple-duplicate-ACK
//! - Multiplicative decrease on loss
//! - RTT estimation using Jacobson/Karels algorithm (RFC 6298)

use std::time::{Duration, Instant};

// ── RTT estimator ─────────────────────────────────────────────────────────────

/// Jacobson/Karels RTT estimator (RFC 6298).
#[derive(Debug)]
pub struct RttEstimator {
    /// Smoothed RTT (ms).
    srtt_ms:    Option<f64>,
    /// RTT variance (ms).
    rttvar_ms:  f64,
    /// Current retransmission timeout.
    pub rto:    Duration,
    /// Configurable RTO floor in ms (defaults to [`RttEstimator::MIN_RTO_MS`]).
    min_rto_ms: f64,
}

impl RttEstimator {
    const ALPHA: f64 = 0.125; // 1/8
    const BETA:  f64 = 0.25;  // 1/4
    const K:     f64 = 4.0;

    const MIN_RTO_MS: f64 = 200.0;
    const MAX_RTO_MS: f64 = 60_000.0;

    pub fn new() -> Self {
        Self {
            srtt_ms:   None,
            rttvar_ms: 0.0,
            rto:       Duration::from_millis(1000),
            min_rto_ms: Self::MIN_RTO_MS,
        }
    }

    /// Override the RTO floor (defaults to [`RttEstimator::MIN_RTO_MS`]).
    pub fn set_min_rto_ms(&mut self, v: f64) { self.min_rto_ms = v.max(1.0); }

    /// Incorporate a new RTT sample (in milliseconds).
    pub fn update(&mut self, sample_ms: f64) {
        match self.srtt_ms {
            None => {
                // First measurement
                self.srtt_ms   = Some(sample_ms);
                self.rttvar_ms = sample_ms / 2.0;
            }
            Some(srtt) => {
                let err        = (sample_ms - srtt).abs();
                self.rttvar_ms = (1.0 - Self::BETA) * self.rttvar_ms + Self::BETA * err;
                let new_srtt   = (1.0 - Self::ALPHA) * srtt + Self::ALPHA * sample_ms;
                self.srtt_ms   = Some(new_srtt);
            }
        }
        let srtt = self.srtt_ms.unwrap();
        let rto_ms = (srtt + Self::K * self.rttvar_ms)
            .max(self.min_rto_ms)
            .min(Self::MAX_RTO_MS);
        self.rto = Duration::from_millis(rto_ms as u64);
    }

    /// Exponential back-off (called on RTO expiry).
    pub fn backoff(&mut self) {
        let ms = self.rto.as_millis() as f64;
        self.rto = Duration::from_millis((ms * 2.0).min(Self::MAX_RTO_MS) as u64);
    }

    /// Current smoothed RTT in milliseconds (returns 1000 before first sample).
    pub fn srtt_ms(&self) -> f64 {
        self.srtt_ms.unwrap_or(1000.0)
    }

    /// `(srtt_ms, rttvar_ms)` once at least one RTT sample exists.
    pub fn sample(&self) -> Option<(f64, f64)> {
        self.srtt_ms.map(|s| (s, self.rttvar_ms))
    }
}

impl Default for RttEstimator {
    fn default() -> Self { Self::new() }
}

// ── Congestion-control state machine ─────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CcState {
    SlowStart,
    CongestionAvoidance,
    FastRecovery,
}

/// TCP-like AIMD congestion controller.
#[derive(Debug)]
pub struct CongestionControl {
    /// Congestion window (packets).
    pub cwnd:    f64,
    /// Slow-start threshold (packets).
    ssthresh:    f64,
    /// Current state.
    pub state:   CcState,
    /// RTT estimator.
    pub rtt:     RttEstimator,
    /// Duplicate-ACK counter used to trigger fast retransmit.
    dup_acks:    u32,
    /// Timestamp of the last congestion event.
    last_cong:   Option<Instant>,
}

impl CongestionControl {
    const BETA: f64 = 0.5; // multiplicative-decrease factor

    pub fn new(initial_cwnd: f64) -> Self {
        Self {
            cwnd:      initial_cwnd,
            ssthresh:  64.0,
            state:     CcState::SlowStart,
            rtt:       RttEstimator::new(),
            dup_acks:  0,
            last_cong: None,
        }
    }

    /// Override the RTO floor used by the RTT estimator.
    pub fn set_rto_min_ms(&mut self, v: f64) { self.rtt.set_min_rto_ms(v); }

    // ── Events ────────────────────────────────────────────────────────────────

    /// An ACK was received successfully.  `rtt_ms` is the measured RTT for the
    /// acknowledged packet; pass `None` if no RTT sample is available.
    pub fn on_ack(&mut self, rtt_ms: Option<f64>) {
        if let Some(r) = rtt_ms {
            self.rtt.update(r);
        }
        self.dup_acks = 0;

        match self.state {
            CcState::SlowStart => {
                self.cwnd += 1.0;
                if self.cwnd >= self.ssthresh {
                    self.state = CcState::CongestionAvoidance;
                    log::debug!(
                        "CC: slow-start → congestion-avoidance cwnd={:.1}",
                        self.cwnd
                    );
                }
            }
            CcState::CongestionAvoidance => {
                // Additive increase: +1/cwnd per ACK ≈ +1 per RTT
                self.cwnd += 1.0 / self.cwnd;
            }
            CcState::FastRecovery => {
                // Exiting fast recovery on a new ACK
                self.cwnd  = self.ssthresh;
                self.state = CcState::CongestionAvoidance;
            }
        }
    }

    /// A retransmission timeout occurred.
    pub fn on_timeout(&mut self) {
        log::warn!("CC: timeout – cwnd {:.1} → 1", self.cwnd);
        self.ssthresh  = (self.cwnd * Self::BETA).max(2.0);
        self.cwnd      = 1.0;
        self.state     = CcState::SlowStart;
        self.last_cong = Some(Instant::now());
        self.rtt.backoff();
    }

    /// A duplicate ACK was received.  Three duplicate ACKs trigger fast
    /// retransmit and enter fast recovery.
    pub fn on_duplicate_ack(&mut self) {
        self.dup_acks += 1;

        if self.dup_acks == 3 {
            log::warn!("CC: 3 dup-ACKs – fast retransmit, cwnd {:.1}", self.cwnd);
            self.ssthresh  = (self.cwnd * Self::BETA).max(2.0);
            self.cwnd      = self.ssthresh + 3.0;
            self.state     = CcState::FastRecovery;
            self.last_cong = Some(Instant::now());
        } else if self.state == CcState::FastRecovery {
            // Inflate window per additional dup-ACK during fast recovery
            self.cwnd += 1.0;
        }
    }

    // ── Derived quantities ────────────────────────────────────────────────────

    /// How many packets we are allowed to have in flight simultaneously.
    pub fn effective_window(&self) -> u32 {
        self.cwnd.ceil() as u32
    }

    /// Minimum pacing interval between consecutive packet transmissions (ms).
    /// Returns 0 when cwnd ≥ 1 and the RTT is well-estimated.
    pub fn pacing_interval_ms(&self) -> f64 {
        if self.cwnd < 1.0 {
            return self.rtt.srtt_ms();
        }
        (self.rtt.srtt_ms() / self.cwnd).max(0.0)
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slow_start_growth() {
        let mut cc = CongestionControl::new(1.0);
        for _ in 0..10 {
            cc.on_ack(Some(50.0));
        }
        assert!(cc.cwnd > 1.0);
    }

    #[test]
    fn timeout_resets_to_slow_start() {
        let mut cc = CongestionControl::new(10.0);
        cc.on_timeout();
        assert_eq!(cc.cwnd, 1.0);
        assert_eq!(cc.state, CcState::SlowStart);
    }

    #[test]
    fn three_dup_acks_trigger_fast_retransmit() {
        let mut cc = CongestionControl::new(20.0);
        cc.on_duplicate_ack();
        cc.on_duplicate_ack();
        cc.on_duplicate_ack();
        assert_eq!(cc.state, CcState::FastRecovery);
    }

    #[test]
    fn rtt_estimator_basic() {
        let mut est = RttEstimator::new();
        est.update(100.0);
        assert!(est.srtt_ms() > 0.0);
        let old_rto = est.rto;
        est.backoff();
        assert!(est.rto > old_rto);
    }
}
