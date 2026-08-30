//! Per-session token-bucket rate limiting (Step 25): packets/sec and
//! bytes/sec with a one-second burst capacity. Exceeding traffic is
//! silently dropped (datagram semantics).

use std::sync::Mutex;
use std::time::Instant;

/// Per-session limits; 0 means unlimited for that dimension.
#[derive(Debug, Clone, Copy, Default)]
pub struct RateLimits {
    pub packets_per_sec: u64,
    pub bytes_per_sec: u64,
}

impl RateLimits {
    pub fn is_unlimited(&self) -> bool {
        self.packets_per_sec == 0 && self.bytes_per_sec == 0
    }
}

#[derive(Debug)]
struct BucketState {
    packet_tokens: u64,
    byte_tokens: u64,
    last_refill: Instant,
}

/// Token buckets for one session. Capacity equals the per-second rate,
/// i.e. up to one second of burst.
#[derive(Debug)]
pub struct SessionLimiter {
    limits: RateLimits,
    state: Mutex<BucketState>,
}

impl SessionLimiter {
    pub fn new(limits: RateLimits) -> Self {
        Self {
            limits,
            state: Mutex::new(BucketState {
                packet_tokens: limits.packets_per_sec,
                byte_tokens: limits.bytes_per_sec,
                last_refill: Instant::now(),
            }),
        }
    }

    /// Try to admit one packet of `bytes` length.
    pub fn try_consume(&self, bytes: u64) -> bool {
        self.try_consume_at(bytes, Instant::now())
    }

    fn try_consume_at(&self, bytes: u64, now: Instant) -> bool {
        if self.limits.is_unlimited() {
            return true;
        }
        let mut state = self.state.lock().unwrap();

        // Refill proportionally to elapsed time, capped at one second's
        // worth of tokens.
        let elapsed = now.duration_since(state.last_refill);
        if !elapsed.is_zero() {
            let add = |rate: u64| (rate as u128 * elapsed.as_micros() / 1_000_000) as u64;
            state.packet_tokens = (state.packet_tokens + add(self.limits.packets_per_sec))
                .min(self.limits.packets_per_sec);
            state.byte_tokens =
                (state.byte_tokens + add(self.limits.bytes_per_sec)).min(self.limits.bytes_per_sec);
            state.last_refill = now;
        }

        let packets_ok = self.limits.packets_per_sec == 0 || state.packet_tokens >= 1;
        let bytes_ok = self.limits.bytes_per_sec == 0 || state.byte_tokens >= bytes;
        if !(packets_ok && bytes_ok) {
            return false;
        }
        if self.limits.packets_per_sec > 0 {
            state.packet_tokens -= 1;
        }
        if self.limits.bytes_per_sec > 0 {
            state.byte_tokens -= bytes;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn unlimited_admits_everything() {
        let limiter = SessionLimiter::new(RateLimits::default());
        for _ in 0..10_000 {
            assert!(limiter.try_consume(1500));
        }
    }

    #[test]
    fn packet_rate_enforced_and_refilled() {
        let limiter = SessionLimiter::new(RateLimits {
            packets_per_sec: 3,
            bytes_per_sec: 0,
        });
        let t0 = Instant::now();
        assert!(limiter.try_consume_at(100, t0));
        assert!(limiter.try_consume_at(100, t0));
        assert!(limiter.try_consume_at(100, t0));
        assert!(!limiter.try_consume_at(100, t0), "burst exhausted");

        // Half a second refills half the bucket (1 token at 3 pps).
        let t1 = t0 + Duration::from_millis(500);
        assert!(limiter.try_consume_at(100, t1));
        assert!(!limiter.try_consume_at(100, t1));
    }

    #[test]
    fn byte_rate_enforced() {
        let limiter = SessionLimiter::new(RateLimits {
            packets_per_sec: 0,
            bytes_per_sec: 3000,
        });
        let t0 = Instant::now();
        assert!(limiter.try_consume_at(1500, t0));
        assert!(limiter.try_consume_at(1500, t0));
        assert!(!limiter.try_consume_at(1, t0), "byte bucket empty");

        let t1 = t0 + Duration::from_secs(1);
        assert!(limiter.try_consume_at(3000, t1), "fully refilled");
    }

    #[test]
    fn refill_caps_at_one_second_burst() {
        let limiter = SessionLimiter::new(RateLimits {
            packets_per_sec: 2,
            bytes_per_sec: 0,
        });
        let t0 = Instant::now();
        // Long idle must not accumulate more than one second of tokens.
        let t1 = t0 + Duration::from_secs(3600);
        assert!(limiter.try_consume_at(1, t1));
        assert!(limiter.try_consume_at(1, t1));
        assert!(!limiter.try_consume_at(1, t1));
    }
}
