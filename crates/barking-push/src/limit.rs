//! Per-token push limiter: a token bucket for the burst (6 pushes, refilled
//! at 1 per 10 s, hence 1 push / 10 s on average) and a sliding window for the
//! hourly cap (60 pushes in any rolling hour). Keys are the BLAKE3 hash of the
//! APNs token, so the table never holds a token itself, and live in memory
//! only.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Pushes allowed in a row.
const BURST: u32 = 6;
/// Time to earn one more push.
const REFILL: Duration = Duration::from_secs(10);
/// Pushes allowed in any rolling `WINDOW`.
const PER_WINDOW: usize = 60;
const WINDOW: Duration = Duration::from_secs(3600);
/// Entries idle for `WINDOW` are dropped, at most once per `PURGE_EVERY`.
const PURGE_EVERY: Duration = Duration::from_secs(60);

struct Entry {
    /// Whole pushes available, and the instant of the last refill step
    /// (kept on a `REFILL` boundary so that fractions are not lost).
    tokens: u32,
    refilled: Instant,
    /// Instants of the pushes allowed in the last `WINDOW`: at most
    /// `PER_WINDOW`, so memory per token is bounded.
    window: VecDeque<Instant>,
    last_seen: Instant,
}

pub struct TokenLimiter {
    entries: HashMap<[u8; 32], Entry>,
    last_purge: Option<Instant>,
}

impl Default for TokenLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenLimiter {
    pub fn new() -> Self {
        TokenLimiter {
            entries: HashMap::new(),
            last_purge: None,
        }
    }

    /// Number of tracked tokens.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// True if a push to `token` is allowed now (and counts it). `now` must
    /// not go backwards between calls.
    pub fn allow(&mut self, token: &[u8], now: Instant) -> bool {
        self.purge(now);
        let key = *blake3::hash(token).as_bytes();
        let e = self.entries.entry(key).or_insert_with(|| Entry {
            tokens: BURST,
            refilled: now,
            window: VecDeque::new(),
            last_seen: now,
        });
        e.last_seen = now;

        let steps = now.saturating_duration_since(e.refilled).as_secs() / REFILL.as_secs();
        if steps > 0 {
            let steps = u32::try_from(steps).unwrap_or(u32::MAX);
            e.tokens = e.tokens.saturating_add(steps).min(BURST);
            e.refilled += REFILL * steps;
        }
        if e.tokens == BURST {
            // Full bucket: no fraction to carry.
            e.refilled = now;
        }
        while e
            .window
            .front()
            .is_some_and(|t| now.saturating_duration_since(*t) >= WINDOW)
        {
            e.window.pop_front();
        }
        if e.tokens == 0 || e.window.len() >= PER_WINDOW {
            return false;
        }
        e.tokens -= 1;
        e.window.push_back(now);
        true
    }

    fn purge(&mut self, now: Instant) {
        if self
            .last_purge
            .is_some_and(|p| now.saturating_duration_since(p) < PURGE_EVERY)
        {
            return;
        }
        self.last_purge = Some(now);
        self.entries
            .retain(|_, e| now.saturating_duration_since(e.last_seen) < WINDOW);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn six_in_a_row_then_one_per_ten_seconds() {
        let mut l = TokenLimiter::new();
        let t0 = Instant::now();
        for i in 0..6 {
            assert!(l.allow(b"tok", t0), "burst {i}");
        }
        assert!(!l.allow(b"tok", t0));
        assert!(!l.allow(b"tok", t0 + Duration::from_secs(9)));
        assert!(l.allow(b"tok", t0 + Duration::from_secs(10)));
        assert!(!l.allow(b"tok", t0 + Duration::from_secs(10)));
        assert!(!l.allow(b"tok", t0 + Duration::from_secs(19)));
        assert!(l.allow(b"tok", t0 + Duration::from_secs(20)));
    }

    #[test]
    fn sixty_per_hour_cap() {
        let mut l = TokenLimiter::new();
        let t0 = Instant::now();
        // One push every 10 s is within the bucket rate: 60 pass in 590 s.
        for i in 0..60u64 {
            assert!(
                l.allow(b"tok", t0 + Duration::from_secs(10 * i)),
                "push {i}"
            );
        }
        // The bucket has refilled but the hour window is full.
        assert!(!l.allow(b"tok", t0 + Duration::from_secs(600)));
        assert!(!l.allow(b"tok", t0 + Duration::from_secs(3599)));
        // The first push leaves the window after an hour.
        assert!(l.allow(b"tok", t0 + Duration::from_secs(3600)));
        assert!(!l.allow(b"tok", t0 + Duration::from_secs(3600)));
    }

    #[test]
    fn tokens_are_independent() {
        let mut l = TokenLimiter::new();
        let t0 = Instant::now();
        for _ in 0..6 {
            assert!(l.allow(b"a", t0));
        }
        assert!(!l.allow(b"a", t0));
        assert!(l.allow(b"b", t0));
    }

    #[test]
    fn idle_entries_are_purged() {
        let mut l = TokenLimiter::new();
        let t0 = Instant::now();
        l.allow(b"a", t0);
        l.allow(b"b", t0);
        assert_eq!(l.len(), 2);
        l.allow(b"c", t0 + Duration::from_secs(3601));
        assert_eq!(l.len(), 1);
    }
}
