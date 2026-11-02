//! Relay limiters, in memory only.
//!
//! `TokenLimiter`: per-token push limiter, a token bucket for the burst (6
//! pushes, refilled at 1 per 10 s, hence 1 push / 10 s on average) and a
//! sliding window for the hourly cap (60 pushes in any rolling hour). Keys are
//! the BLAKE3 hash of the APNs token, so the table never holds a token itself;
//! the table is capped at `MAX_ENTRIES`.
//!
//! `IntakeBudget`: per-peer budget of items opened, checked before any
//! decryption work (peers grouped as the connection caps group them).

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
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
/// Most tokens tracked at once: at the cap a new token is refused (its push
/// counted as limited) rather than inserted, so junk tokens cannot grow the
/// table without bound.
pub const MAX_ENTRIES: usize = 1_000_000;

/// Items a peer may hand in a row, then items per second.
pub const INTAKE_BURST: u32 = 400;
pub const INTAKE_PER_SEC: u32 = 200;

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
    max_entries: usize,
}

impl Default for TokenLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenLimiter {
    pub fn new() -> Self {
        Self::with_max_entries(MAX_ENTRIES)
    }

    /// A limiter tracking at most `max_entries` tokens.
    pub fn with_max_entries(max_entries: usize) -> Self {
        TokenLimiter {
            entries: HashMap::new(),
            last_purge: None,
            max_entries,
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
        if self.entries.len() >= self.max_entries && !self.entries.contains_key(&key) {
            return false;
        }
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

/// Per-peer token bucket of items, refilled continuously.
struct Bucket {
    tokens: f64,
    at: Instant,
}

pub struct IntakeBudget {
    peers: HashMap<IpAddr, Bucket>,
    last_purge: Option<Instant>,
}

impl Default for IntakeBudget {
    fn default() -> Self {
        Self::new()
    }
}

impl IntakeBudget {
    pub fn new() -> Self {
        IntakeBudget {
            peers: HashMap::new(),
            last_purge: None,
        }
    }

    /// Number of tracked peers.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Takes up to `n` items from `peer`'s budget; returns how many were
    /// granted. `now` must not go backwards between calls.
    pub fn take(&mut self, peer: IpAddr, n: u32, now: Instant) -> u32 {
        self.purge(now);
        let burst = f64::from(INTAKE_BURST);
        let b = self.peers.entry(peer).or_insert(Bucket {
            tokens: burst,
            at: now,
        });
        let earned = now.saturating_duration_since(b.at).as_secs_f64() * f64::from(INTAKE_PER_SEC);
        b.tokens = (b.tokens + earned).min(burst);
        b.at = now;
        // Whole items only; `tokens` is within 0..=burst, so this fits.
        let granted = (b.tokens.floor() as u32).min(n);
        b.tokens -= f64::from(granted);
        granted
    }

    /// Drops peers idle long enough for their bucket to be full again.
    fn purge(&mut self, now: Instant) {
        if self
            .last_purge
            .is_some_and(|p| now.saturating_duration_since(p) < PURGE_EVERY)
        {
            return;
        }
        self.last_purge = Some(now);
        self.peers
            .retain(|_, b| now.saturating_duration_since(b.at) < PURGE_EVERY);
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
    fn new_tokens_are_refused_at_the_entry_cap() {
        let mut l = TokenLimiter::with_max_entries(2);
        let t0 = Instant::now();
        assert!(l.allow(b"a", t0));
        assert!(l.allow(b"b", t0));
        // Full table: a new token is refused and not inserted...
        assert!(!l.allow(b"c", t0));
        assert_eq!(l.len(), 2);
        // ...while tracked tokens keep their quota.
        assert!(l.allow(b"a", t0));
        // Once idle entries are purged, room is made again.
        assert!(l.allow(b"c", t0 + Duration::from_secs(3601)));
        assert_eq!(l.len(), 1);
    }

    #[test]
    fn default_entry_cap() {
        assert_eq!(MAX_ENTRIES, 1_000_000);
        assert_eq!(TokenLimiter::new().max_entries, MAX_ENTRIES);
    }

    fn v4(last: u8) -> IpAddr {
        IpAddr::from([192, 0, 2, last])
    }

    #[test]
    fn intake_burst_then_rate() {
        let mut b = IntakeBudget::new();
        let t0 = Instant::now();
        assert_eq!((INTAKE_BURST, INTAKE_PER_SEC), (400, 200));
        assert_eq!(b.take(v4(1), 300, t0), 300);
        assert_eq!(b.take(v4(1), 300, t0), 100);
        assert_eq!(b.take(v4(1), 10, t0), 0);
        // 200 items per second come back, never more than the burst.
        assert_eq!(b.take(v4(1), 300, t0 + Duration::from_millis(500)), 100);
        assert_eq!(b.take(v4(1), 1000, t0 + Duration::from_secs(60)), 400);
    }

    #[test]
    fn intake_budgets_are_per_peer() {
        let mut b = IntakeBudget::new();
        let t0 = Instant::now();
        assert_eq!(b.take(v4(1), 400, t0), 400);
        assert_eq!(b.take(v4(1), 1, t0), 0);
        assert_eq!(b.take(v4(2), 400, t0), 400);
    }

    #[test]
    fn idle_intake_entries_are_purged() {
        let mut b = IntakeBudget::new();
        let t0 = Instant::now();
        b.take(v4(1), 1, t0);
        b.take(v4(2), 1, t0);
        assert_eq!(b.len(), 2);
        b.take(v4(3), 1, t0 + Duration::from_secs(61));
        assert_eq!(b.len(), 1);
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
