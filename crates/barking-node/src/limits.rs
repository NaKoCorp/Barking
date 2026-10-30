//! Limites anti-abus (spec §5), tenues en mémoire seulement.
//!
//! - Connexions simultanées par adresse IP (IPv6 regroupée par préfixe /64,
//!   IPv4 encapsulée dans IPv6 ramenée à IPv4) et au total.
//! - Seau de jetons par connexion : requêtes et octets, rafale ×`burst`.
//!
//! Les adresses ne vivent que dans la table des connexions ouvertes, le temps
//! de la connexion ; elles ne sont ni écrites, ni journalisées, ni affichables
//! (`IpKey` n'implémente pas `Debug`).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LimitConfig {
    pub max_connections: u32,
    pub max_connections_per_ip: u32,
    pub requests_per_sec: u32,
    pub bytes_per_sec: u64,
    /// Capacité des seaux, en secondes de débit.
    pub burst: u32,
}

impl Default for LimitConfig {
    fn default() -> Self {
        LimitConfig {
            max_connections: 1_000,
            max_connections_per_ip: 8,
            requests_per_sec: 20,
            bytes_per_sec: 1 << 20,
            burst: 5,
        }
    }
}

/// Clé de regroupement d'une adresse : IPv4 entière, ou préfixe /64 IPv6.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum IpKey {
    V4([u8; 4]),
    V6([u8; 8]),
}

fn ip_key(ip: IpAddr) -> IpKey {
    match ip {
        IpAddr::V4(v4) => IpKey::V4(v4.octets()),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpKey::V4(v4.octets()),
            None => {
                let mut p = [0u8; 8];
                p.copy_from_slice(&v6.octets()[..8]);
                IpKey::V6(p)
            }
        },
    }
}

/// Un groupe d'adresses : connexions ouvertes et octets de réponses réservés.
#[derive(Default)]
struct Group {
    conns: u32,
    bytes: usize,
}

#[derive(Default)]
struct Table {
    per_ip: HashMap<IpKey, Group>,
    total: u32,
}

/// Compteur de connexions ouvertes.
pub struct Limiter {
    cfg: LimitConfig,
    table: Mutex<Table>,
}

impl Limiter {
    pub fn new(cfg: LimitConfig) -> Arc<Limiter> {
        Arc::new(Limiter {
            cfg,
            table: Mutex::new(Table::default()),
        })
    }

    pub fn config(&self) -> &LimitConfig {
        &self.cfg
    }

    fn table(&self) -> std::sync::MutexGuard<'_, Table> {
        self.table.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Réserve une place pour une connexion depuis `ip`, ou `None` si une
    /// limite est atteinte. La place est rendue quand la garde est lâchée.
    pub fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Option<ConnectionSlot> {
        let key = ip_key(ip);
        let mut t = self.table();
        if t.total >= self.cfg.max_connections {
            return None;
        }
        let g = t.per_ip.entry(key).or_default();
        if g.conns >= self.cfg.max_connections_per_ip {
            if g.conns == 0 {
                t.per_ip.remove(&key);
            }
            return None;
        }
        g.conns += 1;
        t.total += 1;
        Some(ConnectionSlot {
            limiter: Arc::clone(self),
            key,
        })
    }

    /// Nombre total de connexions ouvertes.
    pub fn connections(&self) -> u32 {
        self.table().total
    }

    /// Budget de débit d'une nouvelle connexion.
    pub fn budget(&self, now: Instant) -> ConnBudget {
        ConnBudget::new(&self.cfg, now)
    }
}

/// Place réservée pour une connexion.
pub struct ConnectionSlot {
    limiter: Arc<Limiter>,
    key: IpKey,
}

impl ConnectionSlot {
    /// Réserve `n` octets de réponse pour le groupe d'adresses de cette
    /// connexion, sans dépasser `cap`.
    pub fn try_reserve_bytes(&self, n: usize, cap: usize) -> bool {
        let mut t = self.limiter.table();
        let Some(g) = t.per_ip.get_mut(&self.key) else {
            return false;
        };
        match g.bytes.checked_add(n) {
            Some(v) if v <= cap => {
                g.bytes = v;
                true
            }
            _ => false,
        }
    }

    /// Rend `n` octets réservés par `try_reserve_bytes`.
    pub fn release_bytes(&self, n: usize) {
        let mut t = self.limiter.table();
        if let Some(g) = t.per_ip.get_mut(&self.key) {
            g.bytes = g.bytes.saturating_sub(n);
        }
    }

    /// Octets réservés par le groupe d'adresses de cette connexion.
    pub fn group_bytes(&self) -> usize {
        self.limiter
            .table()
            .per_ip
            .get(&self.key)
            .map_or(0, |g| g.bytes)
    }
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        let mut t = self.limiter.table();
        t.total = t.total.saturating_sub(1);
        if let Some(g) = t.per_ip.get_mut(&self.key) {
            g.conns = g.conns.saturating_sub(1);
            if g.conns == 0 {
                t.per_ip.remove(&self.key);
            }
        }
    }
}

/// Seau de jetons : `rate` jetons par seconde, `capacity` au plus.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    rate: f64,
    capacity: f64,
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    /// Seau plein au départ.
    pub fn new(rate: f64, capacity: f64, now: Instant) -> TokenBucket {
        TokenBucket {
            rate,
            capacity,
            tokens: capacity,
            last: now,
        }
    }

    fn refill(&mut self, now: Instant) {
        let dt = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + dt * self.rate).min(self.capacity);
        self.last = now;
    }

    fn available(&mut self, n: f64, now: Instant) -> bool {
        self.refill(now);
        self.tokens >= n
    }

    /// Prend `n` jetons sans condition ; le seau peut s'endetter jusqu'à
    /// `-capacity` (une réponse volumineuse freine les requêtes suivantes).
    fn charge(&mut self, n: f64, now: Instant) {
        self.refill(now);
        self.tokens = (self.tokens - n).max(-self.capacity);
    }
}

/// Budget de débit d'une connexion : requêtes et octets.
#[derive(Debug, Clone)]
pub struct ConnBudget {
    requests: TokenBucket,
    bytes: TokenBucket,
}

impl ConnBudget {
    pub fn new(cfg: &LimitConfig, now: Instant) -> ConnBudget {
        let burst = f64::from(cfg.burst.max(1));
        let rps = f64::from(cfg.requests_per_sec);
        let bps = cfg.bytes_per_sec as f64;
        ConnBudget {
            requests: TokenBucket::new(rps, rps * burst, now),
            bytes: TokenBucket::new(bps, bps * burst, now),
        }
    }

    /// Admet une requête de `bytes` octets si les deux seaux le permettent,
    /// et la débite. Sinon rien n'est débité.
    pub fn admit(&mut self, bytes: usize, now: Instant) -> bool {
        let b = bytes as f64;
        if self.requests.available(1.0, now) && self.bytes.available(b, now) {
            self.requests.charge(1.0, now);
            self.bytes.charge(b, now);
            true
        } else {
            false
        }
    }

    /// Débite les octets d'une réponse.
    pub fn charge_bytes(&mut self, bytes: usize, now: Instant) {
        self.bytes.charge(bytes as f64, now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn cfg() -> LimitConfig {
        LimitConfig {
            max_connections: 5,
            max_connections_per_ip: 2,
            ..LimitConfig::default()
        }
    }

    #[test]
    fn per_ip_limit_and_release() {
        let l = Limiter::new(cfg());
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let a = l.try_acquire(ip).unwrap();
        let _b = l.try_acquire(ip).unwrap();
        assert!(l.try_acquire(ip).is_none());
        // Autre adresse : acceptée.
        let _c = l.try_acquire("192.0.2.2".parse().unwrap()).unwrap();
        drop(a);
        assert!(l.try_acquire(ip).is_some());
    }

    #[test]
    fn ipv6_grouped_by_64_and_mapped_v4() {
        let l = Limiter::new(cfg());
        let _a = l.try_acquire("2001:db8:1:2::1".parse().unwrap()).unwrap();
        let _b = l
            .try_acquire("2001:db8:1:2:ffff:ffff:ffff:ffff".parse().unwrap())
            .unwrap();
        // Même /64 : refusée.
        assert!(l.try_acquire("2001:db8:1:2::99".parse().unwrap()).is_none());
        // Autre /64 : acceptée.
        let _c = l.try_acquire("2001:db8:1:3::1".parse().unwrap()).unwrap();
        // IPv4 encapsulée = même clé que l'IPv4.
        let _d = l.try_acquire("198.51.100.7".parse().unwrap()).unwrap();
        let _e = l
            .try_acquire("::ffff:198.51.100.7".parse().unwrap())
            .unwrap();
        assert!(l.try_acquire("198.51.100.7".parse().unwrap()).is_none());
    }

    #[test]
    fn group_byte_reservation() {
        let l = Limiter::new(cfg());
        let a = l.try_acquire("2001:db8::1".parse().unwrap()).unwrap();
        let b = l.try_acquire("2001:db8::2".parse().unwrap()).unwrap();
        let c = l.try_acquire("2001:db9::1".parse().unwrap()).unwrap();
        assert!(a.try_reserve_bytes(600, 1000));
        // Même /64 : part commune.
        assert!(!b.try_reserve_bytes(500, 1000));
        assert!(b.try_reserve_bytes(400, 1000));
        assert_eq!(a.group_bytes(), 1000);
        // Autre groupe : indépendant.
        assert!(c.try_reserve_bytes(1000, 1000));
        a.release_bytes(600);
        assert!(b.try_reserve_bytes(600, 1000));
        assert!(!a.try_reserve_bytes(usize::MAX, usize::MAX));
    }

    #[test]
    fn global_limit() {
        let l = Limiter::new(cfg());
        let slots: Vec<_> = (1..=5u8)
            .map(|i| l.try_acquire(IpAddr::from([10, 0, 0, i])).unwrap())
            .collect();
        assert_eq!(l.connections(), 5);
        assert!(l.try_acquire(IpAddr::from([10, 0, 0, 9])).is_none());
        drop(slots);
        assert_eq!(l.connections(), 0);
        assert!(l.table().per_ip.is_empty());
    }

    #[test]
    fn request_bucket_burst_then_refill() {
        let t0 = Instant::now();
        let c = LimitConfig::default();
        let mut b = ConnBudget::new(&c, t0);
        // Rafale ×5 : 100 requêtes, puis refus.
        for _ in 0..100 {
            assert!(b.admit(10, t0));
        }
        assert!(!b.admit(10, t0));
        // 1 s plus tard : 20 de plus.
        let t1 = t0 + Duration::from_secs(1);
        for _ in 0..20 {
            assert!(b.admit(10, t1));
        }
        assert!(!b.admit(10, t1));
    }

    #[test]
    fn byte_bucket_and_response_debt() {
        let t0 = Instant::now();
        let c = LimitConfig::default();
        let mut b = ConnBudget::new(&c, t0);
        assert!(b.admit(5 << 20, t0));
        assert!(!b.admit(1, t0));
        // Une réponse endette le seau : il faut attendre plus longtemps.
        b.charge_bytes(1 << 20, t0);
        assert!(!b.admit(1, t0 + Duration::from_millis(900)));
        assert!(b.admit(1, t0 + Duration::from_millis(1100)));
    }
}
