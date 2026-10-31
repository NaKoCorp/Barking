//! TOML configuration of the node (spec §8). The default values are those of
//! the spec; an unknown key or an out-of-range value is an error.

use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::path::{Path, PathBuf};

use barking_dht::{BootstrapEntry, parse_bootstrap};
use barking_proto::pow::{DEFAULT_POW_BITS, MAX_POW_BITS};
use barking_proto::routable;
use ed25519_dalek::SigningKey;
use serde::Deserialize;

use crate::limits::LimitConfig;
use crate::rules::Policy;
use crate::server::{
    self, DEFAULT_MAX_DB_JOBS, DEFAULT_MAX_RESPONSE_BYTES_IN_FLIGHT,
    DEFAULT_MAX_RESPONSE_BYTES_PER_IP, DEFAULT_MIN_SEND_RATE, ServerConfig,
};
use crate::{Error, Result};

/// Default data directory (provided systemd unit).
pub const DEFAULT_DATA_DIR: &str = "/var/lib/barking-node";
/// Default QUIC port.
pub const DEFAULT_LISTEN: &str = "[::]:4433";
/// Floor of the per-address response cap: one whole page (1 MiB).
pub const MIN_RESPONSE_BYTES_PER_IP: usize = 1 << 20;
/// Default outbound replication cap (spec §5.3).
pub const DEFAULT_REPLICATION_BYTES_PER_HOUR: u64 = 512 << 20;

/// `[dht]` section (spec §8). Without it, or without `public_addr`, the table
/// is disabled: the node stays a plain relay and answers `Unsupported` to
/// table requests.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "DhtToml")]
pub struct DhtConfig {
    /// Addresses published in the record, at most one per family.
    pub public_v4: Option<SocketAddrV4>,
    pub public_v6: Option<SocketAddrV6>,
    /// Nodes tried after the built-in list.
    pub bootstrap: Vec<BootstrapEntry>,
    /// Accepts non-routable addresses (tests, local networks).
    pub allow_private_addrs: bool,
    /// Maximum bytes replicated per hour.
    pub replication_bytes_per_hour: u64,
}

/// TOML form of `[dht]`, before validation.
#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct DhtToml {
    public_addr: Vec<String>,
    bootstrap: Vec<String>,
    allow_private_addrs: bool,
    replication_bytes_per_hour: u64,
}

impl Default for DhtToml {
    fn default() -> Self {
        DhtToml {
            public_addr: Vec::new(),
            bootstrap: Vec::new(),
            allow_private_addrs: false,
            replication_bytes_per_hour: DEFAULT_REPLICATION_BYTES_PER_HOUR,
        }
    }
}

impl TryFrom<DhtToml> for DhtConfig {
    type Error = String;

    /// Error messages echo neither the addresses nor the entries.
    fn try_from(t: DhtToml) -> core::result::Result<DhtConfig, String> {
        if t.replication_bytes_per_hour == 0 {
            return Err("dht.replication_bytes_per_hour: at least 1".into());
        }
        let mut cfg = DhtConfig {
            public_v4: None,
            public_v6: None,
            bootstrap: Vec::with_capacity(t.bootstrap.len()),
            allow_private_addrs: t.allow_private_addrs,
            replication_bytes_per_hour: t.replication_bytes_per_hour,
        };
        for a in &t.public_addr {
            let addr: SocketAddr = a
                .parse()
                .map_err(|_| "dht.public_addr: invalid address (expected ip:port)".to_string())?;
            if !t.allow_private_addrs && !routable(&addr) {
                return Err(
                    "dht.public_addr: non-routable address (allow_private_addrs = false)".into(),
                );
            }
            if let SocketAddr::V6(v6) = addr
                && barking_proto::embeds_ipv4(v6.ip())
            {
                return Err("dht.public_addr: IPv4 written as IPv6, publish it as IPv4".into());
            }
            let twice = match addr {
                SocketAddr::V4(v4) => cfg.public_v4.replace(v4).is_some(),
                SocketAddr::V6(v6) => cfg.public_v6.replace(v6).is_some(),
            };
            if twice {
                return Err("dht.public_addr: at most one address per family".into());
            }
        }
        for e in &t.bootstrap {
            cfg.bootstrap
                .push(parse_bootstrap(e).map_err(|e| format!("dht.bootstrap: {e}"))?);
        }
        Ok(cfg)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// UDP listen addresses. `[::]` also accepts IPv4 on Linux
    /// (`net.ipv6.bindv6only=0`); otherwise, list both families.
    pub listen: Vec<String>,
    pub data_dir: PathBuf,
    /// Cap on stored bytes (packets + acks).
    pub storage_max_bytes: u64,
    /// Base proof-of-work difficulty, 1 to 24 bits.
    pub pow_bits: u8,
    pub max_connections: u32,
    /// Per IPv4 address (/32) or IPv6 /64 prefix.
    pub max_connections_per_ip: u32,
    pub max_connections_per_ipv6_56: u32,
    pub max_connections_per_ipv6_48: u32,
    pub max_connections_per_ipv4_24: u32,
    /// Response bytes in flight, all peers combined (real memory:
    /// about double).
    pub max_response_bytes_in_flight: usize,
    /// Response bytes in flight per address (/64 in IPv6), at least 1 MiB.
    pub max_response_bytes_per_ip: usize,
    /// Concurrent or pending database operations.
    pub max_db_jobs: usize,
    /// Share of a /48 (IPv6) or /24 (IPv4); absent: `max_db_jobs / 8`.
    pub max_db_jobs_per_prefix: Option<usize>,
    /// Minimum expected rate of a reader, in bytes/s (extends the write
    /// deadline of a response, at most 60 s).
    pub min_send_rate: u64,
    /// Period of the aggregated logs, in seconds.
    pub log_interval_secs: u64,
    /// Hash table between nodes; absent: disabled.
    pub dht: Option<DhtConfig>,
    /// `[dht]` present without `public_addr`: table disabled, to be reported
    /// in the logs at startup.
    #[serde(skip)]
    pub dht_without_public_addr: bool,
}

impl Default for Config {
    fn default() -> Self {
        let limits = LimitConfig::default();
        let policy = Policy::default();
        Config {
            listen: vec![DEFAULT_LISTEN.to_string()],
            data_dir: PathBuf::from(DEFAULT_DATA_DIR),
            storage_max_bytes: policy.storage_max_bytes,
            pow_bits: DEFAULT_POW_BITS,
            max_connections: limits.max_connections,
            max_connections_per_ip: limits.max_connections_per_ip,
            max_connections_per_ipv6_56: limits.max_connections_per_ipv6_56,
            max_connections_per_ipv6_48: limits.max_connections_per_ipv6_48,
            max_connections_per_ipv4_24: limits.max_connections_per_ipv4_24,
            max_response_bytes_in_flight: DEFAULT_MAX_RESPONSE_BYTES_IN_FLIGHT,
            max_response_bytes_per_ip: DEFAULT_MAX_RESPONSE_BYTES_PER_IP,
            max_db_jobs: DEFAULT_MAX_DB_JOBS,
            max_db_jobs_per_prefix: None,
            min_send_rate: DEFAULT_MIN_SEND_RATE,
            log_interval_secs: 60,
            dht: None,
            dht_without_public_addr: false,
        }
    }
}

fn bad(msg: impl Into<String>) -> Error {
    Error::Config(msg.into())
}

/// Each family published in `[dht]` must have a listen address that serves
/// it: an IPv4, or `[::]` (dual stack) for IPv4; an IPv6 for IPv6.
/// Otherwise peers could not verify the record, and outbound calls would
/// have no endpoint of that family.
fn check_dht_listen(d: &DhtConfig, listen: &[String]) -> Result<()> {
    let addrs: Vec<SocketAddr> = listen.iter().filter_map(|a| a.parse().ok()).collect();
    let serves_v4 = addrs
        .iter()
        .any(|a| a.is_ipv4() || (a.is_ipv6() && a.ip().is_unspecified()));
    if d.public_v4.is_some() && !serves_v4 {
        return Err(bad(
            "dht.public_addr: IPv4 published without an IPv4 or [::] listen address",
        ));
    }
    if d.public_v6.is_some() && !addrs.iter().any(SocketAddr::is_ipv6) {
        return Err(bad(
            "dht.public_addr: IPv6 published without an IPv6 listen address",
        ));
    }
    Ok(())
}

impl Config {
    /// Reads and validates a TOML text.
    pub fn parse(text: &str) -> Result<Config> {
        let mut cfg: Config = toml::from_str(text).map_err(|e| bad(e.to_string()))?;
        cfg.validate()?;
        // `[dht]` without a public address: table disabled (spec §8).
        if cfg
            .dht
            .as_ref()
            .is_some_and(|d| d.public_v4.is_none() && d.public_v6.is_none())
        {
            cfg.dht = None;
            cfg.dht_without_public_addr = true;
        }
        Ok(cfg)
    }

    pub fn load(path: &Path) -> Result<Config> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| bad(format!("cannot read {}: {e}", path.display())))?;
        Self::parse(&text)
    }

    pub fn validate(&self) -> Result<()> {
        if self.listen.is_empty() {
            return Err(bad("listen: at least one address"));
        }
        for a in &self.listen {
            a.parse::<SocketAddr>()
                .map_err(|_| bad(format!("listen: invalid address {a:?} (expected ip:port)")))?;
        }
        if !(1..=MAX_POW_BITS).contains(&self.pow_bits) {
            return Err(bad(format!(
                "pow_bits = {} outside 1..={MAX_POW_BITS}",
                self.pow_bits
            )));
        }
        if [
            self.max_connections,
            self.max_connections_per_ip,
            self.max_connections_per_ipv6_56,
            self.max_connections_per_ipv6_48,
            self.max_connections_per_ipv4_24,
        ]
        .contains(&0)
        {
            return Err(bad("max_connections and max_connections_per_*: at least 1"));
        }
        if self.storage_max_bytes == 0 {
            return Err(bad("storage_max_bytes: at least 1"));
        }
        if self.max_response_bytes_per_ip < MIN_RESPONSE_BYTES_PER_IP {
            return Err(bad("max_response_bytes_per_ip: at least 1 MiB (one page)"));
        }
        if self.max_response_bytes_in_flight < server::FETCH_PAGE_BYTES + (64 << 10) {
            return Err(bad("max_response_bytes_in_flight: at least 1 MiB"));
        }
        if self.max_db_jobs_per_prefix == Some(0) {
            return Err(bad("max_db_jobs_per_prefix: at least 1"));
        }
        if let Some(d) = &self.dht {
            check_dht_listen(d, &self.listen)?;
        }
        if self.max_db_jobs == 0 || self.min_send_rate == 0 || self.log_interval_secs == 0 {
            return Err(bad(
                "max_db_jobs, min_send_rate and log_interval_secs: at least 1",
            ));
        }
        Ok(())
    }

    pub fn policy(&self) -> Policy {
        Policy {
            pow_bits: self.pow_bits,
            storage_max_bytes: self.storage_max_bytes,
            ..Policy::default()
        }
    }

    /// Binds the listen addresses. The error message does not echo the address.
    pub fn bind(&self) -> Result<Vec<UdpSocket>> {
        self.listen
            .iter()
            .map(|a| {
                let addr: SocketAddr = a.parse().map_err(|_| bad("listen: invalid address"))?;
                UdpSocket::bind(addr)
                    .map_err(|e| bad(format!("cannot listen on a `listen` address: {e}")))
            })
            .collect()
    }

    pub fn server_config(&self, sockets: Vec<UdpSocket>, key: SigningKey) -> ServerConfig {
        let mut cfg = ServerConfig::new(sockets, key);
        cfg.limits = LimitConfig {
            max_connections: self.max_connections,
            max_connections_per_ip: self.max_connections_per_ip,
            max_connections_per_ipv6_56: self.max_connections_per_ipv6_56,
            max_connections_per_ipv6_48: self.max_connections_per_ipv6_48,
            max_connections_per_ipv4_24: self.max_connections_per_ipv4_24,
            ..LimitConfig::default()
        };
        cfg.max_response_bytes_in_flight = self.max_response_bytes_in_flight;
        cfg.max_response_bytes_per_ip = self.max_response_bytes_per_ip;
        cfg.max_db_jobs = self.max_db_jobs;
        cfg.max_db_jobs_per_prefix = self.max_db_jobs_per_prefix;
        cfg.min_send_rate = self.min_send_rate;
        cfg.dht = self.dht.clone();
        cfg
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_spec_and_validate() {
        let c = Config::parse("").unwrap();
        assert_eq!(c, Config::default());
        assert_eq!(c.pow_bits, 18);
        assert_eq!(c.max_connections, 1_000);
        assert_eq!(c.max_connections_per_ip, 8);
        assert_eq!(c.max_connections_per_ipv6_56, 32);
        assert_eq!(c.max_connections_per_ipv6_48, 64);
        assert_eq!(c.max_connections_per_ipv4_24, 32);
        assert_eq!(c.storage_max_bytes, 1 << 30);
        assert_eq!(c.max_response_bytes_in_flight, 64 << 20);
        assert_eq!(c.max_response_bytes_per_ip, 4 << 20);
        assert_eq!(c.max_db_jobs, 64);
        assert_eq!(c.min_send_rate, 32 * 1024);
    }

    #[test]
    fn unknown_key_is_rejected() {
        let e = Config::parse("pow_bits = 18\nlisten_adress = []\n").unwrap_err();
        assert!(e.to_string().contains("listen_adress"), "{e}");
    }

    #[test]
    fn config_parses_dht_section() {
        assert!(Config::parse("").unwrap().dht.is_none());
        let id = barking_proto::NodeId([7; 32]);
        let c = Config::parse(&format!(
            "[dht]\npublic_addr = [\"1.2.3.4:4433\", \"[2a01::1]:4433\"]\nbootstrap = [\"{id}@5.6.7.8:4433\"]\n"
        ))
        .unwrap();
        let d = c.dht.clone().unwrap();
        assert_eq!(d.public_v4, Some("1.2.3.4:4433".parse().unwrap()));
        assert_eq!(d.public_v6, Some("[2a01::1]:4433".parse().unwrap()));
        assert_eq!(d.bootstrap.len(), 1);
        assert_eq!(d.bootstrap[0].id, id);
        assert!(!d.allow_private_addrs);
        assert_eq!(d.replication_bytes_per_hour, 512 << 20);
        let sc = c.server_config(vec![], SigningKey::from_bytes(&[1; 32]));
        assert_eq!(sc.dht, Some(d));
        // A single family is enough; private addresses allowed on request.
        let c = Config::parse(
            "[dht]\npublic_addr = [\"127.0.0.1:4433\"]\nallow_private_addrs = true\nreplication_bytes_per_hour = 1024\n",
        )
        .unwrap();
        let d = c.dht.unwrap();
        assert_eq!((d.public_v4.is_some(), d.public_v6.is_none()), (true, true));
        assert_eq!(d.replication_bytes_per_hour, 1024);
        // Without a public address: table disabled, no error.
        for off in ["[dht]\npublic_addr = []", "[dht]\nbootstrap = []"] {
            let c = Config::parse(off).unwrap_or_else(|e| panic!("{off}: {e}"));
            assert!(c.dht.is_none() && c.dht_without_public_addr, "{off}");
        }
        assert!(!Config::parse("").unwrap().dht_without_public_addr);
        // Listen address serving the published family: direct IPv4, or `[::]`.
        for ok in [
            "listen = [\"0.0.0.0:4433\"]\n[dht]\npublic_addr = [\"1.2.3.4:4433\"]",
            "listen = [\"[::]:4433\"]\n[dht]\npublic_addr = [\"1.2.3.4:4433\", \"[2a01::1]:4433\"]",
            "listen = [\"0.0.0.0:4433\", \"[2a01::1]:4433\"]\n[dht]\npublic_addr = [\"[2a01::1]:4433\"]",
        ] {
            Config::parse(ok).unwrap_or_else(|e| panic!("{ok}: {e}"));
        }
        for bad in [
            // Two addresses of the same family.
            "[dht]\npublic_addr = [\"1.2.3.4:4433\", \"5.6.7.8:4433\"]",
            "[dht]\npublic_addr = [\"[2a01::1]:4433\", \"[2a01::2]:4433\"]",
            // Malformed bootstrap entry.
            "[dht]\npublic_addr = [\"1.2.3.4:4433\"]\nbootstrap = [\"1.2.3.4:4433\"]",
            // Unparsable address.
            "[dht]\npublic_addr = [\"1.2.3.4\"]",
            // Non-routable address without `allow_private_addrs`.
            "[dht]\npublic_addr = [\"192.168.1.2:4433\"]",
            "[dht]\npublic_addr = [\"1.2.3.4:0\"]",
            "[dht]\npublic_addr = [\"1.2.3.4:4433\"]\ninconnue = 1",
            // Zero replication cap.
            "[dht]\npublic_addr = [\"1.2.3.4:4433\"]\nreplication_bytes_per_hour = 0",
            // IPv4 written as IPv6.
            "[dht]\npublic_addr = [\"[::ffff:1.2.3.4]:4433\"]\nallow_private_addrs = true",
            // Published family without a listen address serving it.
            "listen = [\"[::1]:4433\"]\n[dht]\npublic_addr = [\"1.2.3.4:4433\"]",
            "listen = [\"0.0.0.0:4433\"]\n[dht]\npublic_addr = [\"[2a01::1]:4433\"]",
        ] {
            assert!(Config::parse(bad).is_err(), "{bad} must be rejected");
        }
    }

    #[test]
    fn deploy_example_parses_with_dht_section() {
        let text = include_str!("../../../docs/deploy/barking-node.toml");
        assert!(Config::parse(text).unwrap().dht.is_none());
        // `[dht]` section uncommented (without the empty bootstrap example).
        let on: String = text
            .lines()
            .map(|l| match l.strip_prefix("# ") {
                Some(r) if r == "[dht]" || r.starts_with("public_addr") => r,
                Some(r) if r.starts_with("replication_bytes_per_hour") => r,
                _ => l,
            })
            .collect::<Vec<_>>()
            .join("\n")
            // Documentation addresses, non-routable: replaced.
            .replace("203.0.113.7", "1.2.3.4")
            .replace("2001:db8::7", "2a01::7");
        let d = Config::parse(&on).unwrap().dht.unwrap();
        assert_eq!(d.replication_bytes_per_hour, 128 << 20);
        assert!(d.public_v4.is_some() && d.public_v6.is_some());
    }

    #[test]
    fn bounds_are_enforced() {
        for bad in [
            "pow_bits = 0",
            "pow_bits = 25",
            "max_response_bytes_per_ip = 1048575",
            "max_response_bytes_in_flight = 1000",
            "max_connections = 0",
            "max_connections_per_ip = 0",
            "max_connections_per_ipv6_56 = 0",
            "max_connections_per_ipv6_48 = 0",
            "max_connections_per_ipv4_24 = 0",
            "max_db_jobs = 0",
            "max_db_jobs_per_prefix = 0",
            "min_send_rate = 0",
            "log_interval_secs = 0",
            "storage_max_bytes = 0",
            "listen = []",
            "listen = [\"not an address\"]",
        ] {
            assert!(Config::parse(bad).is_err(), "{bad} must be rejected");
        }
        for ok in [
            "pow_bits = 1",
            "pow_bits = 24",
            "max_connections_per_ipv6_48 = 128",
            "max_db_jobs_per_prefix = 4",
            "max_response_bytes_per_ip = 1048576",
            "listen = [\"127.0.0.1:1\", \"[::1]:1\"]",
        ] {
            Config::parse(ok).unwrap_or_else(|e| panic!("{ok}: {e}"));
        }
    }
}
