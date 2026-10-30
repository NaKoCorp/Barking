//! Configuration TOML du nœud (spec §8). Les valeurs par défaut sont celles de
//! la spec ; une clé inconnue ou une valeur hors bornes est une erreur.

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

/// Dossier de données par défaut (unité systemd fournie).
pub const DEFAULT_DATA_DIR: &str = "/var/lib/barking-node";
/// Port QUIC par défaut.
pub const DEFAULT_LISTEN: &str = "[::]:4433";
/// Plancher du plafond de réponses par adresse : une page entière (1 Mio).
pub const MIN_RESPONSE_BYTES_PER_IP: usize = 1 << 20;
/// Plafond de recopie sortante par défaut (spec §5.3).
pub const DEFAULT_REPLICATION_BYTES_PER_HOUR: u64 = 512 << 20;

/// Section `[dht]` (spec §8). Sans elle, la table est désactivée : le nœud
/// reste un simple relais et répond `Unsupported` aux requêtes de la table.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "DhtToml")]
pub struct DhtConfig {
    /// Adresses publiées dans la fiche, une par famille au plus.
    pub public_v4: Option<SocketAddrV4>,
    pub public_v6: Option<SocketAddrV6>,
    /// Nœuds essayés après la liste intégrée.
    pub bootstrap: Vec<BootstrapEntry>,
    /// Accepte les adresses non routables (tests, réseaux locaux).
    pub allow_private_addrs: bool,
    /// Octets recopiés au plus par heure.
    pub replication_bytes_per_hour: u64,
}

/// Forme TOML de `[dht]`, avant validation.
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

    /// Les messages d'erreur ne reprennent ni les adresses ni les entrées.
    fn try_from(t: DhtToml) -> core::result::Result<DhtConfig, String> {
        let mut cfg = DhtConfig {
            public_v4: None,
            public_v6: None,
            bootstrap: Vec::with_capacity(t.bootstrap.len()),
            allow_private_addrs: t.allow_private_addrs,
            replication_bytes_per_hour: t.replication_bytes_per_hour,
        };
        if t.public_addr.is_empty() {
            return Err(
                "dht.public_addr : une ou deux adresses (IPv4 et/ou IPv6) ; \
                        sans table, retirer la section [dht]"
                    .into(),
            );
        }
        for a in &t.public_addr {
            let addr: SocketAddr = a
                .parse()
                .map_err(|_| "dht.public_addr : adresse invalide (attendu ip:port)".to_string())?;
            if !t.allow_private_addrs && !routable(&addr) {
                return Err(
                    "dht.public_addr : adresse non routable (allow_private_addrs = false)".into(),
                );
            }
            let twice = match addr {
                SocketAddr::V4(v4) => cfg.public_v4.replace(v4).is_some(),
                SocketAddr::V6(v6) => cfg.public_v6.replace(v6).is_some(),
            };
            if twice {
                return Err("dht.public_addr : une adresse par famille au plus".into());
            }
        }
        for e in &t.bootstrap {
            cfg.bootstrap
                .push(parse_bootstrap(e).map_err(|e| format!("dht.bootstrap : {e}"))?);
        }
        Ok(cfg)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Adresses d'écoute UDP. `[::]` accepte aussi l'IPv4 sous Linux
    /// (`net.ipv6.bindv6only=0`) ; sinon, lister les deux familles.
    pub listen: Vec<String>,
    pub data_dir: PathBuf,
    /// Plafond d'octets stockés (paquets + accusés).
    pub storage_max_bytes: u64,
    /// Difficulté de base de la preuve de travail, 1 à 24 bits.
    pub pow_bits: u8,
    pub max_connections: u32,
    /// Par adresse IPv4 (/32) ou préfixe IPv6 /64.
    pub max_connections_per_ip: u32,
    pub max_connections_per_ipv6_56: u32,
    pub max_connections_per_ipv6_48: u32,
    pub max_connections_per_ipv4_24: u32,
    /// Octets de réponses en vol, tous pairs confondus (mémoire réelle :
    /// environ le double).
    pub max_response_bytes_in_flight: usize,
    /// Octets de réponses en vol par adresse (/64 en IPv6), au moins 1 Mio.
    pub max_response_bytes_per_ip: usize,
    /// Opérations de base simultanées ou en attente.
    pub max_db_jobs: usize,
    /// Part d'un /48 (IPv6) ou /24 (IPv4) ; absent : `max_db_jobs / 8`.
    pub max_db_jobs_per_prefix: Option<usize>,
    /// Débit minimal attendu d'un lecteur, en octets/s (allonge l'échéance
    /// d'écriture d'une réponse, au plus 60 s).
    pub min_send_rate: u64,
    /// Période des journaux agrégés, en secondes.
    pub log_interval_secs: u64,
    /// Table de hachage entre nœuds ; absente : désactivée.
    pub dht: Option<DhtConfig>,
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
        }
    }
}

fn bad(msg: impl Into<String>) -> Error {
    Error::Config(msg.into())
}

impl Config {
    /// Lit et valide un texte TOML.
    pub fn parse(text: &str) -> Result<Config> {
        let cfg: Config = toml::from_str(text).map_err(|e| bad(e.to_string()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn load(path: &Path) -> Result<Config> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| bad(format!("lecture de {} impossible : {e}", path.display())))?;
        Self::parse(&text)
    }

    pub fn validate(&self) -> Result<()> {
        if self.listen.is_empty() {
            return Err(bad("listen : au moins une adresse"));
        }
        for a in &self.listen {
            a.parse::<SocketAddr>()
                .map_err(|_| bad(format!("listen : adresse invalide {a:?} (attendu ip:port)")))?;
        }
        if !(1..=MAX_POW_BITS).contains(&self.pow_bits) {
            return Err(bad(format!(
                "pow_bits = {} hors de 1..={MAX_POW_BITS}",
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
            return Err(bad("max_connections et max_connections_per_* : au moins 1"));
        }
        if self.storage_max_bytes == 0 {
            return Err(bad("storage_max_bytes : au moins 1"));
        }
        if self.max_response_bytes_per_ip < MIN_RESPONSE_BYTES_PER_IP {
            return Err(bad("max_response_bytes_per_ip : au moins 1 Mio (une page)"));
        }
        if self.max_response_bytes_in_flight < server::FETCH_PAGE_BYTES + (64 << 10) {
            return Err(bad("max_response_bytes_in_flight : au moins 1 Mio"));
        }
        if self.max_db_jobs_per_prefix == Some(0) {
            return Err(bad("max_db_jobs_per_prefix : au moins 1"));
        }
        if self.max_db_jobs == 0 || self.min_send_rate == 0 || self.log_interval_secs == 0 {
            return Err(bad(
                "max_db_jobs, min_send_rate et log_interval_secs : au moins 1",
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

    /// Lie les adresses d'écoute. Le message d'erreur ne reprend pas l'adresse.
    pub fn bind(&self) -> Result<Vec<UdpSocket>> {
        self.listen
            .iter()
            .map(|a| {
                let addr: SocketAddr = a.parse().map_err(|_| bad("listen : adresse invalide"))?;
                UdpSocket::bind(addr)
                    .map_err(|e| bad(format!("écoute impossible sur une adresse de listen : {e}")))
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
        // Une seule famille suffit ; adresses privées permises sur demande.
        let c = Config::parse(
            "[dht]\npublic_addr = [\"127.0.0.1:4433\"]\nallow_private_addrs = true\nreplication_bytes_per_hour = 1024\n",
        )
        .unwrap();
        let d = c.dht.unwrap();
        assert_eq!((d.public_v4.is_some(), d.public_v6.is_none()), (true, true));
        assert_eq!(d.replication_bytes_per_hour, 1024);
        for bad in [
            // Deux adresses de la même famille.
            "[dht]\npublic_addr = [\"1.2.3.4:4433\", \"5.6.7.8:4433\"]",
            "[dht]\npublic_addr = [\"[2a01::1]:4433\", \"[2a01::2]:4433\"]",
            // Entrée d'amorçage mal formée.
            "[dht]\npublic_addr = [\"1.2.3.4:4433\"]\nbootstrap = [\"1.2.3.4:4433\"]",
            // Sans adresse publique, ou adresse illisible.
            "[dht]\npublic_addr = []",
            "[dht]\nbootstrap = []",
            "[dht]\npublic_addr = [\"1.2.3.4\"]",
            // Adresse non routable sans `allow_private_addrs`.
            "[dht]\npublic_addr = [\"192.168.1.2:4433\"]",
            "[dht]\npublic_addr = [\"1.2.3.4:0\"]",
            "[dht]\npublic_addr = [\"1.2.3.4:4433\"]\ninconnue = 1",
        ] {
            assert!(Config::parse(bad).is_err(), "{bad} doit être refusé");
        }
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
            "listen = [\"pas une adresse\"]",
        ] {
            assert!(Config::parse(bad).is_err(), "{bad} doit être refusé");
        }
        for ok in [
            "pow_bits = 1",
            "pow_bits = 24",
            "max_connections_per_ipv6_48 = 128",
            "max_db_jobs_per_prefix = 4",
            "max_response_bytes_per_ip = 1048576",
            "listen = [\"127.0.0.1:1\", \"[::1]:1\"]",
        ] {
            Config::parse(ok).unwrap_or_else(|e| panic!("{ok} : {e}"));
        }
    }
}
