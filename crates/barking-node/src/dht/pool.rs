//! Connexions sortantes vers les pairs (spec §3.3) : parties des endpoints
//! du serveur (même port UDP), avec le certificat du nœud, réutilisées, au
//! plus `MAX_OUTBOUND`. Au-delà, la moins récemment utilisée est lâchée ;
//! QUIC la ferme quand ses derniers utilisateurs ont fini.
//!
//! Une connexion est rangée sous (identifiant, adresse) : l'adresse
//! appelée est celle de la connexion, ce que la vérification des adresses
//! d'une fiche exige (chaque adresse doit répondre elle-même).
//!
//! Une famille d'adresses n'est joignable que si le nœud **publie** une
//! adresse de cette famille et a un endpoint qui peut y envoyer : un socket
//! `[::]` ne prouve pas une route IPv6 (règle R17). Les adresses d'une
//! famille injoignable ne sont jamais appelées.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};

use barking_proto::client::{self, ClientError, Result};
use barking_proto::{NodeId, Request, Response};
use ed25519_dalek::SigningKey;
use quinn::{Connection, Endpoint};

/// Connexions sortantes gardées au plus.
pub const MAX_OUTBOUND: usize = 64;

struct Entry {
    conn: Connection,
    /// Date d'usage (compteur croissant) pour l'éviction.
    used: u64,
}

#[derive(Default)]
struct Conns {
    map: HashMap<(NodeId, SocketAddr), Entry>,
    clock: u64,
}

struct Inner {
    key: SigningKey,
    endpoints: Vec<Endpoint>,
    /// Familles publiées dans notre fiche : IPv4, IPv6.
    v4: bool,
    v6: bool,
    conns: Mutex<Conns>,
}

/// Réserve de connexions sortantes, partagée par clonage.
#[derive(Clone)]
pub struct PeerPool {
    inner: Arc<Inner>,
}

impl PeerPool {
    /// `v4`, `v6` : familles dont le nœud publie une adresse.
    pub fn new(key: SigningKey, endpoints: Vec<Endpoint>, v4: bool, v6: bool) -> PeerPool {
        PeerPool {
            inner: Arc::new(Inner {
                key,
                endpoints,
                v4,
                v6,
                conns: Mutex::new(Conns::default()),
            }),
        }
    }

    fn conns(&self) -> std::sync::MutexGuard<'_, Conns> {
        self.inner
            .conns
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Connexion encore ouverte vers `id` à l'une de `addrs`, marquée
    /// utilisée ; les connexions fermées rencontrées sont oubliées.
    fn cached(&self, id: NodeId, addrs: &[SocketAddr]) -> Option<Connection> {
        let mut c = self.conns();
        c.clock += 1;
        let now = c.clock;
        for a in addrs {
            let key = (id, *a);
            let Some(e) = c.map.get_mut(&key) else {
                continue;
            };
            if e.conn.close_reason().is_some() {
                c.map.remove(&key);
                continue;
            }
            e.used = now;
            return Some(e.conn.clone());
        }
        None
    }

    fn insert(&self, id: NodeId, addr: SocketAddr, conn: Connection) {
        let mut c = self.conns();
        c.clock += 1;
        let used = c.clock;
        let key = (id, addr);
        if !c.map.contains_key(&key) && c.map.len() >= MAX_OUTBOUND {
            // Les fermées d'abord, sinon la moins récemment utilisée.
            c.map.retain(|_, e| e.conn.close_reason().is_none());
            if c.map.len() >= MAX_OUTBOUND
                && let Some(old) = c.map.iter().min_by_key(|(_, e)| e.used).map(|(k, _)| *k)
            {
                c.map.remove(&old);
            }
        }
        c.map.insert(key, Entry { conn, used });
    }

    fn forget(&self, id: NodeId, conn: &Connection) {
        let mut c = self.conns();
        c.map
            .retain(|(i, _), e| !(*i == id && e.conn.stable_id() == conn.stable_id()));
    }

    /// Endpoint d'où appeler `addr` : de la même famille, ou un endpoint
    /// IPv6 (double pile) pour une adresse IPv4. `None` si nous ne publions
    /// pas d'adresse de cette famille.
    fn endpoint_for(&self, addr: &SocketAddr) -> Option<&Endpoint> {
        let published = if addr.is_ipv6() {
            self.inner.v6
        } else {
            self.inner.v4
        };
        if !published {
            return None;
        }
        let family = |ep: &&Endpoint, v6: bool| ep.local_addr().is_ok_and(|l| l.is_ipv6() == v6);
        let eps = &self.inner.endpoints;
        eps.iter()
            .find(|ep| family(ep, addr.is_ipv6()))
            .or_else(|| {
                addr.is_ipv4()
                    .then(|| eps.iter().find(|ep| family(ep, true)))
                    .flatten()
            })
    }

    /// Vrai si la famille de `addr` est joignable d'ici : publiée dans
    /// notre fiche, avec un endpoint qui peut y envoyer.
    pub fn can_reach(&self, addr: &SocketAddr) -> bool {
        self.endpoint_for(addr).is_some()
    }

    /// Connexion vers le nœud `id` : une connexion gardée vers l'une de
    /// `addrs`, sinon une nouvelle, essayée sur `addrs` dans l'ordre
    /// (identité épinglée sur `id`, certificat du nœud, `Hello`).
    pub async fn get(&self, id: NodeId, addrs: &[SocketAddr]) -> Result<Connection> {
        if let Some(c) = self.cached(id, addrs) {
            return Ok(c);
        }
        let mut last = ClientError::Connect("aucune adresse joignable".into());
        for a in addrs {
            let Some(ep) = self.endpoint_for(a) else {
                continue;
            };
            match client::connect_peer(ep, *a, id, &self.inner.key).await {
                Ok(c) => {
                    self.insert(id, *a, c.clone());
                    return Ok(c);
                }
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// Envoie `req` au nœud `id`. Une connexion gardée qui s'avère fermée
    /// (fermée par le pair pour inactivité, par exemple) est remplacée une
    /// fois par une nouvelle.
    pub async fn request(
        &self,
        id: NodeId,
        addrs: &[SocketAddr],
        req: &Request,
    ) -> Result<Response> {
        if let Some(c) = self.cached(id, addrs) {
            match client::request(&c, req).await {
                Err(e) if c.close_reason().is_some() => {
                    self.forget(id, &c);
                    drop(e);
                }
                r => return r,
            }
        }
        let c = self.get(id, addrs).await?;
        client::request(&c, req).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn only_published_families_are_reachable() {
        let Ok(ep) = Endpoint::client("[::]:0".parse().unwrap()) else {
            eprintln!("[::] indisponible : test ignoré");
            return;
        };
        let key = SigningKey::from_bytes(&[1; 32]);
        let v4: SocketAddr = "192.0.2.1:4433".parse().unwrap();
        let v6: SocketAddr = "[2001:db8::1]:4433".parse().unwrap();
        // Socket `[::]` double pile, IPv4 seule publiée : l'IPv6 n'est pas
        // joignable, l'IPv4 passe par l'endpoint IPv6.
        let p = PeerPool::new(key.clone(), vec![ep.clone()], true, false);
        assert!(p.can_reach(&v4));
        assert!(!p.can_reach(&v6));
        // Et l'inverse.
        let p = PeerPool::new(key.clone(), vec![ep.clone()], false, true);
        assert!(!p.can_reach(&v4));
        assert!(p.can_reach(&v6));
        // Famille publiée sans endpoint pour elle.
        let ep4 = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let p = PeerPool::new(key, vec![ep4], true, true);
        assert!(p.can_reach(&v4));
        assert!(!p.can_reach(&v6));
    }
}
