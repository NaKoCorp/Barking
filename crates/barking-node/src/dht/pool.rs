//! Outgoing connections to peers (spec §3.3): started from the server's
//! endpoints (same UDP port), with the node's certificate (built once,
//! `tls::NodeIdentity`), reused, at most `MAX_OUTBOUND`. Beyond that, the
//! least recently used is dropped; QUIC closes it when its last users have
//! finished.
//!
//! A connection is stored under (identifier, address): the address called
//! is the connection's, which the verification of a record's addresses
//! requires (each address must answer itself).
//!
//! An address family is reachable only if the node **publishes** an address
//! of that family and has an endpoint that can send to it: a `[::]` socket
//! does not prove an IPv6 route (rule R17). Addresses of an unreachable
//! family are never called.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};

use barking_proto::client::{self, ClientError, Result};
use barking_proto::{NodeId, Request, Response, tls};
use ed25519_dalek::SigningKey;
use quinn::{Connection, Endpoint};

/// At most this many outgoing connections kept.
pub const MAX_OUTBOUND: usize = 64;

struct Entry {
    conn: Connection,
    /// Base difficulty announced by the peer in `Hello`.
    pow_bits: u8,
    /// Usage time (increasing counter) for eviction.
    used: u64,
}

#[derive(Default)]
struct Conns {
    map: HashMap<(NodeId, SocketAddr), Entry>,
    clock: u64,
}

struct Inner {
    identity: tls::NodeIdentity,
    endpoints: Vec<Endpoint>,
    /// Families published in our record: IPv4, IPv6.
    v4: bool,
    v6: bool,
    conns: Mutex<Conns>,
}

/// Pool of outgoing connections, shared by cloning.
#[derive(Clone)]
pub struct PeerPool {
    inner: Arc<Inner>,
}

impl PeerPool {
    /// `v4`, `v6`: families for which the node publishes an address.
    pub fn new(key: SigningKey, endpoints: Vec<Endpoint>, v4: bool, v6: bool) -> PeerPool {
        PeerPool {
            inner: Arc::new(Inner {
                identity: tls::NodeIdentity::new(&key),
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

    /// Connection still open to `id` at one of `addrs`, marked as used;
    /// closed connections encountered are forgotten.
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

    fn insert(&self, id: NodeId, addr: SocketAddr, conn: Connection, pow_bits: u8) {
        let mut c = self.conns();
        c.clock += 1;
        let used = c.clock;
        let key = (id, addr);
        if !c.map.contains_key(&key) && c.map.len() >= MAX_OUTBOUND {
            // Closed ones first, otherwise the least recently used.
            c.map.retain(|_, e| e.conn.close_reason().is_none());
            if c.map.len() >= MAX_OUTBOUND
                && let Some(old) = c.map.iter().min_by_key(|(_, e)| e.used).map(|(k, _)| *k)
            {
                c.map.remove(&old);
            }
        }
        c.map.insert(
            key,
            Entry {
                conn,
                pow_bits,
                used,
            },
        );
    }

    fn forget(&self, id: NodeId, conn: &Connection) {
        let mut c = self.conns();
        c.map
            .retain(|(i, _), e| !(*i == id && e.conn.stable_id() == conn.stable_id()));
    }

    /// Endpoint to call `addr` from: of the same family, or an IPv6
    /// (dual-stack) endpoint for an IPv4 address. `None` if we do not
    /// publish an address of that family.
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

    /// Base difficulty announced by `id` on a kept connection to one of
    /// `addrs`.
    pub fn pow_bits(&self, id: NodeId, addrs: &[SocketAddr]) -> Option<u8> {
        let c = self.conns();
        addrs
            .iter()
            .find_map(|a| c.map.get(&(id, *a)))
            .map(|e| e.pow_bits)
    }

    /// True if the family of `addr` is reachable from here: published in
    /// our record, with an endpoint that can send to it.
    pub fn can_reach(&self, addr: &SocketAddr) -> bool {
        self.endpoint_for(addr).is_some()
    }

    /// Connection to node `id`: a kept connection to one of `addrs`,
    /// otherwise a new one, tried on `addrs` in order (identity pinned to
    /// `id`, node certificate, `Hello`).
    pub async fn get(&self, id: NodeId, addrs: &[SocketAddr]) -> Result<Connection> {
        if let Some(c) = self.cached(id, addrs) {
            return Ok(c);
        }
        let mut last = ClientError::Connect("no reachable address".into());
        for a in addrs {
            let Some(ep) = self.endpoint_for(a) else {
                continue;
            };
            match client::connect_node(ep, *a, id, &self.inner.identity).await {
                Ok((c, pow_bits)) => {
                    self.insert(id, *a, c.clone(), pow_bits);
                    return Ok(c);
                }
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// Sends `req` to node `id`. A kept connection that turns out to be
    /// closed (closed by the peer for inactivity, for example) is replaced
    /// once by a new one.
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
            eprintln!("[::] unavailable: test skipped");
            return;
        };
        let key = SigningKey::from_bytes(&[1; 32]);
        let v4: SocketAddr = "192.0.2.1:4433".parse().unwrap();
        let v6: SocketAddr = "[2001:db8::1]:4433".parse().unwrap();
        // Dual-stack `[::]` socket, only IPv4 published: IPv6 is not
        // reachable, IPv4 goes through the IPv6 endpoint.
        let p = PeerPool::new(key.clone(), vec![ep.clone()], true, false);
        assert!(p.can_reach(&v4));
        assert!(!p.can_reach(&v6));
        // And the reverse.
        let p = PeerPool::new(key.clone(), vec![ep.clone()], false, true);
        assert!(!p.can_reach(&v4));
        assert!(p.can_reach(&v6));
        // Family published without an endpoint for it.
        let ep4 = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let p = PeerPool::new(key, vec![ep4], true, true);
        assert!(p.can_reach(&v4));
        assert!(!p.can_reach(&v6));
    }
}
