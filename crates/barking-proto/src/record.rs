//! Fiche de nœud signée : clé publique, adresses publiques et date
//! d'émission arrondie à l'heure, le tout signé par la clé du nœud. Seules
//! ces fiches circulent entre nœuds et sont écrites sur disque.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::node_id::{NODE_PUZZLE_BITS, NodeId};

/// Contexte de la signature d'une fiche.
pub const RECORD_CONTEXT: &[u8] = b"barking/v0/node-record";
/// Avance tolérée au plus sur `issued_at`, en secondes.
pub const MAX_RECORD_SKEW_SECS: u64 = 3600;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeRecord {
    pub public_key: [u8; 32],
    pub v4: Option<SocketAddrV4>,
    pub v6: Option<SocketAddrV6>,
    pub issued_at: u64,
    pub signature: Signature,
}

/// Règles de validation d'une fiche.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordPolicy {
    /// Accepte les adresses non routables (réseaux privés, tests).
    pub allow_private: bool,
    /// Difficulté du puzzle d'identifiant exigée.
    pub puzzle_bits: u32,
}

impl RecordPolicy {
    /// Politique du réseau : puzzle complet.
    pub fn network(allow_private: bool) -> RecordPolicy {
        RecordPolicy {
            allow_private,
            puzzle_bits: NODE_PUZZLE_BITS,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RecordError {
    #[error("clé publique invalide")]
    BadKey,
    #[error("signature invalide")]
    BadSignature,
    #[error("le puzzle d'identifiant n'est pas résolu")]
    Puzzle,
    #[error("fiche émise dans le futur")]
    FromFuture,
    #[error("fiche sans adresse")]
    NoAddress,
    #[error("adresse non routable")]
    Unroutable,
}

/// Octets signés : contexte, puis `postcard(public_key, v4, v6, issued_at)`.
fn signed_bytes(
    public_key: &[u8; 32],
    v4: &Option<SocketAddrV4>,
    v6: &Option<SocketAddrV6>,
    issued_at: u64,
) -> Vec<u8> {
    let mut out = RECORD_CONTEXT.to_vec();
    out.extend(
        postcard::to_allocvec(&(public_key, v4, v6, issued_at))
            .expect("la sérialisation en mémoire ne échoue pas"),
    );
    out
}

impl NodeRecord {
    /// Signe une fiche ; `now` est arrondi à l'heure inférieure.
    pub fn sign(
        key: &SigningKey,
        v4: Option<SocketAddrV4>,
        v6: Option<SocketAddrV6>,
        now: u64,
    ) -> NodeRecord {
        Self::sign_at(key, v4, v6, now - now % 3600)
    }

    fn sign_at(
        key: &SigningKey,
        v4: Option<SocketAddrV4>,
        v6: Option<SocketAddrV6>,
        issued_at: u64,
    ) -> NodeRecord {
        let public_key = key.verifying_key().to_bytes();
        let signature = key.sign(&signed_bytes(&public_key, &v4, &v6, issued_at));
        NodeRecord {
            public_key,
            v4,
            v6,
            issued_at,
            signature,
        }
    }

    /// Adresses de la fiche, v4 d'abord.
    pub fn addrs(&self) -> Vec<SocketAddr> {
        let mut out = Vec::with_capacity(2);
        if let Some(a) = self.v4 {
            out.push(SocketAddr::V4(a));
        }
        if let Some(a) = self.v6 {
            out.push(SocketAddr::V6(a));
        }
        out
    }

    /// Vérifie clé, signature, puzzle, date et adresses ; renvoie
    /// l'identifiant du nœud.
    pub fn verify(&self, now: u64, policy: &RecordPolicy) -> Result<NodeId, RecordError> {
        let key = VerifyingKey::from_bytes(&self.public_key).map_err(|_| RecordError::BadKey)?;
        let msg = signed_bytes(&self.public_key, &self.v4, &self.v6, self.issued_at);
        key.verify_strict(&msg, &self.signature)
            .map_err(|_| RecordError::BadSignature)?;
        let id = NodeId::from_public_key(&key);
        if !id.puzzle_ok_bits(policy.puzzle_bits) {
            return Err(RecordError::Puzzle);
        }
        if self.issued_at > now.saturating_add(MAX_RECORD_SKEW_SECS) {
            return Err(RecordError::FromFuture);
        }
        let addrs = self.addrs();
        if addrs.is_empty() {
            return Err(RecordError::NoAddress);
        }
        if !policy.allow_private && !addrs.iter().all(routable) {
            return Err(RecordError::Unroutable);
        }
        // Une IPv4 déguisée en IPv6 compterait dans le bloc `::/48` au lieu
        // de son /24 : refusée même sous `allow_private`.
        if self.v6.is_some_and(|a| embeds_ipv4(a.ip())) {
            return Err(RecordError::Unroutable);
        }
        Ok(id)
    }
}

/// Vrai si `ip` porte une IPv4 : `::ffff:0:0/96` (IPv4 encapsulée) ou
/// `::/96` (IPv4 compatible, obsolète, adresse non spécifiée comprise).
/// `::1` (boucle locale) n'en est pas.
pub fn embeds_ipv4(ip: &Ipv6Addr) -> bool {
    let s = ip.segments();
    s[..5] == [0; 5] && (s[5] == 0xffff || (s[5] == 0 && !ip.is_loopback()))
}

fn routable_v4(ip: &Ipv4Addr) -> bool {
    let o = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_documentation()
        // 0.0.0.0/8 : ce réseau.
        || o[0] == 0
        // 100.64.0.0/10 : espace partagé des opérateurs.
        || (o[0] == 100 && (o[1] & 0xc0) == 64)
        // 240.0.0.0/4 : réservé.
        || o[0] >= 240)
}

fn routable_v6(ip: &Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return routable_v4(&v4);
    }
    let s = ip.segments();
    !(ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        // fe80::/10 lien local, fec0::/10 site local (obsolète).
        || (s[0] & 0xffc0) == 0xfe80
        || (s[0] & 0xffc0) == 0xfec0
        // fc00::/7 adresses locales uniques.
        || (s[0] & 0xfe00) == 0xfc00
        // 2001:db8::/32 documentation.
        || (s[0] == 0x2001 && s[1] == 0x0db8))
}

/// Vrai si l'adresse est joignable depuis Internet (ni privée, ni locale,
/// ni de documentation, port non nul).
pub fn routable(addr: &SocketAddr) -> bool {
    addr.port() != 0
        && match addr.ip() {
            std::net::IpAddr::V4(ip) => routable_v4(&ip),
            std::net::IpAddr::V6(ip) => routable_v6(&ip),
        }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    use crate::node_id::generate_node_key;

    const NOW: u64 = 1_000_000;

    fn v4(s: &str) -> Option<SocketAddrV4> {
        Some(s.parse().unwrap())
    }

    fn lax() -> RecordPolicy {
        RecordPolicy {
            allow_private: false,
            puzzle_bits: 0,
        }
    }

    fn any_key() -> SigningKey {
        SigningKey::from_bytes(&[7; 32])
    }

    #[test]
    fn signed_record_verifies() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(11);
        let key = generate_node_key(&mut rng);
        let rec = NodeRecord::sign(&key, v4("1.2.3.4:4433"), None, NOW);
        let id = rec.verify(NOW, &RecordPolicy::network(false)).unwrap();
        assert_eq!(id, NodeId::from_public_key(&key.verifying_key()));
        assert_eq!(rec.addrs(), vec!["1.2.3.4:4433".parse().unwrap()]);
    }

    #[test]
    fn issued_at_is_rounded_to_hour() {
        let rec = NodeRecord::sign(&any_key(), v4("1.2.3.4:4433"), None, 7_205);
        assert_eq!(rec.issued_at, 7_200);
    }

    #[test]
    fn tampered_record_is_refused() {
        let rec = NodeRecord::sign(&any_key(), v4("1.2.3.4:4433"), None, NOW);
        let mut moved = rec.clone();
        moved.v4 = v4("1.2.3.4:4434");
        assert_eq!(moved.verify(NOW, &lax()), Err(RecordError::BadSignature));
        let mut dated = rec;
        dated.issued_at += 3600;
        assert_eq!(dated.verify(NOW, &lax()), Err(RecordError::BadSignature));
    }

    #[test]
    fn future_record_is_refused() {
        let key = any_key();
        let late = NodeRecord::sign_at(&key, v4("1.2.3.4:4433"), None, NOW + 3_601);
        assert_eq!(late.verify(NOW, &lax()), Err(RecordError::FromFuture));
        let edge = NodeRecord::sign_at(&key, v4("1.2.3.4:4433"), None, NOW + 3_600);
        assert!(edge.verify(NOW, &lax()).is_ok());
    }

    #[test]
    fn bad_puzzle_is_refused() {
        let rec = NodeRecord::sign(&any_key(), v4("1.2.3.4:4433"), None, NOW);
        assert_eq!(
            rec.verify(NOW, &RecordPolicy::network(false)),
            Err(RecordError::Puzzle)
        );
        assert!(rec.verify(NOW, &lax()).is_ok());
    }

    #[test]
    fn no_address_is_refused() {
        let rec = NodeRecord::sign(&any_key(), None, None, NOW);
        assert_eq!(rec.verify(NOW, &lax()), Err(RecordError::NoAddress));
    }

    #[test]
    fn bad_key_is_refused() {
        let mut rec = NodeRecord::sign(&any_key(), v4("1.2.3.4:4433"), None, NOW);
        // y = 2 n'est pas un point de la courbe.
        rec.public_key = [0; 32];
        rec.public_key[0] = 2;
        assert_eq!(rec.verify(NOW, &lax()), Err(RecordError::BadKey));
    }

    #[test]
    fn unroutable_addresses() {
        for s in [
            "10.0.0.1:1",
            "127.0.0.1:1",
            "169.254.1.1:1",
            "192.168.1.1:1",
            "0.0.0.0:1",
            "224.0.0.1:1",
            "192.0.2.1:1",
            "198.51.100.1:1",
            "203.0.113.1:1",
            "100.64.0.1:1",
            "1.2.3.4:0",
            "[::1]:1",
            "[fe80::1]:1",
            "[fc00::1]:1",
            "[ff02::1]:1",
            "[2001:db8::1]:1",
        ] {
            assert!(!routable(&s.parse().unwrap()), "{s}");
        }
        for s in ["1.2.3.4:4433", "[2a01:4f8::1]:4433"] {
            assert!(routable(&s.parse().unwrap()), "{s}");
        }
        let key = any_key();
        let rec = NodeRecord::sign(&key, v4("10.0.0.1:4433"), None, NOW);
        assert_eq!(rec.verify(NOW, &lax()), Err(RecordError::Unroutable));
        let private_ok = RecordPolicy {
            allow_private: true,
            puzzle_bits: 0,
        };
        assert!(rec.verify(NOW, &private_ok).is_ok());
    }

    #[test]
    fn ipv4_in_ipv6_is_refused_even_when_private_allowed() {
        let private_ok = RecordPolicy {
            allow_private: true,
            puzzle_bits: 0,
        };
        for bad in ["[::ffff:1.2.3.4]:4433", "[::1.2.3.4]:4433", "[::]:4433"] {
            let rec = NodeRecord::sign(&any_key(), None, Some(bad.parse().unwrap()), NOW);
            for p in [lax(), private_ok] {
                assert_eq!(rec.verify(NOW, &p), Err(RecordError::Unroutable), "{bad}");
            }
            // Aussi en second d'une fiche à double pile.
            let rec = NodeRecord::sign(
                &any_key(),
                v4("1.2.3.4:4433"),
                Some(bad.parse().unwrap()),
                NOW,
            );
            assert_eq!(
                rec.verify(NOW, &lax()),
                Err(RecordError::Unroutable),
                "{bad}"
            );
        }
        // Boucle locale permise sous `allow_private`, IPv6 publique partout.
        let rec = NodeRecord::sign(&any_key(), None, Some("[::1]:4433".parse().unwrap()), NOW);
        assert!(rec.verify(NOW, &private_ok).is_ok());
        let rec = NodeRecord::sign(
            &any_key(),
            None,
            Some("[2a01:4f8::1]:4433".parse().unwrap()),
            NOW,
        );
        assert!(rec.verify(NOW, &lax()).is_ok());
        assert!(!embeds_ipv4(&"::1".parse().unwrap()));
        assert!(!embeds_ipv4(&"2a01::ffff:1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn record_postcard_roundtrip() {
        let rec = NodeRecord::sign(
            &any_key(),
            v4("1.2.3.4:4433"),
            Some("[2a01:4f8::1]:4433".parse().unwrap()),
            NOW,
        );
        let bytes = postcard::to_allocvec(&rec).unwrap();
        assert_eq!(postcard::from_bytes::<NodeRecord>(&bytes).unwrap(), rec);
    }
}
