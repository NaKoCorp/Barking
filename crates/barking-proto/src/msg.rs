//! Requêtes et réponses client↔nœud. Les nouvelles variantes vont toujours
//! à la fin (le codage postcard numérote les variantes).

use barking_packet::MailboxId;
use serde::{Deserialize, Serialize};

use crate::{node_id::NodeId, record::NodeRecord};

/// Curseurs de relève : les paquets d'abord (curseur = leur numéro d'ordre,
/// sous cette base), puis les accusés (`ACK_CURSOR_BASE + numéro`).
pub const ACK_CURSOR_BASE: u64 = 1 << 62;

/// Plus petite page de relève servie par un nœud (octets de paquets).
pub const MIN_PAGE_BYTES: u32 = 16 * 1024;

/// Fiches au plus dans une réponse `Nodes`.
pub const MAX_NODES_PER_RESPONSE: usize = 20;

/// Empreintes au plus dans une page `Holdings`.
pub const MAX_HOLDINGS_PER_PAGE: usize = 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    Hello {
        version: u16,
        min_version: u16,
    },
    Deposit {
        packet: Vec<u8>,
        pow: u64,
    },
    Fetch {
        mailboxes: Vec<MailboxId>,
        cursor: Option<u64>,
        /// Taille de page souhaitée en octets de paquets ; le nœud la borne
        /// entre `MIN_PAGE_BYTES` et sa propre limite (un élément plus gros
        /// que la page est envoyé seul).
        max_bytes: u32,
    },
    /// Table de hachage entre nœuds. `from` est la fiche de l'appelant s'il
    /// est un nœud.
    Ping {
        from: Option<NodeRecord>,
    },
    FindNode {
        target: [u8; 32],
        from: Option<NodeRecord>,
    },
    /// Dépôt d'un paquet recopié entre responsables.
    Store {
        packet: Vec<u8>,
        pow: u64,
    },
    /// Empreintes des paquets détenus pour une boîte, par pages.
    FindValue {
        mailbox: MailboxId,
        cursor: Option<u64>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    pub max_mailboxes_per_fetch: u16,
    pub max_request_bytes: u32,
    pub max_response_bytes: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Response {
    Hello {
        version: u16,
        min_version: u16,
        node_id: NodeId,
        pow_bits: u8,
        limits: Limits,
    },
    Ok,
    Items {
        items: Vec<Vec<u8>>,
        next: Option<u64>,
    },
    Error(ErrorReason),
    Pong {
        record: NodeRecord,
    },
    Nodes {
        records: Vec<NodeRecord>,
    },
    Holdings {
        hashes: Vec<[u8; 32]>,
        next: Option<u64>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorReason {
    VersionTooOld,
    Malformed,
    Expired,
    TooFarInFuture,
    WrongTier,
    PowTooWeak,
    UnknownAckTarget,
    MailboxFull,
    NodeFull,
    RateLimited,
    TooManyMailboxes,
    Unsupported,
    NotResponsible,
}

impl ErrorReason {
    /// Texte français destiné à l'utilisateur.
    pub fn describe(&self) -> &'static str {
        match self {
            ErrorReason::VersionTooOld => "version du protocole trop ancienne pour ce nœud",
            ErrorReason::Malformed => "requête ou paquet mal formé",
            ErrorReason::Expired => "le paquet est déjà expiré",
            ErrorReason::TooFarInFuture => "le paquet expire trop loin dans le futur",
            ErrorReason::WrongTier => "la taille du paquet ne correspond à aucun palier",
            ErrorReason::PowTooWeak => "la preuve de travail est trop faible",
            ErrorReason::UnknownAckTarget => "l'accusé vise un paquet que le nœud ne connaît pas",
            ErrorReason::MailboxFull => "la boîte aux lettres est pleine",
            ErrorReason::NodeFull => "le nœud est plein",
            ErrorReason::RateLimited => "trop de requêtes, réessayez plus tard",
            ErrorReason::TooManyMailboxes => "trop de boîtes demandées en une seule requête",
            ErrorReason::Unsupported => "requête non prise en charge par ce nœud",
            ErrorReason::NotResponsible => "ce nœud n'est pas responsable de cette boîte",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> NodeRecord {
        NodeRecord::sign(
            &ed25519_dalek::SigningKey::from_bytes(&[5; 32]),
            Some("1.2.3.4:4433".parse().unwrap()),
            None,
            7_200,
        )
    }

    fn rt<T: Serialize + for<'a> Deserialize<'a> + PartialEq + std::fmt::Debug>(v: T) {
        let bytes = postcard::to_allocvec(&v).unwrap();
        assert_eq!(postcard::from_bytes::<T>(&bytes).unwrap(), v);
    }

    #[test]
    fn request_roundtrip_all_variants() {
        rt(Request::Hello {
            version: 0,
            min_version: 0,
        });
        rt(Request::Deposit {
            packet: vec![1, 2, 3],
            pow: 42,
        });
        rt(Request::Fetch {
            mailboxes: vec![MailboxId([3; 16])],
            cursor: Some(7),
            max_bytes: 1 << 20,
        });
        rt(Request::Fetch {
            mailboxes: vec![],
            cursor: None,
            max_bytes: 0,
        });
        rt(Request::Ping { from: None });
        rt(Request::Ping {
            from: Some(record()),
        });
        rt(Request::FindNode {
            target: [9; 32],
            from: None,
        });
        rt(Request::FindNode {
            target: [9; 32],
            from: Some(record()),
        });
        rt(Request::Store {
            packet: vec![5; 10],
            pow: 77,
        });
        rt(Request::FindValue {
            mailbox: MailboxId([4; 16]),
            cursor: None,
        });
        rt(Request::FindValue {
            mailbox: MailboxId([4; 16]),
            cursor: Some(9),
        });
    }

    #[test]
    fn response_roundtrip_all_variants() {
        rt(Response::Hello {
            version: 0,
            min_version: 0,
            node_id: NodeId([8; 32]),
            pow_bits: 18,
            limits: Limits {
                max_mailboxes_per_fetch: 64,
                max_request_bytes: 65536,
                max_response_bytes: 1 << 20,
            },
        });
        rt(Response::Ok);
        rt(Response::Items {
            items: vec![vec![1], vec![2, 3]],
            next: Some(5),
        });
        for r in [
            ErrorReason::VersionTooOld,
            ErrorReason::Malformed,
            ErrorReason::Expired,
            ErrorReason::TooFarInFuture,
            ErrorReason::WrongTier,
            ErrorReason::PowTooWeak,
            ErrorReason::UnknownAckTarget,
            ErrorReason::MailboxFull,
            ErrorReason::NodeFull,
            ErrorReason::RateLimited,
            ErrorReason::TooManyMailboxes,
            ErrorReason::Unsupported,
            ErrorReason::NotResponsible,
        ] {
            rt(Response::Error(r));
            assert!(!r.describe().is_empty());
        }
        rt(Response::Pong { record: record() });
        rt(Response::Nodes { records: vec![] });
        rt(Response::Nodes {
            records: vec![record(), record()],
        });
        rt(Response::Holdings {
            hashes: vec![[1; 32], [2; 32]],
            next: Some(3),
        });
        rt(Response::Holdings {
            hashes: vec![],
            next: None,
        });
    }

    #[test]
    fn variant_order_is_stable() {
        // Les variantes réservées suivent les variantes actives : ordre figé.
        assert_eq!(
            postcard::to_allocvec(&Request::Ping { from: None }).unwrap(),
            [3, 0]
        );
        assert_eq!(
            postcard::to_allocvec(&Response::Error(ErrorReason::Unsupported)).unwrap(),
            [3, 11]
        );
    }

    #[test]
    fn new_variants_are_appended() {
        let first = |r: &Response| postcard::to_allocvec(r).unwrap()[0];
        let error = first(&Response::Error(ErrorReason::Unsupported));
        assert_eq!(error, 3);
        assert_eq!(first(&Response::Pong { record: record() }), error + 1);
        assert_eq!(first(&Response::Nodes { records: vec![] }), error + 2);
        assert_eq!(
            first(&Response::Holdings {
                hashes: vec![],
                next: None
            }),
            error + 3
        );
        let reason = |r| postcard::to_allocvec(&Response::Error(r)).unwrap()[1];
        assert_eq!(reason(ErrorReason::Unsupported), 11);
        assert_eq!(
            reason(ErrorReason::NotResponsible),
            reason(ErrorReason::Unsupported) + 1
        );
    }
}
