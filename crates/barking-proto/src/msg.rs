//! Requêtes et réponses client↔nœud. Les nouvelles variantes vont toujours
//! à la fin (le codage postcard numérote les variantes).

use barking_packet::MailboxId;
use serde::{Deserialize, Serialize};

use crate::node_id::NodeId;

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
    },
    /// Réservées au sous-projet 2.
    Ping,
    FindNode {
        target: [u8; 32],
    },
    Store {
        packet: Vec<u8>,
    },
    FindValue {
        mailbox: MailboxId,
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
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        });
        rt(Request::Fetch {
            mailboxes: vec![],
            cursor: None,
        });
        rt(Request::Ping);
        rt(Request::FindNode { target: [9; 32] });
        rt(Request::Store {
            packet: vec![5; 10],
        });
        rt(Request::FindValue {
            mailbox: MailboxId([4; 16]),
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
        ] {
            rt(Response::Error(r));
            assert!(!r.describe().is_empty());
        }
    }

    #[test]
    fn variant_order_is_stable() {
        // Les variantes réservées suivent les variantes actives : ordre figé.
        assert_eq!(postcard::to_allocvec(&Request::Ping).unwrap(), [3]);
        assert_eq!(
            postcard::to_allocvec(&Response::Error(ErrorReason::Unsupported)).unwrap(),
            [3, 11]
        );
    }
}
