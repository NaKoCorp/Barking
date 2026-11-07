//! Client-to-node requests and responses. New variants always go
//! at the end (postcard encoding numbers the variants).

use barking_packet::MailboxId;
use serde::{Deserialize, Serialize};

use crate::{node_id::NodeId, push::Subscription, record::NodeRecord};

/// Pickup cursors: packets first (cursor = their sequence number,
/// below this base), then acknowledgements (`ACK_CURSOR_BASE + number`).
pub const ACK_CURSOR_BASE: u64 = 1 << 62;

/// Smallest pickup page served by a node (bytes of packets).
pub const MIN_PAGE_BYTES: u32 = 16 * 1024;
/// Most items a node puts in one fetch page, whatever its byte size: a page
/// with more is a protocol violation.
pub const MAX_PAGE_ITEMS: usize = 1024;

/// At most this many records in a `Nodes` response.
pub const MAX_NODES_PER_RESPONSE: usize = 20;

/// At most this many sealed tokens in a `Wake` request.
pub const MAX_WAKE_ITEMS: usize = 100;

/// At most this many fingerprints in a `Holdings` page.
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
        /// Desired page size in bytes of packets; the node clamps it
        /// between `MIN_PAGE_BYTES` and its own limit (an item larger
        /// than the page is sent alone).
        max_bytes: u32,
    },
    /// Hash table between nodes. `from` is the caller's record if it
    /// is a node.
    Ping {
        from: Option<NodeRecord>,
    },
    FindNode {
        target: [u8; 32],
        from: Option<NodeRecord>,
    },
    /// Deposit of a packet replicated between responsible nodes.
    Store {
        packet: Vec<u8>,
        pow: u64,
    },
    /// Fingerprints of the packets held for a mailbox, by pages.
    FindValue {
        mailbox: MailboxId,
        cursor: Option<u64>,
    },
    /// Registers a wake subscription for a mailbox; `pow` is the proof of
    /// work over `push::subscription_hash(&sub)`.
    Subscribe {
        sub: Subscription,
        pow: u64,
    },
    /// Cancels the subscriptions of a mailbox whose `cancel_hash` is the
    /// hash of `cancel_secret`.
    Unsubscribe {
        mailbox: MailboxId,
        cancel_secret: [u8; 32],
    },
    /// Node to relay: sealed wake tokens to push (at most `MAX_WAKE_ITEMS`).
    Wake {
        items: Vec<Vec<u8>>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    pub max_mailboxes_per_fetch: u16,
    pub max_request_bytes: u32,
    pub max_response_bytes: u32,
    /// True if the node accepts wake subscriptions.
    pub wake: bool,
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
    /// English text intended for the user.
    pub fn describe(&self) -> &'static str {
        match self {
            ErrorReason::VersionTooOld => "protocol version too old for this node",
            ErrorReason::Malformed => "malformed request or packet",
            ErrorReason::Expired => "the packet has already expired",
            ErrorReason::TooFarInFuture => "the packet expires too far in the future",
            ErrorReason::WrongTier => "the packet size matches no tier",
            ErrorReason::PowTooWeak => "the proof of work is too weak",
            ErrorReason::UnknownAckTarget => {
                "the acknowledgement targets a packet the node does not know"
            }
            ErrorReason::MailboxFull => "the mailbox is full",
            ErrorReason::NodeFull => "the node is full",
            ErrorReason::RateLimited => "too many requests, try again later",
            ErrorReason::TooManyMailboxes => "too many mailboxes requested in a single request",
            ErrorReason::Unsupported => "request not supported by this node",
            ErrorReason::NotResponsible => "this node is not responsible for this mailbox",
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
        rt(Request::Subscribe {
            sub: crate::push::Subscription {
                mailbox: MailboxId([6; 16]),
                relay: crate::push::RelayRef {
                    host: "relay.example.org".into(),
                    port: 443,
                    id: NodeId([2; 32]),
                },
                sealed: vec![7; 100],
                cancel_hash: [8; 32],
                expires_day: 20_000,
                kind: crate::push::SubKind::Messages,
            },
            pow: 99,
        });
        rt(Request::Unsubscribe {
            mailbox: MailboxId([6; 16]),
            cancel_secret: [5; 32],
        });
        rt(Request::Wake {
            items: vec![vec![1, 2], vec![]],
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
                wake: true,
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
        // Reserved variants follow the active variants: frozen order.
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
    fn push_variants_are_appended() {
        let first = |r: &Request| postcard::to_allocvec(r).unwrap()[0];
        let find_value = first(&Request::FindValue {
            mailbox: MailboxId([0; 16]),
            cursor: None,
        });
        let sub = crate::push::Subscription {
            mailbox: MailboxId([0; 16]),
            relay: crate::push::RelayRef {
                host: "r".into(),
                port: 1,
                id: NodeId([0; 32]),
            },
            sealed: vec![],
            cancel_hash: [0; 32],
            expires_day: 0,
            kind: crate::push::SubKind::Messages,
        };
        assert_eq!(first(&Request::Subscribe { sub, pow: 0 }), find_value + 1);
        assert_eq!(
            first(&Request::Unsubscribe {
                mailbox: MailboxId([0; 16]),
                cancel_secret: [0; 32]
            }),
            find_value + 2
        );
        assert_eq!(first(&Request::Wake { items: vec![] }), find_value + 3);
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
