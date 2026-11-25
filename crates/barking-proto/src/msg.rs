//! Client-to-node requests and responses. New variants always go
//! at the end (postcard encoding numbers the variants).

use barking_packet::MailboxId;
use serde::{Deserialize, Serialize};

use crate::{
    node_id::NodeId,
    push::{OwnerProof, Subscription},
    record::NodeRecord,
};

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

/// A relay's push link is only reported (`Ok` / `Failing`) once it serves at
/// least this many subscriptions; below, it is `Unknown`.
pub const PUSH_LINK_MIN_SUBS: u64 = 20;

/// Longest `NodeInfoReport::software` a node sends (bytes).
pub const MAX_SOFTWARE_LEN: usize = 32;

/// Longest `NodeOrigin::as_name` a node sends (bytes).
pub const MAX_AS_NAME_LEN: usize = 64;

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
    /// `Subscribe` for an intro mailbox, with proof that the sender owns it
    /// (protocol 3). `pow` is over `push::subscription_hash(&sub)`.
    SubscribeOwned {
        sub: Subscription,
        pow: u64,
        owner: OwnerProof,
    },
    /// Public report on the node (protocol 5). With `relay`, the report of
    /// the push relay that node id names, if the node fronts it.
    Info {
        relay: Option<NodeId>,
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
    /// Answer to `Request::Info` (protocol 5).
    Info(NodeInfoReport),
}

/// How full a resource is, coarsely: exact figures stay private.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FillTier {
    /// Under 50 %.
    Low,
    /// From 50 % to under 80 %.
    Medium,
    /// From 80 % to under 95 %.
    High,
    /// 95 % or more (also a resource without capacity).
    Full,
}

impl FillTier {
    /// Tier of `used` out of `max`; `max == 0` is `Full`.
    pub fn of(used: u64, max: u64) -> FillTier {
        if max == 0 {
            return FillTier::Full;
        }
        let used = u128::from(used) * 100;
        let max = u128::from(max);
        if used >= max * 95 {
            FillTier::Full
        } else if used >= max * 80 {
            FillTier::High
        } else if used >= max * 50 {
            FillTier::Medium
        } else {
            FillTier::Low
        }
    }
}

/// State of a relay's link to its push provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PushLink {
    /// Recent pushes went through.
    Ok,
    /// Recent pushes failed.
    Failing,
    /// Not enough subscriptions (`PUSH_LINK_MIN_SUBS`) or data to tell.
    Unknown,
}

/// Where a node's address sits on the network.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeOrigin {
    /// Autonomous system number.
    pub asn: u32,
    /// Name of the autonomous system (at most `MAX_AS_NAME_LEN` bytes).
    pub as_name: String,
    /// ISO 3166-1 alpha-2 country code.
    pub country: [u8; 2],
    /// True if this describes the node's IPv6 address, false for IPv4.
    pub for_v6: bool,
}

/// Public self-report of a node (protocol 5).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeInfoReport {
    /// Software name and version (at most `MAX_SOFTWARE_LEN` bytes).
    pub software: String,
    /// Highest protocol version the node speaks.
    pub protocol: u16,
    /// Seconds since the node started.
    pub uptime_secs: u64,
    /// Fill of the node's message storage.
    pub storage: FillTier,
    /// Fill of the wake subscription table, if the node takes subscriptions.
    pub wake: Option<FillTier>,
    /// Push link state, if the node fronts a push relay.
    pub push_link: Option<PushLink>,
    /// Network origin of the node, if known.
    pub origin: Option<NodeOrigin>,
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
        let sub2 = sub.clone();
        assert_eq!(first(&Request::Subscribe { sub, pow: 0 }), find_value + 1);
        assert_eq!(
            first(&Request::Unsubscribe {
                mailbox: MailboxId([0; 16]),
                cancel_secret: [0; 32]
            }),
            find_value + 2
        );
        assert_eq!(first(&Request::Wake { items: vec![] }), find_value + 3);
        let owner = crate::push::OwnerProof {
            sig: [1; 32],
            dh: [2; 32],
            day: 7,
            signature: [3; 64],
        };
        let owned = Request::SubscribeOwned {
            sub: sub2,
            pow: 5,
            owner,
        };
        assert_eq!(first(&owned), find_value + 4);
        rt(owned);
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

    #[test]
    fn old_request_variant_indices_unchanged() {
        let enc = |r: &Request| postcard::to_allocvec(r).unwrap();
        let hello = Request::Hello {
            version: 4,
            min_version: 2,
        };
        assert_eq!(enc(&hello), [0, 4, 2]);
        assert_eq!(postcard::from_bytes::<Request>(&[0, 4, 2]).unwrap(), hello);
        let ping = Request::Ping { from: None };
        assert_eq!(enc(&ping), [3, 0]);
        assert_eq!(postcard::from_bytes::<Request>(&[3, 0]).unwrap(), ping);
        let wake = Request::Wake { items: vec![] };
        assert_eq!(enc(&wake), [9, 0]);
        assert_eq!(postcard::from_bytes::<Request>(&[9, 0]).unwrap(), wake);
        let owned = postcard::to_allocvec(&Request::SubscribeOwned {
            sub: crate::push::Subscription {
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
            },
            pow: 0,
            owner: crate::push::OwnerProof {
                sig: [0; 32],
                dh: [0; 32],
                day: 0,
                signature: [0; 64],
            },
        })
        .unwrap()[0];
        let info = enc(&Request::Info { relay: None })[0];
        assert!(info > owned);
        assert_eq!(info, owned + 1);
        // The new response goes after the last old one (`Holdings`).
        let holdings = postcard::to_allocvec(&Response::Holdings {
            hashes: vec![],
            next: None,
        })
        .unwrap()[0];
        let report = postcard::to_allocvec(&Response::Info(report_none())).unwrap()[0];
        assert_eq!(report, holdings + 1);
    }

    fn report_none() -> NodeInfoReport {
        NodeInfoReport {
            software: String::new(),
            protocol: 0,
            uptime_secs: 0,
            storage: FillTier::Low,
            wake: None,
            push_link: None,
            origin: None,
        }
    }

    #[test]
    fn info_report_roundtrip() {
        rt(Request::Info { relay: None });
        rt(Request::Info {
            relay: Some(NodeId([4; 32])),
        });
        rt(Response::Info(report_none()));
        rt(Response::Info(NodeInfoReport {
            software: "barking-node 0.1.0".into(),
            protocol: 5,
            uptime_secs: 86_400,
            storage: FillTier::High,
            wake: Some(FillTier::Medium),
            push_link: Some(PushLink::Failing),
            origin: Some(NodeOrigin {
                asn: 64_496,
                as_name: "EXAMPLE-AS".into(),
                country: *b"FR",
                for_v6: true,
            }),
        }));
        for t in [
            FillTier::Low,
            FillTier::Medium,
            FillTier::High,
            FillTier::Full,
        ] {
            rt(t);
        }
        for l in [PushLink::Ok, PushLink::Failing, PushLink::Unknown] {
            rt(l);
        }
    }

    #[test]
    fn fill_tier_thresholds() {
        assert_eq!(FillTier::of(49, 100), FillTier::Low);
        assert_eq!(FillTier::of(50, 100), FillTier::Medium);
        assert_eq!(FillTier::of(79, 100), FillTier::Medium);
        assert_eq!(FillTier::of(80, 100), FillTier::High);
        assert_eq!(FillTier::of(94, 100), FillTier::High);
        assert_eq!(FillTier::of(95, 100), FillTier::Full);
        assert_eq!(FillTier::of(0, 0), FillTier::Full);
        // Beyond the maximum, and no overflow on huge values.
        assert_eq!(FillTier::of(200, 100), FillTier::Full);
        assert_eq!(FillTier::of(u64::MAX / 2 + 1, u64::MAX), FillTier::Medium);
    }
}
