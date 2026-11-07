//! Transparency log: what the core did, and what the
//! intermediaries could see of it (spec §8). Local only.

use crate::identity::device::DeviceId;
use crate::identity::root::Fingerprint;
use crate::mailbox::MailboxId;
use crate::packet::{PacketId, Tier};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransparencyEvent {
    SessionEstablished {
        contact: Fingerprint,
        device: DeviceId,
        initiator: bool,
        post_quantum: bool,
    },
    PacketSealed {
        packet_id: PacketId,
        tier: Tier,
        size: u32,
        mailbox: MailboxId,
        expires_at: u32,
        recipient_device: DeviceId,
        /// First message of a session (introduction mailbox).
        first_contact: bool,
    },
    PacketOpened {
        packet_id: PacketId,
        sender: Fingerprint,
        transport: String,
        /// The packet opened a session (introduction mailbox).
        first_contact: bool,
    },
    AckEmitted {
        for_packet: PacketId,
    },
    AckVerified {
        for_packet: PacketId,
    },
    DecryptFailed {
        packet_id: PacketId,
        reason: String,
    },
    DuplicateIgnored {
        packet_id: PacketId,
    },
    ContactKeyChanged {
        alias: String,
        old: Fingerprint,
        new: Fingerprint,
    },
    /// Frame rejected at reassembly; `reason` is a fixed text.
    FrameRejected {
        reason: String,
    },
    /// Administrator side: a new device was linked to my account.
    DeviceLinked {
        device: DeviceId,
        name: String,
    },
    /// New device side: the linking is finished.
    LinkFinished {
        device_count: u32,
        contacts: u32,
    },
    /// Synchronisation content received from one of my devices and applied.
    SyncApplied {
        kind: SyncKind,
    },
    /// Synchronisation copy not sent: too large for a packet.
    SyncSkipped {
        kind: SyncKind,
    },
    /// Card of a contact replaced by a new device list:
    /// `added` devices added, `removed` removed. `alias`: that of the
    /// contact at the time of the update (empty: none).
    ContactCardUpdated {
        contact: Fingerprint,
        alias: String,
        added: u32,
        removed: u32,
    },
    /// New device side: `count` history messages imported
    /// during the linking (offline archive).
    HistoryImported {
        count: u32,
    },
    /// My device list changed, received from one of my devices
    /// (`SyncDevices`): `added` devices added, `removed` removed.
    /// Added last: the order of the variants is the stored format.
    OwnDevicesUpdated {
        added: u32,
        removed: u32,
    },
    /// Deposits on a node: `node` is the short identifier (8 base32
    /// characters), never a mailbox or an address. Added last.
    NodeDeposit {
        node: String,
        count: u32,
        refused: u32,
    },
    /// Fetch on a node: `mailboxes` mailboxes fetched, `received` items
    /// received. Added last.
    NodeFetch {
        node: String,
        mailboxes: u32,
        received: u32,
    },
    /// A node was set aside by the client's scoring (`node` is the short
    /// identifier, never an address). Added last.
    NodeAvoided {
        node: String,
        reason: AvoidReason,
    },
    /// A packet was not sealed for one device of a contact (or of mine):
    /// its published keys are unusable. The other devices still get
    /// theirs. Added last.
    SealSkipped {
        contact: Fingerprint,
        device: DeviceId,
    },
    /// The root key was sent to another of my devices; it stays here until
    /// that device acknowledges it. Added last.
    AdminTransferStarted {
        device: DeviceId,
    },
    /// The root key was received by `device` and erased here. Added last.
    AdminTransferred {
        device: DeviceId,
    },
    /// The root key arrived from another of my devices. Added last.
    AdminReceived,
    /// A newer device list signed by my root no longer contains this device:
    /// it is removed from my account, its root key (if any) erased. Added last.
    ThisDeviceRemoved {
        version: u64,
    },
    /// Administrator side: my device `device` (`name`) was removed from my
    /// list, which went to my devices and contacts. Added last.
    DeviceRemoved {
        device: DeviceId,
        name: String,
    },
    /// Administrator side: my device `device` (`name`) asked to leave my
    /// account (`RemoveMe`) and was removed. Added last.
    RemoveRequested {
        device: DeviceId,
        name: String,
    },
    /// `count` messages deleted from this device: `cancelled` of them
    /// before any packet to the contact left it (nobody receives them),
    /// `already_left` with at least one packet already on the network or
    /// received (the contact still receives them). No content, no
    /// contact. Added last.
    MessagesDeleted {
        count: u32,
        cancelled: u32,
        already_left: u32,
    },
}

/// Why a node was set aside.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AvoidReason {
    /// A message deposited there was lost.
    MessageLost,
    /// The node kept failing to answer.
    Unreachable,
}

/// Type of synchronisation between my devices.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncKind {
    Sent,
    Contact,
    Devices,
    /// The root key (admin transfer). Added last.
    Admin,
}

impl SyncKind {
    /// Displayed name: "sent message", "contact", "device list".
    pub fn label(self) -> &'static str {
        match self {
            SyncKind::Sent => "sent message",
            SyncKind::Contact => "contact",
            SyncKind::Devices => "device list",
            SyncKind::Admin => "admin key",
        }
    }
}

/// What any relay reads in the plaintext header of a packet.
const RELAYS_SEE: &str = "Relays see: the size, the type (message or acknowledgement), \
    the hop count, a packet identifier, the mailbox, the expiry.";

/// What relays do not see (real identity, real recipient, content).
const RELAYS_DONT_SEE: &str = "They do not see: who you are, whom you are writing to, the content.";

/// Variant for a first message: the introduction mailbox designates the recipient.
const RELAYS_DONT_SEE_FIRST: &str = "They see neither who you are nor the content. But \
    anyone who has the recipient's contact card can tell that this is a first \
    message for that person.";

/// Message / acknowledgement link, visible to relays.
const ACK_LINK: &str = "The packet identifier lets relays link a message to its \
    acknowledgement, and the acknowledgement reuses the message's mailbox: they can therefore link \
    the two, without learning anyone's real identity.";

fn tier_label(tier: Tier) -> &'static str {
    match tier {
        Tier::S => "small",
        Tier::M => "medium",
        Tier::L => "large",
    }
}

impl TransparencyEvent {
    /// Security proof: an established session, a changed contact
    /// key, a contact's updated device list, a device linked to my account (administrator side) or a
    /// finished linking (new device side: it is the proof of the identity
    /// it has joined). These entries have their own cap in the log; the
    /// others (which a third party can trigger in bulk) never evict them.
    pub fn is_security(&self) -> bool {
        matches!(
            self,
            Self::SessionEstablished { .. }
                | Self::ContactKeyChanged { .. }
                | Self::DeviceLinked { .. }
                | Self::LinkFinished { .. }
                | Self::ContactCardUpdated { .. }
                | Self::OwnDevicesUpdated { .. }
                | Self::AdminTransferred { .. }
                | Self::AdminReceived
                | Self::ThisDeviceRemoved { .. }
                | Self::DeviceRemoved { .. }
                | Self::RemoveRequested { .. }
        )
    }

    /// English text intended for the user. Never includes message
    /// text (events do not carry any).
    pub fn describe(&self) -> String {
        match self {
            Self::SessionEstablished {
                contact,
                device,
                initiator,
                post_quantum,
            } => {
                let role = if *initiator {
                    "You opened"
                } else {
                    "Your contact opened"
                };
                let crypto = if *post_quantum {
                    "also protected against quantum computers"
                } else {
                    "without post-quantum protection"
                };
                format!(
                    "{role} a session with contact {contact} (device {}), {crypto}.",
                    hex(&device.0[..4])
                )
            }
            Self::PacketSealed {
                tier,
                size,
                expires_at,
                first_contact,
                ..
            } => {
                let (mailbox, hidden) = if *first_contact {
                    (
                        "First message of a session: the introduction mailbox \
                         is computed from the public key of the recipient device \
                         and the day.",
                        RELAYS_DONT_SEE_FIRST,
                    )
                } else {
                    (
                        "The mailbox is temporary: it changes every day and does not \
                         reveal your contact's real identity.",
                        RELAYS_DONT_SEE,
                    )
                };
                format!(
                    "Encrypted packet of {size} bytes ({} tier), expires on {}. {mailbox} \
                     {RELAYS_SEE} {hidden}",
                    tier_label(*tier),
                    format_utc(*expires_at)
                )
            }
            Self::PacketOpened {
                sender,
                transport,
                first_contact,
                ..
            } => {
                let (intro, hidden) = if *first_contact {
                    (
                        " It opened a session: it arrived in your introduction \
                         mailbox, computed from the public key of your device \
                         and the day.",
                        RELAYS_DONT_SEE_FIRST,
                    )
                } else {
                    ("", RELAYS_DONT_SEE)
                };
                format!(
                    "Packet received via {transport} and decrypted: it comes from {sender}.{intro} \
                     The relays that carried it were able to read its header. {RELAYS_SEE} \
                     {hidden}"
                )
            }
            Self::AckEmitted { for_packet } => format!(
                "Acknowledgement published for packet {}. {RELAYS_SEE} {ACK_LINK} \
                 The acknowledgement secret lets them delete their copies.",
                hex(&for_packet.0[..4])
            ),
            Self::AckVerified { for_packet } => format!(
                "Your packet {} has arrived: the acknowledgement has been verified. \
                 {RELAYS_SEE} {ACK_LINK}",
                hex(&for_packet.0[..4])
            ),
            Self::DecryptFailed { packet_id, reason } => format!(
                "Packet {} could not be decrypted ({reason}). It was ignored. \
                 {RELAYS_SEE} They do not know whether it was read.",
                hex(&packet_id.0[..4])
            ),
            Self::DuplicateIgnored { packet_id } => format!(
                "Packet {} already received: the copy was ignored. \
                 Relays may carry several copies of it; this is normal.",
                hex(&packet_id.0[..4])
            ),
            Self::ContactKeyChanged { alias, old, new } => format!(
                "Warning: the key of {alias} has changed (old fingerprint {old}, \
                 new {new}). Check the safety number with this person \
                 before continuing."
            ),
            Self::FrameRejected { reason } => format!(
                "Frame rejected ({reason}): it does not match the announced packet. \
                 The packet was not reassembled; the sender will resend it."
            ),
            Self::DeviceLinked { name, .. } => format!(
                "New device \"{name}\" linked to your account. \
                 Your contacts will receive your new device list."
            ),
            Self::LinkFinished {
                device_count,
                contacts,
            } => format!(
                "This device is now linked to your account ({device_count} devices, \
                 {contacts} contacts copied). The root key was not copied."
            ),
            Self::SyncApplied { kind } => {
                format!("Synchronized from one of your devices: {}.", kind.label())
            }
            Self::SyncSkipped { kind } => format!(
                "Copy to your other devices not sent ({}): too large. \
                 Your devices may differ on this point.",
                kind.label()
            ),
            Self::ContactCardUpdated {
                contact,
                alias,
                added,
                removed,
            } => format!(
                "{} updated their device list (+{added}, \u{2212}{removed}). \
                 Messages will also be encrypted for their new devices.",
                if alias.is_empty() {
                    contact.to_string()
                } else {
                    alias.clone()
                }
            ),
            Self::HistoryImported { count } => format!(
                "{count} history messages copied from your other device. \
                 They did not pass through any node."
            ),
            Self::OwnDevicesUpdated { added, removed } => {
                format!("Your device list has changed (+{added}, \u{2212}{removed}).")
            }
            Self::NodeDeposit {
                node,
                count,
                refused,
            } => format!(
                "{count} packets deposited on node {node} ({refused} refused). \
                 The node sees the mailbox, the size, the time and your IP address; \
                 not the content."
            ),
            Self::NodeFetch {
                node,
                mailboxes,
                received,
            } => format!(
                "Mailboxes fetched from node {node}: {mailboxes} mailboxes, {received} items \
                 received. The node sees which mailboxes you fetch and your IP address during the \
                 connection, and can link together the deposits and the fetch of a single \
                 connection. Your introduction mailbox is computed from your public key: \
                 fetching it links your identity to this IP address."
            ),
            Self::NodeAvoided { node, reason } => {
                let why = match reason {
                    AvoidReason::MessageLost => "a message deposited there was lost",
                    AvoidReason::Unreachable => "it kept failing to answer",
                };
                format!("Node {node} is set aside for 7 days: {why}.")
            }
            Self::SealSkipped { contact, device } => format!(
                "Nothing was encrypted for device {} of {contact}: its published keys \
                 are unusable. Its other devices still receive the packet.",
                hex(&device.0[..4])
            ),
            Self::AdminTransferStarted { device } => format!(
                "The root key was sent, encrypted, to your device {}. This device keeps \
                 it until that device confirms receipt, then erases it.",
                hex(&device.0[..4])
            ),
            Self::AdminTransferred { device } => format!(
                "Your device {} is now the administrator: it holds the root key. \
                 This device erased its copy.",
                hex(&device.0[..4])
            ),
            Self::AdminReceived => "This device is now the administrator: it received the \
                 root key from another of your devices."
                .to_owned(),
            Self::ThisDeviceRemoved { version } => format!(
                "This device was removed from your account by a newer device list \
                 (version {version}), for example after a recovery from the 24 words. \
                 It can no longer send; its root key, if it had one, was erased."
            ),
            Self::DeviceRemoved { device, name } => format!(
                "Your device \"{name}\" ({}) was removed from your account: your other \
                 devices and your contacts will no longer encrypt anything for it once \
                 they receive the new device list.",
                hex(&device.0[..4])
            ),
            Self::RemoveRequested { device, name } => format!(
                "Your device \"{name}\" ({}) asked to leave your account; it was \
                 removed from your device list.",
                hex(&device.0[..4])
            ),
            Self::MessagesDeleted {
                count,
                cancelled,
                already_left,
            } => format!(
                "{count} message(s) deleted from this device: {cancelled} cancelled before \
                 leaving it, {already_left} had already left (the contact still receives \
                 them)."
            ),
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Readable UTC date `YYYY-MM-DD HH:MM UTC`, with no clock or dependency
/// (Howard Hinnant's "civil from days" algorithm).
fn format_utc(secs: u32) -> String {
    let secs = i64::from(secs);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02} UTC",
        rem / 3_600,
        rem % 3_600 / 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid() -> PacketId {
        PacketId([0xab; 16])
    }
    fn fp(b: u8) -> Fingerprint {
        Fingerprint([b; 32])
    }
    fn sealed() -> TransparencyEvent {
        TransparencyEvent::PacketSealed {
            packet_id: pid(),
            tier: Tier::M,
            size: 1024,
            mailbox: MailboxId([1; 16]),
            expires_at: 1_700_000_000,
            recipient_device: DeviceId([2; 16]),
            first_contact: false,
        }
    }
    fn sealed_first() -> TransparencyEvent {
        match sealed() {
            TransparencyEvent::PacketSealed {
                packet_id,
                tier,
                size,
                mailbox,
                expires_at,
                recipient_device,
                ..
            } => TransparencyEvent::PacketSealed {
                packet_id,
                tier,
                size,
                mailbox,
                expires_at,
                recipient_device,
                first_contact: true,
            },
            _ => unreachable!(),
        }
    }

    fn all() -> Vec<TransparencyEvent> {
        vec![
            TransparencyEvent::SessionEstablished {
                contact: fp(1),
                device: DeviceId([2; 16]),
                initiator: true,
                post_quantum: true,
            },
            sealed(),
            TransparencyEvent::PacketOpened {
                packet_id: pid(),
                sender: fp(3),
                transport: "file".into(),
                first_contact: false,
            },
            TransparencyEvent::PacketOpened {
                packet_id: pid(),
                sender: fp(3),
                transport: "file".into(),
                first_contact: true,
            },
            TransparencyEvent::AckEmitted { for_packet: pid() },
            TransparencyEvent::AckVerified { for_packet: pid() },
            TransparencyEvent::DecryptFailed {
                packet_id: pid(),
                reason: "invalid authentication".into(),
            },
            TransparencyEvent::DuplicateIgnored { packet_id: pid() },
            TransparencyEvent::ContactKeyChanged {
                alias: "Alice".into(),
                old: fp(4),
                new: fp(5),
            },
            TransparencyEvent::FrameRejected {
                reason: "bad frame hash".into(),
            },
            TransparencyEvent::DeviceLinked {
                device: DeviceId([6; 16]),
                name: "tablet".into(),
            },
            TransparencyEvent::LinkFinished {
                device_count: 2,
                contacts: 3,
            },
            TransparencyEvent::SyncApplied {
                kind: SyncKind::Sent,
            },
            TransparencyEvent::SyncApplied {
                kind: SyncKind::Contact,
            },
            TransparencyEvent::SyncApplied {
                kind: SyncKind::Devices,
            },
            TransparencyEvent::SyncSkipped {
                kind: SyncKind::Contact,
            },
            TransparencyEvent::ContactCardUpdated {
                contact: fp(7),
                alias: "Alice".into(),
                added: 1,
                removed: 0,
            },
            TransparencyEvent::HistoryImported { count: 3 },
            TransparencyEvent::OwnDevicesUpdated {
                added: 1,
                removed: 0,
            },
            TransparencyEvent::NodeDeposit {
                node: "ABCDEFGH".into(),
                count: 2,
                refused: 1,
            },
            TransparencyEvent::NodeFetch {
                node: "ABCDEFGH".into(),
                mailboxes: 5,
                received: 3,
            },
            TransparencyEvent::NodeAvoided {
                node: "ABCDEFGH".into(),
                reason: AvoidReason::MessageLost,
            },
            TransparencyEvent::NodeAvoided {
                node: "ABCDEFGH".into(),
                reason: AvoidReason::Unreachable,
            },
            TransparencyEvent::SealSkipped {
                contact: fp(8),
                device: DeviceId([9; 16]),
            },
            TransparencyEvent::SyncApplied {
                kind: SyncKind::Admin,
            },
            TransparencyEvent::AdminTransferStarted {
                device: DeviceId([10; 16]),
            },
            TransparencyEvent::AdminTransferred {
                device: DeviceId([10; 16]),
            },
            TransparencyEvent::AdminReceived,
            TransparencyEvent::ThisDeviceRemoved { version: 7 },
            TransparencyEvent::DeviceRemoved {
                device: DeviceId([11; 16]),
                name: "iPad".to_owned(),
            },
            TransparencyEvent::RemoveRequested {
                device: DeviceId([12; 16]),
                name: "iPad".to_owned(),
            },
        ]
    }

    /// Logged before the `CardUpdate` leaves: the contacts stop encrypting
    /// for the device only once they receive the new list.
    #[test]
    fn describe_device_removed_exact() {
        let e = TransparencyEvent::DeviceRemoved {
            device: DeviceId([0xab; 16]),
            name: "iPad".to_owned(),
        };
        assert_eq!(
            e.describe(),
            "Your device \"iPad\" (abababab) was removed from your account: your \
             other devices and your contacts will no longer encrypt anything for \
             it once they receive the new device list."
        );
    }

    #[test]
    fn node_avoided_event_roundtrip() {
        let e = TransparencyEvent::NodeAvoided {
            node: "ABCDEFGH".into(),
            reason: AvoidReason::MessageLost,
        };
        assert!(!e.is_security());
        let bytes = postcard::to_allocvec(&e).unwrap();
        assert_eq!(
            postcard::from_bytes::<TransparencyEvent>(&bytes).unwrap(),
            e
        );
        assert_eq!(
            e.describe(),
            "Node ABCDEFGH is set aside for 7 days: a message deposited there was lost."
        );
        let u = TransparencyEvent::NodeAvoided {
            node: "ABCDEFGH".into(),
            reason: AvoidReason::Unreachable,
        };
        assert_eq!(
            u.describe(),
            "Node ABCDEFGH is set aside for 7 days: it kept failing to answer."
        );
    }

    #[test]
    fn describe_sync_applied_exact() {
        let d = |kind| TransparencyEvent::SyncApplied { kind }.describe();
        assert_eq!(
            d(SyncKind::Sent),
            "Synchronized from one of your devices: sent message."
        );
        assert_eq!(
            d(SyncKind::Contact),
            "Synchronized from one of your devices: contact."
        );
        assert_eq!(
            d(SyncKind::Devices),
            "Synchronized from one of your devices: device list."
        );
        assert!(
            !TransparencyEvent::SyncApplied {
                kind: SyncKind::Devices
            }
            .is_security()
        );
        let skipped = |kind| TransparencyEvent::SyncSkipped { kind };
        assert_eq!(
            skipped(SyncKind::Contact).describe(),
            "Copy to your other devices not sent (contact): too large. \
             Your devices may differ on this point."
        );
        assert_eq!(
            skipped(SyncKind::Devices).describe(),
            "Copy to your other devices not sent (device list): too \
             large. Your devices may differ on this point."
        );
        assert!(!skipped(SyncKind::Sent).is_security());
    }

    #[test]
    fn describe_sealed_mentions_what_relays_see() {
        let d = sealed().describe();
        assert!(d.contains("Relays see"), "{d}");
        assert!(d.contains("They do not see"), "{d}");
        assert!(d.contains("1024 bytes"), "{d}");
        // 1_700_000_000 = 2023-11-14 22:13:20 UTC
        assert!(d.contains("2023-11-14 22:13 UTC"), "{d}");
    }

    #[test]
    fn describe_is_nonempty_for_all_variants() {
        for e in all() {
            assert!(!e.describe().is_empty(), "{e:?}");
        }
    }

    #[test]
    fn describe_packet_events_explain_visibility() {
        for e in all() {
            if matches!(
                e,
                TransparencyEvent::PacketOpened { .. }
                    | TransparencyEvent::DecryptFailed { .. }
                    | TransparencyEvent::AckEmitted { .. }
            ) {
                let d = e.describe();
                assert!(d.contains("Relays see"), "{d}");
            }
        }
    }

    #[test]
    fn describe_lists_all_visible_header_fields() {
        let ack = TransparencyEvent::AckEmitted { for_packet: pid() }.describe();
        for d in [sealed().describe(), ack] {
            for w in ["type", "hop count", "identifier", "mailbox", "expiry"] {
                assert!(d.contains(w), "{w} missing: {d}");
            }
        }
        assert!(!sealed().describe().contains("Tier"));
        assert!(sealed().describe().contains("medium"));
    }

    #[test]
    fn describe_ack_states_linkability() {
        let d = TransparencyEvent::AckVerified { for_packet: pid() }.describe();
        assert!(d.contains("link"), "{d}");
    }

    #[test]
    fn describe_first_contact_mentions_contact_card() {
        let d = sealed_first().describe();
        assert!(d.contains("contact card"), "{d}");
        assert!(!sealed().describe().contains("contact card"));
    }

    #[test]
    fn describe_first_contact_does_not_claim_recipient_hidden() {
        let opened = |first_contact| TransparencyEvent::PacketOpened {
            packet_id: pid(),
            sender: fp(3),
            transport: "file".into(),
            first_contact,
        };
        for d in [sealed_first().describe(), opened(true).describe()] {
            assert!(!d.contains("whom you are writing to"), "{d}");
            assert!(d.contains("contact card"), "{d}");
            assert!(d.contains("Relays see"), "{d}");
            assert!(d.contains("who you are"), "{d}");
        }
        assert!(sealed().describe().contains("whom you are writing to"));
        assert!(!opened(false).describe().contains("contact card"));
    }

    #[test]
    fn security_class_is_session_key_change_and_link_only() {
        let security: Vec<_> = all().into_iter().filter(|e| e.is_security()).collect();
        assert_eq!(security.len(), 11);
        assert!(security.iter().all(|e| matches!(
            e,
            TransparencyEvent::SessionEstablished { .. }
                | TransparencyEvent::ContactKeyChanged { .. }
                | TransparencyEvent::DeviceLinked { .. }
                | TransparencyEvent::LinkFinished { .. }
                | TransparencyEvent::ContactCardUpdated { .. }
                | TransparencyEvent::AdminTransferred { .. }
                | TransparencyEvent::AdminReceived
                | TransparencyEvent::ThisDeviceRemoved { .. }
                | TransparencyEvent::DeviceRemoved { .. }
                | TransparencyEvent::RemoveRequested { .. }
                | TransparencyEvent::OwnDevicesUpdated { .. }
        )));
    }

    #[test]
    fn describe_link_events_exact() {
        let linked = TransparencyEvent::DeviceLinked {
            device: DeviceId([6; 16]),
            name: "tablet".into(),
        };
        assert_eq!(
            linked.describe(),
            "New device \"tablet\" linked to your account. \
             Your contacts will receive your new device list."
        );
        let finished = TransparencyEvent::LinkFinished {
            device_count: 2,
            contacts: 3,
        };
        assert_eq!(
            finished.describe(),
            "This device is now linked to your account (2 devices, 3 contacts copied). \
             The root key was not copied."
        );
    }

    #[test]
    fn describe_history_imported_exact() {
        let e = TransparencyEvent::HistoryImported { count: 42 };
        assert!(!e.is_security());
        assert_eq!(
            e.describe(),
            "42 history messages copied from your other device. \
             They did not pass through any node."
        );
    }

    #[test]
    fn describe_contact_card_updated_exact() {
        let e = |alias: &str| TransparencyEvent::ContactCardUpdated {
            contact: fp(7),
            alias: alias.into(),
            added: 1,
            removed: 2,
        };
        assert_eq!(
            e("Alice").describe(),
            "Alice updated their device list (+1, \u{2212}2). \
             Messages will also be encrypted for their new devices."
        );
        // Without alias: the fingerprint.
        assert_eq!(
            e("").describe(),
            format!(
                "{} updated their device list (+1, \u{2212}2). \
                 Messages will also be encrypted for their new devices.",
                fp(7)
            )
        );
    }

    #[test]
    fn describe_own_devices_updated_exact() {
        let e = TransparencyEvent::OwnDevicesUpdated {
            added: 2,
            removed: 1,
        };
        assert!(e.is_security());
        assert_eq!(
            e.describe(),
            "Your device list has changed (+2, \u{2212}1)."
        );
    }

    #[test]
    fn describe_node_events_exact() {
        let dep = TransparencyEvent::NodeDeposit {
            node: "ABCDEFGH".into(),
            count: 2,
            refused: 1,
        };
        assert!(!dep.is_security());
        assert_eq!(
            dep.describe(),
            "2 packets deposited on node ABCDEFGH (1 refused). \
             The node sees the mailbox, the size, the time and your IP address; \
             not the content."
        );
        let fetch = TransparencyEvent::NodeFetch {
            node: "ABCDEFGH".into(),
            mailboxes: 5,
            received: 3,
        };
        assert!(!fetch.is_security());
        assert_eq!(
            fetch.describe(),
            "Mailboxes fetched from node ABCDEFGH: 5 mailboxes, 3 items received. \
             The node sees which mailboxes you fetch and your IP address during the connection, \
             and can link together the deposits and the fetch of a single connection. \
             Your introduction mailbox is computed from your public key: \
             fetching it links your identity to this IP address."
        );
    }

    #[test]
    fn civil_date_known_values() {
        assert_eq!(format_utc(0), "1970-01-01 00:00 UTC");
        assert_eq!(format_utc(951_782_400), "2000-02-29 00:00 UTC");
        assert_eq!(format_utc(u32::MAX), "2106-02-07 06:28 UTC");
    }

    #[test]
    fn serde_roundtrip_all_variants() {
        for e in all() {
            let bytes = postcard::to_allocvec(&e).unwrap();
            let back: TransparencyEvent = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(e, back);
        }
    }
}
