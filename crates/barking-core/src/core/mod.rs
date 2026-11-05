//! `Core` facade: assembles identity, handshake, ratchet, mailboxes,
//! packets, storage and the transparency log.
//!
//! Bytes in and bytes out; the clock (`now`, Unix seconds) and the
//! random generator are always passed as parameters. Each operation
//! that writes (`send_text`, `receive`, `add_contact`, …) does so in a single
//! storage transaction.
//!
//! Layout: `contacts.rs` (cards, alias, verification), `send.rs`
//! (`send_text`), `receive.rs` (`receive`), `frames.rs` (fragmentation and
//! reassembly of frames), `link.rs` (linking a new device),
//! `history.rs` (history archive transferred at link time), `sync.rs`
//! (synchronization between my devices).

mod contacts;
mod frames;
mod history;
mod link;
mod log_limit;
mod receive;
mod send;
mod sync;

#[cfg(test)]
mod tests;

use core::fmt;
use std::path::Path;

use rand_core::CryptoRng;
use zeroize::{Zeroize, Zeroizing};

use crate::contact::ContactCard;
use crate::fragment::Reassembler;
use crate::handshake::pqxdh::InitialMessage;
use crate::handshake::{PrekeyBundle, PrekeySecrets};
use crate::identity::{
    DeviceCertificate, DeviceId, DeviceKeys, DeviceList, DevicePublic, Fingerprint, RecoveryPhrase,
    RootIdentity, safety_number,
};
use crate::mailbox::{MailboxId, day_of, intro_mailbox, session_mailbox};
use crate::packet::{DEFAULT_TTL_SECS, Kind, Packet, PacketId};
use crate::ratchet::RatchetState;
use crate::store::{EventClass, MessageRow, Queries, Store};
use crate::transparency::TransparencyEvent;
use crate::{CoreError, Result};

pub use crate::transparency::SyncKind;
pub use contacts::ContactSummary;
pub use frames::{FRAME_REJECT_LOG_INTERVAL_SECS, FRAME_TTL_SECS, MAX_PENDING_FRAMES};
pub use history::{HistoryArchive, MAX_ARCHIVE_BYTES};
pub use link::{
    ContactSnapshot, LINK_OFFER_TTL_SECS, LinkBundle, LinkOffer, LinkOutcome, LinkRequest,
    MAX_LINK_BUNDLE_BYTES, MAX_LINK_FILE_BYTES,
};
pub use log_limit::NOISY_EVENT_LOG_INTERVAL_SECS;

use log_limit::LogLimiter;

const META_ROOT: &str = "root_seed";
const META_DEVICE: &str = "device_keys";
const META_DEVICE_NAME: &str = "device_name";
/// My display name: last name passed to `contact_card` or `set_display_name`,
/// carried by the cards the core signs itself (link, card update
/// sent to contacts). Absent: empty name.
const META_DISPLAY_NAME: &str = "display_name";
/// Node hints carried by my contact card (`set_card_nodes`).
pub(super) const META_CARD_NODES: &str = "card_nodes";
const META_PREKEYS: &str = "prekeys";
const META_DEVICE_LIST: &str = "device_list";
const META_LINKED_BUNDLES: &str = "linked_bundles";
/// Last day (day number) on which this device polled its mailboxes.
const META_LAST_POLLED: &str = "last_polled_day";
/// Polling window: 7 days back, the current day and the next day =
/// 9 days at most. Covers each day of `accepted_days` (receive) that may
/// still hold an unexpired packet (7-day lifetime).
const MAX_POLL_BACK_DAYS: u32 = 7;

/// Mailboxes to poll, by class. A poll reads the sessions first: the
/// introduction mailbox is derivable from my public key, so anyone who has my
/// card can fill it, and reading it must not delay the sessions.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WatchedMailboxes {
    /// My session mailboxes, and the session mailboxes where I await an
    /// ack: known only to my correspondents.
    pub sessions: Vec<MailboxId>,
    /// My introduction mailboxes, and those of my contacts where I await
    /// the ack of a first contact.
    pub intro: Vec<MailboxId>,
}

/// Maximum size of a transport's state.
pub const MAX_TRANSPORT_STATE: usize = 4 << 20;

fn transport_key(key: &str) -> Result<String> {
    if key.is_empty()
        || key.len() > 64
        || !key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(CoreError::Malformed("transport state key"));
    }
    Ok(format!("transport/{key}"))
}

/// Maximum accepted age of a message (authenticated envelope timestamp):
/// packet lifetime plus one day of clock skew.
const MAX_AGE_SECS: u64 = DEFAULT_TTL_SECS + 86_400;
/// Maximum accepted lead of the sender's clock.
const MAX_FUTURE_SECS: u64 = 86_400;
/// Retention of the `seen` table. A packet seen longer ago has an
/// authenticated timestamp `sent_at <= seen + MAX_FUTURE`, so it is now
/// refused as too old: the purge does not reopen the door to replays.
const SEEN_RETENTION_SECS: u64 = MAX_AGE_SECS + MAX_FUTURE_SECS;

/// Result of receiving bytes from outside.
pub enum ReceiveOutcome {
    /// Decrypted message. `ack` is the receipt acknowledgement to send back.
    Message {
        from: Fingerprint,
        alias: Option<String>,
        text: String,
        ack: Packet,
    },
    /// Verified ack for one of my packets, now `Delivered`.
    AckReceived {
        packet_id: PacketId,
    },
    /// Frame accepted, but the packet it announces is still incomplete.
    Partial,
    Duplicate,
    NotForUs,
    Expired,
    /// Packet for me but refused; its content is never shown.
    Quarantined {
        reason: String,
    },
    /// Synchronization coming from one of my devices, applied; its ack
    /// is in the send queue.
    Synced {
        kind: SyncKind,
    },
    /// New card from a contact (new device list), applied;
    /// its ack is in the send queue.
    CardUpdated {
        from: Fingerprint,
        alias: Option<String>,
    },
}

impl fmt::Debug for ReceiveOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Message {
                from, alias, text, ..
            } => f
                .debug_struct("Message")
                .field("from", from)
                .field("alias", alias)
                .field("text", &format_args!("<{} bytes>", text.len()))
                .finish_non_exhaustive(),
            Self::AckReceived { packet_id } => f
                .debug_struct("AckReceived")
                .field("packet_id", packet_id)
                .finish(),
            Self::Partial => f.write_str("Partial"),
            Self::Duplicate => f.write_str("Duplicate"),
            Self::NotForUs => f.write_str("NotForUs"),
            Self::Expired => f.write_str("Expired"),
            Self::Quarantined { reason } => f
                .debug_struct("Quarantined")
                .field("reason", reason)
                .finish(),
            Self::Synced { kind } => f.debug_struct("Synced").field("kind", kind).finish(),
            Self::CardUpdated { from, alias } => f
                .debug_struct("CardUpdated")
                .field("from", from)
                .field("alias", alias)
                .finish(),
        }
    }
}

/// Messaging core for one device.
pub struct Core {
    store: Store,
    /// Absent on a non-admin device.
    root: Option<RootIdentity>,
    device: DeviceKeys,
    prekeys: PrekeySecrets,
    /// My signed device list (the most recent one I know).
    devices: DeviceList,
    /// Key packets of my other devices (`link_device` on
    /// the admin, link packet on a linked device).
    linked_bundles: Vec<PrekeyBundle>,
    /// Awaiting link (`begin_link` without `finish_link`): `devices`
    /// is then a dummy list (see `link.rs`) and any operation that
    /// requires a linked device returns `CoreError::LinkPending`.
    pending: bool,
    /// Frames received for a still-incomplete packet (in memory, not persisted).
    frames: Reassembler,
    /// Grouping of noisy events in the log (rejected frames,
    /// undecryptable packets, duplicates), in memory.
    log_limiter: LogLimiter,
}

impl fmt::Debug for Core {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Core")
            .field("fingerprint", &self.fingerprint().to_string())
            .field("device", &self.device.public().id())
            .field("admin", &self.root.is_some())
            .field("pending", &self.pending)
            .finish_non_exhaustive()
    }
}

/// One of my devices (`Core::my_devices`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MyDevice {
    pub name: String,
    /// Certificate date (Unix seconds).
    pub issued_at: u64,
    pub this_device: bool,
    pub admin: bool,
}

impl Core {
    /// New identity: root, recovery phrase, device, initial list
    /// (version `max(1, now)`).
    pub fn create(
        path: &Path,
        db_key: &[u8; 32],
        device_name: &str,
        now: u64,
        rng: &mut impl CryptoRng,
    ) -> Result<(Core, RecoveryPhrase)> {
        let store = Store::open(path, db_key)?;
        ensure_empty(&store)?;
        let (root, phrase) = RootIdentity::generate(rng);
        let core = Self::init(store, root, device_name, now, rng)?;
        Ok((core, phrase))
    }

    /// New device for an existing identity, from its phrase.
    /// Contacts are not restored (v0). The device list is
    /// signed with version `max(1, now)`: it replaces, on contacts,
    /// the list of the lost device (signed earlier).
    pub fn recover(
        path: &Path,
        db_key: &[u8; 32],
        phrase: &str,
        device_name: &str,
        now: u64,
        rng: &mut impl CryptoRng,
    ) -> Result<Core> {
        let root = RootIdentity::from_phrase(phrase)?;
        let store = Store::open(path, db_key)?;
        ensure_empty(&store)?;
        Self::init(store, root, device_name, now, rng)
    }

    fn init(
        mut store: Store,
        root: RootIdentity,
        device_name: &str,
        now: u64,
        rng: &mut impl CryptoRng,
    ) -> Result<Core> {
        let device = DeviceKeys::generate(rng);
        // No one-time key: cards are public and reused.
        let prekeys = PrekeySecrets::generate(rng, 0);
        let cert = DeviceCertificate::issue(&root, &device, device_name, now)?;
        // Version = timestamp (at least 1): a later recovery
        // replaces the contacts' known list, `link_device` stays monotonic.
        let devices = DeviceList::sign(&root, now.max(1), vec![cert])?;
        let linked_bundles: Vec<PrekeyBundle> = Vec::new();
        store.transaction(|tx| {
            tx.put_meta(META_ROOT, &*root.to_seed())?;
            let dev = Zeroizing::new(device.to_bytes().to_vec());
            tx.put_meta(META_DEVICE, &*dev)?;
            tx.put_meta(META_DEVICE_NAME, &device_name)?;
            tx.put_meta(META_PREKEYS, &prekeys)?;
            tx.put_meta(META_DEVICE_LIST, &devices)?;
            tx.put_meta(META_LINKED_BUNDLES, &linked_bundles)
        })?;
        Ok(Core::assemble(
            store,
            Some(root),
            device,
            prekeys,
            devices,
            linked_bundles,
            false,
        ))
    }

    fn assemble(
        store: Store,
        root: Option<RootIdentity>,
        device: DeviceKeys,
        prekeys: PrekeySecrets,
        devices: DeviceList,
        linked_bundles: Vec<PrekeyBundle>,
        pending: bool,
    ) -> Core {
        Core {
            store,
            root,
            device,
            prekeys,
            devices,
            linked_bundles,
            pending,
            frames: Reassembler::new(MAX_PENDING_FRAMES, FRAME_TTL_SECS),
            log_limiter: LogLimiter::default(),
        }
    }

    /// Reopens an existing database. Wrong key: `StoreLocked`. Skipped keys
    /// older than 7 days at `now` are purged (irreversible, including a `now`
    /// very far in the future, as in decryption).
    pub fn open(path: &Path, db_key: &[u8; 32], now: u64) -> Result<Core> {
        // Do not create an empty database when trying to open one.
        if !path.exists() {
            return Err(CoreError::Store("database missing".into()));
        }
        let mut store = Store::open(path, db_key)?;
        let dev = Zeroizing::new(
            store
                .get_meta::<Vec<u8>>(META_DEVICE)?
                .ok_or_else(|| CoreError::Store("database not initialized".into()))?,
        );
        let mut dev_bytes = Zeroizing::new([0u8; 64]);
        if dev.len() != 64 {
            return Err(CoreError::Store("corrupted device keys".into()));
        }
        dev_bytes.copy_from_slice(&dev);
        let device = DeviceKeys::from_bytes(&dev_bytes);
        let root = store
            .get_meta::<[u8; 32]>(META_ROOT)?
            .map(|seed| RootIdentity::from_seed(&Zeroizing::new(seed)));
        let prekeys = store
            .get_meta::<PrekeySecrets>(META_PREKEYS)?
            .ok_or_else(|| CoreError::Store("key packets missing".into()))?;
        // Device awaiting link: no signed list yet.
        let pending_root = link::pending_root(&store)?;
        let devices = match pending_root {
            Some(root) => link::pending_devices(root),
            None => store
                .get_meta::<DeviceList>(META_DEVICE_LIST)?
                .ok_or_else(|| CoreError::Store("device list missing".into()))?,
        };
        let linked_bundles = store
            .get_meta::<Vec<PrekeyBundle>>(META_LINKED_BUNDLES)?
            .unwrap_or_default();
        store.transaction(|tx| {
            link::purge_expired_offer(tx, now)?;
            sweep_skipped(tx, now)
        })?;
        Ok(Core::assemble(
            store,
            root,
            device,
            prekeys,
            devices,
            linked_bundles,
            pending_root.is_some(),
        ))
    }

    /// Rereads my device list and the key packets of my other
    /// devices from the database (after a `SyncDevices`, or a link
    /// refused because another opening of the database changed the list).
    fn reload_own_devices(&mut self) -> Result<()> {
        if let Some(own) = OwnDevices::read(&self.store)? {
            self.devices = own.list;
            self.linked_bundles = own.bundles;
        }
        Ok(())
    }

    /// Fingerprint of my identity (root).
    pub fn fingerprint(&self) -> Fingerprint {
        self.devices.root.fingerprint()
    }

    /// My devices, from the signed device list. Only this device is known to
    /// hold the root (`admin`): other devices may, without the list saying so.
    pub fn my_devices(&self) -> Vec<MyDevice> {
        let me = self.device.public().id();
        self.devices
            .certs
            .iter()
            .map(|c| {
                let this_device = c.device.id() == me;
                MyDevice {
                    name: c.name.clone(),
                    issued_at: c.issued_at,
                    this_device,
                    admin: this_device && self.root.is_some(),
                }
            })
            .collect()
    }

    /// My signed contact card: device list and one key packet per
    /// device. `display_name` is recorded as my display name (reused
    /// by the cards the core signs itself, see `set_display_name`).
    pub fn contact_card(&self, display_name: &str) -> Result<ContactCard> {
        self.ensure_linked()?;
        let root = self.root.as_ref().ok_or(CoreError::NotAdmin)?;
        let mut bundles = vec![self.prekeys.bundle(&self.device, false)];
        bundles.extend(
            self.linked_bundles
                .iter()
                .filter(|b| self.devices.certs.iter().any(|c| c.device == b.device))
                .cloned(),
        );
        let nodes = self
            .store
            .get_meta::<Vec<Vec<u8>>>(META_CARD_NODES)?
            .unwrap_or_default();
        let card = ContactCard::sign(root, display_name, self.devices.clone(), bundles, nodes)?;
        if self.store.get_meta::<String>(META_DISPLAY_NAME)?.as_deref() != Some(display_name) {
            self.store.put_meta(META_DISPLAY_NAME, &display_name)?;
        }
        Ok(card)
    }

    /// Sets the node hints carried by my contact card (opaque to the core:
    /// at most `MAX_CARD_NODES` of at most `MAX_NODE_HINT_BYTES` bytes
    /// each, otherwise `TooLarge`). They appear in the next card signed.
    pub fn set_card_nodes(&mut self, nodes: Vec<Vec<u8>>) -> Result<()> {
        crate::contact::check_nodes(&nodes)?;
        self.store.put_meta(META_CARD_NODES, &nodes)
    }

    /// Node hints carried by the cards of all my contacts, without
    /// duplicates. A stored card that cannot be read is skipped.
    pub fn contact_node_hints(&self) -> Result<Vec<Vec<u8>>> {
        let mut out: Vec<Vec<u8>> = Vec::new();
        for row in self.store.list_contacts()? {
            let Ok(card) = load_card(&row.card) else {
                continue;
            };
            for n in card.nodes {
                if !out.contains(&n) {
                    out.push(n);
                }
            }
        }
        Ok(out)
    }

    /// Changes my display name, carried by the cards the core signs
    /// itself (link packet, card update sent to
    /// contacts). More than 64 bytes: `TooLarge`.
    pub fn set_display_name(&mut self, name: &str) -> Result<()> {
        if name.len() > crate::identity::device::MAX_NAME_LEN {
            return Err(CoreError::TooLarge);
        }
        self.store.put_meta(META_DISPLAY_NAME, &name)
    }

    /// Mailboxes to poll: this device's introduction mailbox
    /// and those of each session (from the last poll to the next day, 9 days
    /// at most; the day before, the day and the next day when no poll is recorded), plus the mailbox of
    /// each of my messages awaiting an ack, where the ack will arrive.
    /// Union of the two groups of `watched_mailbox_groups`, introduction
    /// first.
    ///
    /// A storage read error is returned: a partial list would let the
    /// caller poll, then `mark_polled`, past unread session mailboxes.
    pub fn watched_mailboxes(&self, now: u64) -> Result<Vec<MailboxId>> {
        let g = self.watched_mailbox_groups(now)?;
        let mut out = g.intro;
        for m in g.sessions {
            if !out.contains(&m) {
                out.push(m);
            }
        }
        Ok(out)
    }

    /// Mailboxes to poll, by class (see `WatchedMailboxes`). An expected-ack
    /// mailbox is a session mailbox if it is the send mailbox of one of
    /// my sessions (over the receive window), otherwise an introduction mailbox
    /// (first contact). A storage read error is returned (see
    /// `watched_mailboxes`).
    pub fn watched_mailbox_groups(&self, now: u64) -> Result<WatchedMailboxes> {
        let mut g = WatchedMailboxes::default();
        // Awaiting link: nothing to poll (`receive` would refuse).
        if self.pending {
            return Ok(g);
        }
        let me = self.device.public();
        let my_id = me.id();
        let days = self.watched_days(now);
        let push = |v: &mut Vec<MailboxId>, m: MailboxId| {
            if !v.contains(&m) {
                v.push(m);
            }
        };
        for &d in &days {
            push(&mut g.intro, intro_mailbox(&me, d));
        }
        let sessions = self.store.all_sessions()?;
        for s in &sessions {
            for &d in &days {
                push(
                    &mut g.sessions,
                    session_mailbox(&s.mailbox_secret, &my_id, d),
                );
            }
        }
        let pending = self.store.outbox_pending(now)?;
        // Send mailboxes of my sessions, over the whole window in which a
        // queued packet may have been sealed.
        let first = day_of(now.saturating_sub(MAX_AGE_SECS));
        let last = day_of(now).saturating_add(1);
        let mut sent: Vec<MailboxId> = Vec::new();
        let mut sent_ready = false;
        for (_, bytes) in pending {
            let Ok(p) = Packet::decode(&bytes) else {
                continue;
            };
            if p.kind != Kind::Message {
                continue;
            }
            if !sent_ready {
                for s in &sessions {
                    for d in first..=last {
                        sent.push(session_mailbox(&s.mailbox_secret, &s.contact_device, d));
                    }
                }
                sent_ready = true;
            }
            if sent.contains(&p.mailbox) {
                push(&mut g.sessions, p.mailbox);
            } else {
                push(&mut g.intro, p.mailbox);
            }
        }
        // A mailbox is in one group only: the sessions group takes precedence.
        g.intro.retain(|m| !g.sessions.contains(m));
        Ok(g)
    }

    /// My own mailboxes (introduction and one per session, me as recipient)
    /// for each of `days`, as `(mailbox, day)` in the order of `days`, without
    /// duplicates. Unlike `watched_mailbox_groups` it leaves out the
    /// mailboxes where I await an ack. Empty while awaiting the link. A
    /// storage read error is returned.
    pub fn own_mailboxes(&self, days: &[u32]) -> Result<Vec<(MailboxId, u32)>> {
        if self.pending {
            return Ok(Vec::new());
        }
        let me = self.device.public();
        let my_id = me.id();
        let sessions = self.store.all_sessions()?;
        let mut out: Vec<(MailboxId, u32)> = Vec::new();
        let mut push = |m: MailboxId, d: u32| {
            if !out.iter().any(|(x, _)| *x == m) {
                out.push((m, d));
            }
        };
        for &d in days {
            push(intro_mailbox(&me, d), d);
            for s in &sessions {
                push(session_mailbox(&s.mailbox_secret, &my_id, d), d);
            }
        }
        Ok(out)
    }

    /// My introduction mailboxes for each of `days`, in that order: the
    /// part of `own_mailboxes` anyone can write to. Empty while awaiting
    /// the link.
    pub fn own_intro_mailboxes(&self, days: &[u32]) -> Vec<MailboxId> {
        if self.pending {
            return Vec::new();
        }
        let me = self.device.public();
        let mut out: Vec<MailboxId> = Vec::new();
        for &d in days {
            let m = intro_mailbox(&me, d);
            if !out.contains(&m) {
                out.push(m);
            }
        }
        out
    }

    /// Records that the mailboxes were polled at `now`. To be called after
    /// polling all mailboxes successfully; deliberately overwrites the
    /// previous value (an earlier value only widens the window).
    pub fn mark_polled(&mut self, now: u64) -> Result<()> {
        self.store.put_meta(META_LAST_POLLED, &day_of(now))
    }

    /// Days to poll: from the last poll (or the day before) to the next day,
    /// 9 days at most. A failed read or a poll dated in the future
    /// (clock set back) falls back to the normal window.
    fn watched_days(&self, now: u64) -> Vec<u32> {
        let today = day_of(now);
        let end = today.saturating_add(1);
        let normal = today.saturating_sub(1);
        let start = match self.store.get_meta::<u32>(META_LAST_POLLED) {
            Ok(Some(last)) if last <= end => last.min(normal),
            _ => normal,
        };
        let start = start.max(today.saturating_sub(MAX_POLL_BACK_DAYS));
        (start..=end).collect()
    }

    /// Security code to compare with the contact.
    pub fn safety_number(&self, contact: &Fingerprint) -> Result<String> {
        self.store
            .get_contact(*contact)?
            .ok_or(CoreError::UnknownContact)?;
        Ok(safety_number(&self.fingerprint(), contact))
    }

    /// The `limit` most recent events, from oldest to newest.
    pub fn transparency_log(&self, limit: usize) -> Result<Vec<(u64, TransparencyEvent)>> {
        self.store
            .recent_events(limit)?
            .into_iter()
            .map(|(at, bytes)| {
                postcard::from_bytes(&bytes)
                    .map(|e| (at, e))
                    .map_err(|_| CoreError::Store("unreadable event".into()))
            })
            .collect()
    }

    /// Purges expired packets from the send queue then returns the bytes to
    /// (re)transmit, from oldest to newest. A packet stays there
    /// until its receipt ack or its expiry.
    pub fn pending_outbox(&mut self, now: u64) -> Result<Vec<Vec<u8>>> {
        self.store.transaction(|tx| {
            tx.outbox_purge_expired(now)?;
            sweep_skipped(tx, now)?;
            Ok(tx
                .outbox_pending(now)?
                .into_iter()
                .map(|(_, bytes)| bytes)
                .collect())
        })
    }

    /// Opaque state of a transport (for example poll positions and deposits
    /// per node of the CLI), kept in the encrypted database under `transport/<key>`.
    /// `key`: 1 to 64 ASCII alphanumeric characters, `_` or `-`.
    pub fn transport_state(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.store.get_meta(&transport_key(key)?)
    }

    /// Replaces a transport's state (at most `MAX_TRANSPORT_STATE` bytes).
    pub fn set_transport_state(&mut self, key: &str, bytes: &[u8]) -> Result<()> {
        if bytes.len() > MAX_TRANSPORT_STATE {
            return Err(CoreError::TooLarge);
        }
        self.store.put_meta(&transport_key(key)?, &bytes)
    }

    /// Logs a transport event (deposit or poll on a node):
    /// only `NodeDeposit`, `NodeFetch` and `NodeAvoided` are accepted.
    pub fn log_transport_event(&mut self, event: TransparencyEvent, now: u64) -> Result<()> {
        if !matches!(
            event,
            TransparencyEvent::NodeDeposit { .. }
                | TransparencyEvent::NodeFetch { .. }
                | TransparencyEvent::NodeAvoided { .. }
        ) {
            return Err(CoreError::Malformed("transport event"));
        }
        log(&self.store, now, None, &event)
    }

    /// History with a contact, from oldest to newest.
    pub fn messages_with(&self, contact: &Fingerprint) -> Result<Vec<MessageRow>> {
        self.store.messages_with(*contact)
    }
}

/// Purges too-old skipped keys from all sessions, even
/// inactive ones; rewrites only the modified sessions. An unreadable session
/// is ignored (it must not block opening). A `now` very far
/// in the future purges keys irreversibly, exactly like
/// decryption.
fn sweep_skipped(q: &impl Queries, now: u64) -> Result<()> {
    for mut row in q.all_sessions()? {
        let Ok(mut state) = de_state(&row.state) else {
            continue;
        };
        if state.purge_skipped(now) {
            let new = ser_state(&state)?;
            // The old serialized state contains the purged keys.
            let mut old = std::mem::replace(&mut row.state, new);
            old.zeroize();
            q.put_session(&row)?;
        }
    }
    Ok(())
}

/// Refuses to overwrite an already initialized database.
fn ensure_empty(store: &Store) -> Result<()> {
    if store.get_meta::<Vec<u8>>(META_DEVICE)?.is_some() {
        return Err(CoreError::Store("database already initialized".into()));
    }
    Ok(())
}

/// Session identifier: `BLAKE3(ek)[..16]`, where `ek` is the ephemeral PQXDH
/// key of the initial message (never the packet's sealing ephemeral).
fn session_id(ek: &[u8; 32]) -> [u8; 16] {
    let mut id = [0u8; 16];
    id.copy_from_slice(&blake3::hash(ek).as_bytes()[..16]);
    id
}

/// Ratchet associated data: `IK_A || IK_B` (PQXDH), then the
/// full identifiers of both devices (initiator, responder).
///
/// The proof of possession of a certificate covers only the signing key,
/// not the X25519 key: a card could pair its own signing key
/// with a third party's `dh` key. The device identifier hashes both keys;
/// binding it here makes any session fail whose two sides do not see
/// exactly the same devices.
fn session_ad(pqxdh_ad: &[u8], initiator: &DeviceId, responder: &DeviceId) -> Vec<u8> {
    let mut ad = Vec::with_capacity(pqxdh_ad.len() + 32);
    ad.extend_from_slice(pqxdh_ad);
    ad.extend_from_slice(&initiator.0);
    ad.extend_from_slice(&responder.0);
    ad
}

fn log(
    q: &impl Queries,
    at: u64,
    packet: Option<PacketId>,
    event: &TransparencyEvent,
) -> Result<()> {
    let bytes = postcard::to_allocvec(event).map_err(|_| CoreError::Store("event".into()))?;
    let class = if event.is_security() {
        EventClass::Security
    } else {
        EventClass::Routine
    };
    q.append_event(at, packet, class, &bytes)
}

/// My devices as stored: my signed list and the key packets
/// of my other devices. Same source on the admin (`link_device`)
/// and on a linked device (`finish_link`); absent while a link is
/// pending.
pub(super) struct OwnDevices {
    pub list: DeviceList,
    pub bundles: Vec<PrekeyBundle>,
}

impl OwnDevices {
    pub fn read(q: &impl Queries) -> Result<Option<OwnDevices>> {
        let Some(list) = q.get_meta::<DeviceList>(META_DEVICE_LIST)? else {
            return Ok(None);
        };
        let bundles = q
            .get_meta::<Vec<PrekeyBundle>>(META_LINKED_BUNDLES)?
            .unwrap_or_default();
        Ok(Some(OwnDevices { list, bundles }))
    }

    /// My other devices (all except `me`), with their key packet if known.
    pub fn others(&self, me: &DevicePublic) -> Vec<(DevicePublic, Option<PrekeyBundle>)> {
        self.list
            .certs
            .iter()
            .filter(|c| c.device != *me)
            .map(|c| {
                let bundle = self.bundles.iter().find(|b| b.device == c.device).cloned();
                (c.device, bundle)
            })
            .collect()
    }
}

fn load_card(bytes: &[u8]) -> Result<ContactCard> {
    ContactCard::decode(bytes).map_err(|_| CoreError::Store("unreadable stored card".into()))
}

fn ser_state(state: &RatchetState) -> Result<Vec<u8>> {
    postcard::to_allocvec(state).map_err(|_| CoreError::Store("serialization".into()))
}

fn de_state(bytes: &[u8]) -> Result<RatchetState> {
    postcard::from_bytes(bytes).map_err(|_| CoreError::Store("corrupted session".into()))
}

fn ser_init(init: &InitialMessage) -> Result<Vec<u8>> {
    postcard::to_allocvec(init).map_err(|_| CoreError::Store("serialization".into()))
}

fn de_init(bytes: &[u8]) -> Result<InitialMessage> {
    postcard::from_bytes(bytes).map_err(|_| CoreError::Store("corrupted session".into()))
}
