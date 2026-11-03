//! Wake subscriptions (network-free part): a client leaves a sealed push
//! token on the node that holds its mailbox. The first message arriving in
//! that mailbox marks the subscription; a sender task (not in this module)
//! takes the due wake-ups, at most one per minute and per subscription.
//! The node never sees the APNs token, only the relay can open `sealed`.

use barking_packet::MailboxId;
use barking_proto::msg::ErrorReason;
use barking_proto::pow;
use barking_proto::push::{MAX_SEALED, RelayRef, Subscription, cancel_hash, subscription_hash};
use rusqlite::{OptionalExtension, params};
use serde::Deserialize;

use crate::{NodeStore, Result};

pub mod sender;
#[cfg(test)]
mod tests;

/// Subscriptions kept per mailbox.
pub const MAX_SUBS_PER_MAILBOX: i64 = 4;
/// A subscription may expire at most this many days after the current day.
pub const MAX_EXPIRY_DAYS: u32 = 8;
/// Minimum delay between two wake-ups of the same subscription.
pub const WAKE_INTERVAL_SECS: u64 = 60;

const DAY_SECS: u64 = 86_400;

/// `[wake]` section of the node configuration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WakeConfig {
    /// Accept subscriptions (and send wake-ups).
    pub enabled: bool,
    /// Global cap on stored subscriptions.
    pub max_subscriptions: u64,
}

impl Default for WakeConfig {
    fn default() -> Self {
        WakeConfig {
            enabled: true,
            max_subscriptions: 1_000_000,
        }
    }
}

/// A wake-up to send: where, and the sealed token to hand over.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WakeOrder {
    pub relay: RelayRef,
    pub sealed: Vec<u8>,
}

/// Day number of a Unix time (days since the epoch).
pub(crate) fn day_of(now: u64) -> u32 {
    u32::try_from(now / DAY_SECS).unwrap_or(u32::MAX)
}

fn int(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

/// Checks a subscription without touching the database: enabled, shape, day
/// bounds and proof of work. `subscribe` runs it again, authoritatively.
pub(crate) fn precheck(
    cfg: &WakeConfig,
    base_bits: u8,
    sub: &Subscription,
    pow_nonce: u64,
    now: u64,
) -> core::result::Result<(), ErrorReason> {
    if !cfg.enabled {
        return Err(ErrorReason::Unsupported);
    }
    if sub.sealed.is_empty() || sub.sealed.len() > MAX_SEALED || !sub.relay.well_formed() {
        return Err(ErrorReason::Malformed);
    }
    let today = day_of(now);
    if sub.expires_day < today {
        return Err(ErrorReason::Expired);
    }
    if sub.expires_day > today.saturating_add(MAX_EXPIRY_DAYS) {
        return Err(ErrorReason::TooFarInFuture);
    }
    if !pow::check(&subscription_hash(sub), &sub.mailbox, pow_nonce, base_bits) {
        return Err(ErrorReason::PowTooWeak);
    }
    Ok(())
}

/// Stores (or replaces) a subscription. `Ok(Err(reason))`: refusal.
pub fn subscribe(
    store: &mut NodeStore,
    cfg: &WakeConfig,
    base_bits: u8,
    sub: &Subscription,
    pow_nonce: u64,
    now: u64,
) -> Result<core::result::Result<(), ErrorReason>> {
    if let Err(r) = precheck(cfg, base_bits, sub, pow_nonce, now) {
        return Ok(Err(r));
    }
    let relay = postcard::to_allocvec(&sub.relay).expect("a relay reference always encodes");
    let tx = store.conn_mut().savepoint()?;
    let exists: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM subscriptions WHERE mailbox=?1 AND cancel_hash=?2)",
        params![&sub.mailbox.0[..], &sub.cancel_hash[..]],
        |r| r.get(0),
    )?;
    if exists {
        // Replacement: refreshes the relay, the token and the expiry; the
        // wake-up state is kept.
        tx.execute(
            "UPDATE subscriptions SET relay=?3, sealed=?4, expires_day=?5
             WHERE mailbox=?1 AND cancel_hash=?2",
            params![
                &sub.mailbox.0[..],
                &sub.cancel_hash[..],
                relay,
                &sub.sealed[..],
                i64::from(sub.expires_day)
            ],
        )?;
    } else {
        let in_box: i64 = tx.query_row(
            "SELECT COUNT(*) FROM subscriptions WHERE mailbox=?1",
            params![&sub.mailbox.0[..]],
            |r| r.get(0),
        )?;
        if in_box >= MAX_SUBS_PER_MAILBOX {
            return Ok(Err(ErrorReason::MailboxFull));
        }
        let total: i64 = tx.query_row("SELECT COUNT(*) FROM subscriptions", [], |r| r.get(0))?;
        if total >= int(cfg.max_subscriptions) {
            return Ok(Err(ErrorReason::NodeFull));
        }
        tx.execute(
            "INSERT INTO subscriptions(mailbox,relay,sealed,cancel_hash,expires_day)
             VALUES(?1,?2,?3,?4,?5)",
            params![
                &sub.mailbox.0[..],
                relay,
                &sub.sealed[..],
                &sub.cancel_hash[..],
                i64::from(sub.expires_day)
            ],
        )?;
    }
    tx.commit()?;
    Ok(Ok(()))
}

/// Removes the subscription whose `cancel_hash` is the hash of the secret.
/// Silent: the same outcome whether or not a row was removed.
pub fn unsubscribe(
    store: &mut NodeStore,
    mailbox: &MailboxId,
    cancel_secret: &[u8; 32],
) -> Result<()> {
    store.conn().execute(
        "DELETE FROM subscriptions WHERE mailbox=?1 AND cancel_hash=?2",
        params![&mailbox.0[..], &cancel_hash(cancel_secret)[..]],
    )?;
    Ok(())
}

/// Marks the unexpired subscriptions of `mailbox` as pending. Called by
/// `deposit_message` right after the packet insert, in the same transaction:
/// never for a known packet nor for an ack.
pub(crate) fn mark_new_message(
    tx: &rusqlite::Connection,
    mailbox: &MailboxId,
    now: u64,
) -> rusqlite::Result<()> {
    tx.execute(
        "UPDATE subscriptions SET pending=1 WHERE mailbox=?1 AND expires_day>=?2",
        params![&mailbox.0[..], i64::from(day_of(now))],
    )?;
    Ok(())
}

/// Takes at most `max` pending subscriptions not woken during the last
/// minute, and records the wake-up (`pending = 0`, `last_wake = now`). A row
/// whose relay no longer decodes is deleted.
pub fn take_due(store: &mut NodeStore, now: u64, max: usize) -> Result<Vec<WakeOrder>> {
    let limit = int(now.saturating_sub(WAKE_INTERVAL_SECS));
    let tx = store.conn_mut().savepoint()?;
    let rows: Vec<(i64, Vec<u8>, Vec<u8>)> = {
        let mut st = tx.prepare(
            "SELECT rowid, relay, sealed FROM subscriptions
             WHERE pending=1 AND last_wake<=?1 ORDER BY last_wake, rowid LIMIT ?2",
        )?;
        st.query_map(params![limit, int(max as u64)], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })?
        .collect::<core::result::Result<_, _>>()?
    };
    let mut orders = Vec::with_capacity(rows.len());
    for (rowid, relay, sealed) in rows {
        match postcard::from_bytes::<RelayRef>(&relay) {
            Ok(relay) => {
                tx.execute(
                    "UPDATE subscriptions SET pending=0, last_wake=?2 WHERE rowid=?1",
                    params![rowid, int(now)],
                )?;
                orders.push(WakeOrder { relay, sealed });
            }
            Err(_) => {
                tx.execute("DELETE FROM subscriptions WHERE rowid=?1", params![rowid])?;
            }
        }
    }
    tx.commit()?;
    Ok(orders)
}

/// True if the node holds at least one subscription (expired ones included).
pub fn has_subscriptions(store: &NodeStore) -> Result<bool> {
    Ok(store
        .conn()
        .query_row("SELECT EXISTS(SELECT 1 FROM subscriptions)", [], |r| {
            r.get::<_, bool>(0)
        })?)
}

/// Tells the wake loop that a message arrived, only once the node holds (or
/// is taking) a subscription: a node without any skips the loop's database
/// round on every stored packet. Armed at startup if the database holds
/// subscriptions, and by each `Subscribe` before its write, so that a row
/// marked pending always finds the signal armed. Never disarmed.
pub(crate) struct WakeSignal {
    armed: std::sync::atomic::AtomicBool,
    notify: tokio::sync::Notify,
}

impl WakeSignal {
    pub(crate) fn new(armed: bool) -> WakeSignal {
        WakeSignal {
            armed: std::sync::atomic::AtomicBool::new(armed),
            notify: tokio::sync::Notify::new(),
        }
    }

    pub(crate) fn arm(&self) {
        self.armed.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// A new message was stored (`Deposit` or `Store`).
    pub(crate) fn message_arrived(&self) {
        if self.armed.load(std::sync::atomic::Ordering::SeqCst) {
            self.notify.notify_one();
        }
    }

    pub(crate) async fn notified(&self) {
        self.notify.notified().await;
    }
}

/// Earliest time a pending subscription becomes due.
pub fn next_due(store: &NodeStore) -> Result<Option<u64>> {
    let t: Option<i64> = store
        .conn()
        .query_row(
            "SELECT MIN(last_wake) FROM subscriptions WHERE pending=1",
            [],
            |r| r.get(0),
        )
        .optional()?
        .flatten();
    Ok(t.map(|t| u64::try_from(t).unwrap_or(0) + WAKE_INTERVAL_SECS))
}
