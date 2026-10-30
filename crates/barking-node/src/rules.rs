//! Règles du nœud (spec §4.3, §5) : fonctions sans réseau.
//!
//! Choix documentés :
//! - « taille ≠ palier » : le paquet encodé doit faire exactement `Tier::size()`
//!   (c'est aussi ce que vérifie `Packet::decode`). Si l'octet de palier est
//!   valide mais la longueur reçue ne correspond pas, la raison est `WrongTier` ;
//!   tout autre défaut de forme donne `Malformed`.
//! - Un message dont un accusé a déjà été reçu est accepté sans effet (il ne
//!   ressuscite pas), comme un doublon.
//! - L'accusé est rangé dans la boîte portée par le paquet accusé (champ
//!   `mailbox` de l'accusé, fixé par le cœur à celle du message d'origine).
//! - Curseur de `fetch` : clé stable `rowid` des paquets, puis `ACK_BASE + rowid`
//!   des accusés. Un rowid libéré par la purge peut être réutilisé : un paquet
//!   très récent peut alors manquer à une pagination en cours, il est rendu à la
//!   relève suivante.

use barking_packet::{Kind, MailboxId, OVERHEAD, Packet, PacketId, Tier, ack};
use barking_proto::{ErrorReason, pow};
use rusqlite::{OptionalExtension, params};

use crate::Result;
use crate::store::{NodeStore, add_stored_bytes, stored_bytes};

/// Marge d'expiration : 7 jours + 1 h (tolérance d'horloge d'une heure).
pub const MAX_EXPIRY_SECS: u64 = 7 * 86_400 + 3_600;
/// Nombre maximal de boîtes par relève.
pub const MAX_MAILBOXES_PER_FETCH: usize = 64;
const ACK_BASE: u64 = 1 << 62;

#[derive(Debug, Clone, Copy)]
pub struct Policy {
    pub pow_bits: u8,
    pub max_per_mailbox: u32,
    pub storage_max_bytes: u64,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            pow_bits: pow::DEFAULT_POW_BITS,
            max_per_mailbox: 1_000,
            storage_max_bytes: 1 << 30,
        }
    }
}

fn i(n: u64) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

/// Valide et enregistre un dépôt. `Err` : stockage ; `Ok(Err(raison))` : refus.
pub fn deposit(
    store: &mut NodeStore,
    policy: &Policy,
    bytes: &[u8],
    pow_nonce: u64,
    now: u64,
) -> Result<core::result::Result<(), ErrorReason>> {
    // Palier valide mais longueur différente : WrongTier.
    if bytes.len() >= OVERHEAD
        && let Some(tier) = tier_from_byte(bytes[3])
        && bytes.len() != tier.size()
    {
        return Ok(Err(ErrorReason::WrongTier));
    }
    let Ok(packet) = Packet::decode(bytes) else {
        return Ok(Err(ErrorReason::Malformed));
    };
    let expires = u64::from(packet.expires_at);
    if expires <= now {
        return Ok(Err(ErrorReason::Expired));
    }
    if expires > now.saturating_add(MAX_EXPIRY_SECS) {
        return Ok(Err(ErrorReason::TooFarInFuture));
    }
    match packet.kind {
        Kind::Message => deposit_message(store, policy, &packet, bytes, pow_nonce, now),
        Kind::Ack => deposit_ack(store, &packet, bytes),
    }
}

fn tier_from_byte(b: u8) -> Option<Tier> {
    match b {
        0 => Some(Tier::S),
        1 => Some(Tier::M),
        2 => Some(Tier::L),
        _ => None,
    }
}

fn deposit_message(
    store: &mut NodeStore,
    policy: &Policy,
    p: &Packet,
    bytes: &[u8],
    nonce: u64,
    now: u64,
) -> Result<core::result::Result<(), ErrorReason>> {
    if !pow::check(&p.id, &p.mailbox, nonce, policy.pow_bits) {
        return Ok(Err(ErrorReason::PowTooWeak));
    }
    let tx = store.conn_mut().transaction()?;
    let known: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM packets WHERE id=?1) OR EXISTS(SELECT 1 FROM acks WHERE packet_id=?1)",
        params![&p.id.0[..]],
        |r| r.get(0),
    )?;
    if known {
        return Ok(Ok(()));
    }
    let in_box: i64 = tx.query_row(
        "SELECT COUNT(*) FROM packets WHERE mailbox=?1",
        params![&p.mailbox.0[..]],
        |r| r.get(0),
    )?;
    if in_box >= i64::from(policy.max_per_mailbox) {
        return Ok(Err(ErrorReason::MailboxFull));
    }
    let len = bytes.len() as u64;
    if stored_bytes(&tx)?.saturating_add(len) > policy.storage_max_bytes {
        return Ok(Err(ErrorReason::NodeFull));
    }
    tx.execute(
        "INSERT INTO packets(id,mailbox,kind,tier,expires_at,received_at,bytes) VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![
            &p.id.0[..],
            &p.mailbox.0[..],
            p.kind as u8,
            p.tier as u8,
            i64::from(p.expires_at),
            i(now / 60 * 60),
            bytes
        ],
    )?;
    add_stored_bytes(&tx, i(len))?;
    tx.commit()?;
    Ok(Ok(()))
}

fn deposit_ack(
    store: &mut NodeStore,
    p: &Packet,
    bytes: &[u8],
) -> Result<core::result::Result<(), ErrorReason>> {
    // Charge : id du paquet accusé (16) || secret (16).
    let Some((target, secret)) = (p.payload.len() == 32).then(|| {
        let mut t = [0u8; 16];
        let mut s = [0u8; 16];
        t.copy_from_slice(&p.payload[..16]);
        s.copy_from_slice(&p.payload[16..]);
        (PacketId(t), s)
    }) else {
        return Ok(Err(ErrorReason::Malformed));
    };
    let tx = store.conn_mut().transaction()?;
    let known: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM acks WHERE packet_id=?1)",
        params![&target.0[..]],
        |r| r.get(0),
    )?;
    if known {
        return Ok(Ok(()));
    }
    let stored: Option<i64> = tx
        .query_row(
            "SELECT length(bytes) FROM packets WHERE id=?1",
            params![&target.0[..]],
            |r| r.get(0),
        )
        .optional()?;
    let Some(old_len) = stored else {
        return Ok(Err(ErrorReason::UnknownAckTarget));
    };
    if !ack::verify(&target, &secret) {
        return Ok(Err(ErrorReason::UnknownAckTarget));
    }
    tx.execute("DELETE FROM packets WHERE id=?1", params![&target.0[..]])?;
    tx.execute(
        "INSERT INTO acks(packet_id,mailbox,expires_at,bytes) VALUES(?1,?2,?3,?4)",
        params![
            &target.0[..],
            &p.mailbox.0[..],
            i64::from(p.expires_at),
            bytes
        ],
    )?;
    add_stored_bytes(&tx, i(bytes.len() as u64) - old_len)?;
    tx.commit()?;
    Ok(Ok(()))
}

/// Une page de relève : (éléments, curseur suivant). Ne supprime rien.
pub type Page = (Vec<Vec<u8>>, Option<u64>);

/// Relève paginée : paquets puis accusés des `mailboxes`, dans un ordre stable.
/// La page ne dépasse `max_bytes` que si un seul élément est plus gros.
pub fn fetch(
    store: &NodeStore,
    mailboxes: &[MailboxId],
    cursor: Option<u64>,
    max_bytes: usize,
) -> Result<core::result::Result<Page, ErrorReason>> {
    if mailboxes.len() > MAX_MAILBOXES_PER_FETCH {
        return Ok(Err(ErrorReason::TooManyMailboxes));
    }
    if mailboxes.is_empty() {
        return Ok(Ok((Vec::new(), None)));
    }
    let after = cursor.unwrap_or(0);
    let marks = vec!["?"; mailboxes.len()].join(",");
    let mut page: Vec<Vec<u8>> = Vec::new();
    let mut used = 0usize;
    let mut last: Option<u64> = None;
    let mut more = false;

    'outer: for (table, key, base) in [("packets", "rowid", 0u64), ("acks", "rowid", ACK_BASE)] {
        // Position de reprise dans cette table (0 = depuis le début).
        let start = after.saturating_sub(base);
        if table == "packets" && after >= ACK_BASE {
            continue;
        }
        let sql = format!(
            "SELECT {key}, bytes FROM {table} WHERE mailbox IN ({marks}) AND {key} > ? ORDER BY {key}"
        );
        let mut stmt = store.conn().prepare(&sql)?;
        let mut args: Vec<rusqlite::types::Value> = mailboxes
            .iter()
            .map(|m| rusqlite::types::Value::Blob(m.0.to_vec()))
            .collect();
        args.push(rusqlite::types::Value::Integer(i(start)));
        let mut rows = stmt.query(rusqlite::params_from_iter(args))?;
        while let Some(row) = rows.next()? {
            let rowid: i64 = row.get(0)?;
            let data: Vec<u8> = row.get(1)?;
            if !page.is_empty() && used + data.len() > max_bytes {
                more = true;
                break 'outer;
            }
            used += data.len();
            last = Some(base + u64::try_from(rowid).unwrap_or(0));
            page.push(data);
        }
    }
    Ok(Ok((page, if more { last } else { None })))
}

#[cfg(test)]
mod tests;
