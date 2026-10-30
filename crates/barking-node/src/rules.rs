//! Règles du nœud (spec §4.3, §5) : fonctions sans réseau.
//!
//! Choix documentés :
//! - « taille ≠ palier » : le paquet encodé doit faire exactement `Tier::size()`
//!   (c'est aussi ce que vérifie `Packet::decode`). Si l'octet de palier est
//!   valide mais la longueur reçue ne correspond pas, la raison est `WrongTier` ;
//!   tout autre défaut de forme donne `Malformed`.
//! - Déduplication par (identifiant, BLAKE3 des octets sans `hops`) : même
//!   contenu = sans effet ; contenu différent sous le même identifiant = gardé à
//!   côté (compte dans les quotas), pour qu'un identifiant ne puisse être squatté.
//! - Un accusé est un paquet de palier S à charge de 32 octets, dans la boîte du
//!   paquet accusé (sinon `UnknownAckTarget`). Il supprime toutes les lignes de
//!   cet identifiant et est rangé dans chaque boîte distincte qui en tenait une
//!   ligne (une ligne d'accusé par (identifiant, boîte)) ; il reste gardé jusqu'à `max(expiration de l'accusé,
//!   expiration des paquets supprimés)` : le message ne ressuscite pas, ni par
//!   redépôt ni par accusé raccourci.
//! - Preuve de travail progressive par boîte : voir `required_pow_bits`.
//! - Curseur de `fetch` : `seq` (AUTOINCREMENT, jamais réutilisé) des paquets,
//!   puis `ACK_BASE + seq` des accusés.

use barking_packet::{Kind, MailboxId, OVERHEAD, Packet, PacketId, Tier, ack};
use barking_proto::{ErrorReason, pow};
use rusqlite::params;

use crate::Result;
use crate::store::{NodeStore, add_stored_bytes, stored_bytes};

/// Nombre de paquets par palier de difficulté supplémentaire.
const POW_STEP_PACKETS: i64 = 64;

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
        Kind::Ack => deposit_ack(store, policy, &packet, bytes),
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

fn pow_bits_for_count(policy: &Policy, count: i64) -> u8 {
    let steps = count / POW_STEP_PACKETS;
    let extra = if steps >= 1 { steps.ilog2() } else { 0 };
    let bits = u32::from(policy.pow_bits).saturating_add(extra);
    u8::try_from(bits.min(u32::from(pow::MAX_POW_BITS))).unwrap_or(pow::MAX_POW_BITS)
}

/// Difficulté exigée pour un dépôt dans `mailbox` :
/// `min(MAX_POW_BITS, pow_bits + floor(log2(max(1, n / 64))))`, `n` étant le
/// nombre de paquets déjà gardés dans cette boîte.
pub fn required_pow_bits(store: &NodeStore, policy: &Policy, mailbox: &MailboxId) -> Result<u8> {
    let count: i64 = store.conn().query_row(
        "SELECT COUNT(*) FROM packets WHERE mailbox=?1",
        params![&mailbox.0[..]],
        |r| r.get(0),
    )?;
    Ok(pow_bits_for_count(policy, count))
}

fn deposit_message(
    store: &mut NodeStore,
    policy: &Policy,
    p: &Packet,
    bytes: &[u8],
    nonce: u64,
    now: u64,
) -> Result<core::result::Result<(), ErrorReason>> {
    let hash = pow::content_hash(bytes);
    let tx = store.conn_mut().transaction()?;
    // Déjà accusé, ou même contenu déjà gardé : sans effet.
    let known: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM packets WHERE id=?1 AND hash=?2) OR EXISTS(SELECT 1 FROM acks WHERE packet_id=?1)",
        params![&p.id.0[..], &hash[..]],
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
    if !pow::check(&hash, &p.mailbox, nonce, pow_bits_for_count(policy, in_box)) {
        return Ok(Err(ErrorReason::PowTooWeak));
    }
    if in_box >= i64::from(policy.max_per_mailbox) {
        return Ok(Err(ErrorReason::MailboxFull));
    }
    let len = bytes.len() as u64;
    if stored_bytes(&tx)?.saturating_add(len) > policy.storage_max_bytes {
        return Ok(Err(ErrorReason::NodeFull));
    }
    tx.execute(
        "INSERT INTO packets(id,mailbox,kind,tier,expires_at,received_at,hash,bytes) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
        params![
            &p.id.0[..],
            &p.mailbox.0[..],
            p.kind as u8,
            p.tier as u8,
            i64::from(p.expires_at),
            i(now / 60 * 60),
            &hash[..],
            bytes
        ],
    )?;
    add_stored_bytes(&tx, i(len))?;
    tx.commit()?;
    Ok(Ok(()))
}

fn deposit_ack(
    store: &mut NodeStore,
    policy: &Policy,
    p: &Packet,
    bytes: &[u8],
) -> Result<core::result::Result<(), ErrorReason>> {
    // Palier S, charge : id du paquet accusé (16) || secret (16).
    if p.tier != Tier::S || p.payload.len() != 32 {
        return Ok(Err(ErrorReason::Malformed));
    }
    let mut t = [0u8; 16];
    let mut sec = [0u8; 16];
    t.copy_from_slice(&p.payload[..16]);
    sec.copy_from_slice(&p.payload[16..]);
    let target = PacketId(t);
    let tx = store.conn_mut().transaction()?;
    let known: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM acks WHERE packet_id=?1)",
        params![&target.0[..]],
        |r| r.get(0),
    )?;
    if known {
        return Ok(Ok(()));
    }
    // Lignes de cet identifiant : octets, expiration maximale, et boîtes
    // distinctes (l'accusé est rangé dans chacune).
    let (n, old_len, max_exp): (i64, i64, i64) = tx.query_row(
        "SELECT COUNT(*), COALESCE(SUM(length(bytes)),0), COALESCE(MAX(expires_at),0)
         FROM packets WHERE id=?1",
        params![&target.0[..]],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    let boxes: Vec<Vec<u8>> = {
        let mut st = tx.prepare("SELECT DISTINCT mailbox FROM packets WHERE id=?1")?;
        st.query_map(params![&target.0[..]], |r| r.get(0))?
            .collect::<core::result::Result<_, _>>()?
    };
    if n == 0 || !boxes.iter().any(|m| m[..] == p.mailbox.0) || !ack::verify(&target, &sec) {
        return Ok(Err(ErrorReason::UnknownAckTarget));
    }
    let delta = i(bytes.len() as u64) * i(boxes.len() as u64) - old_len;
    if delta > 0 && stored_bytes(&tx)?.saturating_add(delta as u64) > policy.storage_max_bytes {
        return Ok(Err(ErrorReason::NodeFull));
    }
    tx.execute("DELETE FROM packets WHERE id=?1", params![&target.0[..]])?;
    let keep = i64::from(p.expires_at).max(max_exp);
    for m in &boxes {
        tx.execute(
            "INSERT INTO acks(packet_id,mailbox,expires_at,bytes) VALUES(?1,?2,?3,?4)",
            params![&target.0[..], m, keep, bytes],
        )?;
    }
    add_stored_bytes(&tx, delta)?;
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

    'outer: for (table, key, base) in [("packets", "seq", 0u64), ("acks", "seq", ACK_BASE)] {
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
