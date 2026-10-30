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
//! - Preuve de travail progressive : par boîte, par palier et selon le
//!   remplissage global, voir `pow_bits_for`. `precheck` vérifie forme,
//!   expiration et preuve au minimum (base + palier) sans la base de données.
//! - Recopie entre nœuds (spec §5.2) : mêmes règles de forme, d'accusé, de
//!   quotas et de déduplication que `deposit`, mais la preuve exigée est la
//!   base du nœud (`pow_bits` + palier), sans le supplément progressif ; le
//!   nonce reçu est gardé pour pouvoir recopier à son tour.
//! - Curseur de `fetch` : `seq` (AUTOINCREMENT, jamais réutilisé) des paquets,
//!   puis `ACK_BASE + seq` des accusés.

use barking_packet::{Kind, MailboxId, OVERHEAD, Packet, PacketId, Tier, ack};
use barking_proto::{ErrorReason, pow};
use std::cmp::Reverse;
use std::collections::BinaryHeap;

use rusqlite::params;

use crate::Result;
use crate::store::{NodeStore, add_stored_bytes, stored_bytes};

/// Nombre de paquets par palier de difficulté supplémentaire.
const POW_STEP_PACKETS: i64 = 64;

/// Marge d'expiration : 7 jours + 1 h (tolérance d'horloge d'une heure).
pub const MAX_EXPIRY_SECS: u64 = 7 * 86_400 + 3_600;
/// Nombre maximal de boîtes par relève.
pub const MAX_MAILBOXES_PER_FETCH: usize = 64;
const ACK_BASE: u64 = barking_proto::ACK_CURSOR_BASE;
const MAX_HOLDINGS: usize = barking_proto::MAX_HOLDINGS_PER_PAGE;

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

impl Policy {
    /// Refuse une politique incohérente (difficulté au-delà de `MAX_POW_BITS`,
    /// qu'aucun client ne pourrait satisfaire).
    pub fn validate(&self) -> Result<()> {
        if self.pow_bits > pow::MAX_POW_BITS {
            return Err(crate::Error::Config(format!(
                "pow_bits = {} dépasse le maximum {}",
                self.pow_bits,
                pow::MAX_POW_BITS
            )));
        }
        if self.max_per_mailbox == 0 {
            return Err(crate::Error::Config("max_per_mailbox = 0".into()));
        }
        Ok(())
    }
}

fn i(n: u64) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

/// Forme et expiration d'un dépôt.
fn parse_checked(bytes: &[u8], now: u64) -> core::result::Result<Packet, ErrorReason> {
    // Palier valide mais longueur différente : WrongTier.
    if bytes.len() >= OVERHEAD
        && let Some(tier) = tier_from_byte(bytes[3])
        && bytes.len() != tier.size()
    {
        return Err(ErrorReason::WrongTier);
    }
    let Ok(packet) = Packet::decode(bytes) else {
        return Err(ErrorReason::Malformed);
    };
    let expires = u64::from(packet.expires_at);
    if expires <= now {
        return Err(ErrorReason::Expired);
    }
    if expires > now.saturating_add(MAX_EXPIRY_SECS) {
        return Err(ErrorReason::TooFarInFuture);
    }
    Ok(packet)
}

/// Contrôles sans base de données, faits avant de prendre une place dans la
/// file : forme, expiration, et pour un message une preuve à la difficulté
/// minimale (base + palier). `deposit` refait tout, avec la difficulté
/// complète.
pub fn precheck(
    policy: &Policy,
    bytes: &[u8],
    pow_nonce: u64,
    now: u64,
) -> core::result::Result<(), ErrorReason> {
    let p = parse_checked(bytes, now)?;
    if p.kind == Kind::Message {
        let hash = pow::content_hash(bytes);
        if !pow::check(
            &hash,
            &p.mailbox,
            pow_nonce,
            pow_bits_for(policy, 0, p.tier, 0),
        ) {
            return Err(ErrorReason::PowTooWeak);
        }
    }
    Ok(())
}

/// Valide et enregistre un dépôt. `Err` : stockage ; `Ok(Err(raison))` : refus.
pub fn deposit(
    store: &mut NodeStore,
    policy: &Policy,
    bytes: &[u8],
    pow_nonce: u64,
    now: u64,
) -> Result<core::result::Result<(), ErrorReason>> {
    let packet = match parse_checked(bytes, now) {
        Ok(p) => p,
        Err(r) => return Ok(Err(r)),
    };
    match packet.kind {
        Kind::Message => deposit_message(
            store,
            policy,
            &packet,
            bytes,
            pow_nonce,
            now,
            Difficulty::Progressive,
        ),
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

/// Bits ajoutés selon le remplissage global : +1 par doublement au-delà de
/// 1/8 du plafond (`stored` ≤ 1/8 : 0 ; ≤ 1/4 : 1 ; ≤ 1/2 : 2 ; au-delà : 3).
pub fn fill_surcharge(stored: u64, storage_max: u64) -> u32 {
    let mut level = (storage_max / 8).max(1);
    let mut extra = 0;
    while stored > level && extra < 64 {
        extra += 1;
        level = level.saturating_mul(2);
    }
    extra
}

/// Difficulté exigée : `min(MAX_POW_BITS, pow_bits + floor(log2(max(1,
/// in_box / 64))) + palier (S 0, M 2, L 6) + remplissage global)`, `in_box`
/// étant le nombre de paquets déjà gardés dans la boîte visée et `stored`
/// les octets gardés par le nœud.
pub fn pow_bits_for(policy: &Policy, in_box: i64, tier: Tier, stored: u64) -> u8 {
    let steps = in_box / POW_STEP_PACKETS;
    let per_box = if steps >= 1 { steps.ilog2() } else { 0 };
    let bits = u32::from(policy.pow_bits)
        .saturating_add(per_box)
        .saturating_add(u32::from(pow::tier_surcharge(tier)))
        .saturating_add(fill_surcharge(stored, policy.storage_max_bytes));
    u8::try_from(bits.min(u32::from(pow::MAX_POW_BITS))).unwrap_or(pow::MAX_POW_BITS)
}

/// Difficulté exigée maintenant pour un dépôt de palier `tier` dans
/// `mailbox` (voir `pow_bits_for`).
pub fn required_pow_bits(
    store: &NodeStore,
    policy: &Policy,
    mailbox: &MailboxId,
    tier: Tier,
) -> Result<u8> {
    let count: i64 = store.conn().query_row(
        "SELECT COUNT(*) FROM packets WHERE mailbox=?1",
        params![&mailbox.0[..]],
        |r| r.get(0),
    )?;
    Ok(pow_bits_for(
        policy,
        count,
        tier,
        stored_bytes(store.conn())?,
    ))
}

/// Difficulté exigée d'un message déposé.
#[derive(Clone, Copy)]
enum Difficulty {
    /// Dépôt d'un client : base, palier, boîte et remplissage (`pow_bits_for`).
    Progressive,
    /// Recopie d'un pair : base et palier seulement (le client a déjà payé le
    /// progressif au premier nœud).
    Base,
}

fn deposit_message(
    store: &mut NodeStore,
    policy: &Policy,
    p: &Packet,
    bytes: &[u8],
    nonce: u64,
    now: u64,
    difficulty: Difficulty,
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
    let stored = stored_bytes(&tx)?;
    let bits = match difficulty {
        Difficulty::Progressive => pow_bits_for(policy, in_box, p.tier, stored),
        Difficulty::Base => pow_bits_for(policy, 0, p.tier, 0),
    };
    if !pow::check(&hash, &p.mailbox, nonce, bits) {
        return Ok(Err(ErrorReason::PowTooWeak));
    }
    if in_box >= i64::from(policy.max_per_mailbox) {
        return Ok(Err(ErrorReason::MailboxFull));
    }
    let len = bytes.len() as u64;
    if stored.saturating_add(len) > policy.storage_max_bytes {
        return Ok(Err(ErrorReason::NodeFull));
    }
    tx.execute(
        "INSERT INTO packets(id,mailbox,kind,tier,expires_at,received_at,hash,bytes,pow) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        params![
            &p.id.0[..],
            &p.mailbox.0[..],
            p.kind as u8,
            p.tier as u8,
            i64::from(p.expires_at),
            i(now / 60 * 60),
            &hash[..],
            bytes,
            // Le nonce est gardé tel quel (réinterprété en i64, sans perte).
            nonce as i64
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

/// Nombre maximal d'éléments par page (borne le travail d'une relève).
pub const MAX_PAGE_ITEMS: usize = 1024;

/// Lecture d'une boîte dans l'ordre de `seq`, via l'index `(mailbox, rowid)` :
/// ni tri, ni lecture des charges utiles. `slot` (rang de la boîte dans la
/// requête) rend le texte unique : le cache de requêtes préparées en garde
/// une par texte, et une relève en tient jusqu'à 64 à la fois par table.
pub(crate) fn fetch_scan_sql(table: &str, slot: usize) -> String {
    format!(
        "SELECT seq, length(bytes) FROM {table} WHERE mailbox=?1 AND seq>?2 ORDER BY seq /*{slot}*/"
    )
}

/// Requêtes préparées gardées en cache : 64 lectures par table, plus la
/// lecture des charges de chaque table.
/// Plus les deux lectures de `holdings` et les deux de `copy_items`.
pub const STATEMENT_CACHE: usize = 2 * MAX_MAILBOXES_PER_FETCH + 2 + 4;

/// Relève paginée : paquets puis accusés des `mailboxes`, dans l'ordre de
/// `seq`. Fusion des lectures indexées de chaque boîte : le travail d'une
/// page est proportionnel à sa taille (au plus `MAX_PAGE_ITEMS` éléments),
/// pas au contenu des boîtes. Seules les charges retenues sont lues.
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
    let mut boxes: Vec<[u8; 16]> = mailboxes.iter().map(|m| m.0).collect();
    boxes.sort_unstable();
    boxes.dedup();
    if boxes.is_empty() {
        return Ok(Ok((Vec::new(), None)));
    }
    let after = cursor.unwrap_or(0);
    let conn = store.conn();
    // (table, seq) retenus, dans l'ordre.
    let mut chosen: Vec<(&str, i64)> = Vec::new();
    let mut used = 0usize;
    let mut last: Option<u64> = None;
    let mut more = false;

    'outer: for (table, base) in [("packets", 0u64), ("acks", ACK_BASE)] {
        if table == "packets" && after >= ACK_BASE {
            continue;
        }
        let start = i(after.saturating_sub(base));
        let mut stmts = (0..boxes.len())
            .map(|k| conn.prepare_cached(&fetch_scan_sql(table, k)))
            .collect::<core::result::Result<Vec<_>, _>>()?;
        let mut rows = Vec::with_capacity(stmts.len());
        for (st, mb) in stmts.iter_mut().zip(&boxes) {
            rows.push(st.query(params![&mb[..], start])?);
        }
        let mut heap = BinaryHeap::new();
        for (k, r) in rows.iter_mut().enumerate() {
            if let Some(row) = r.next()? {
                heap.push(Reverse((row.get::<_, i64>(0)?, k, row.get::<_, i64>(1)?)));
            }
        }
        while let Some(Reverse((seq, k, len))) = heap.pop() {
            let len = usize::try_from(len).unwrap_or(usize::MAX);
            if !chosen.is_empty()
                && (chosen.len() >= MAX_PAGE_ITEMS || used.saturating_add(len) > max_bytes)
            {
                more = true;
                break 'outer;
            }
            used = used.saturating_add(len);
            last = Some(base + u64::try_from(seq).unwrap_or(0));
            chosen.push((table, seq));
            if let Some(row) = rows[k].next()? {
                heap.push(Reverse((row.get::<_, i64>(0)?, k, row.get::<_, i64>(1)?)));
            }
        }
    }

    let mut page = Vec::with_capacity(chosen.len());
    for (table, seq) in chosen {
        let mut st = conn.prepare_cached(&format!("SELECT bytes FROM {table} WHERE seq=?1"))?;
        page.push(st.query_row(params![seq], |r| r.get::<_, Vec<u8>>(0))?);
    }
    Ok(Ok((page, if more { last } else { None })))
}

/// Boîte visée par un paquet à recopier, et `true` si c'est un accusé :
/// forme, expiration et palier vérifiés comme pour un dépôt (spec §5.2,
/// point 3).
pub fn copy_target(
    packet: &[u8],
    now: u64,
) -> core::result::Result<(MailboxId, bool), ErrorReason> {
    let p = parse_checked(packet, now)?;
    Ok((p.mailbox, p.kind == Kind::Ack))
}

/// Preuve d'un message recopié (spec §5.2, point 5) : `pow_bits` + palier,
/// sans le supplément progressif. Un accusé n'en exige aucune.
pub fn copy_pow_ok(
    policy: &Policy,
    packet: &[u8],
    pow_nonce: u64,
) -> core::result::Result<(), ErrorReason> {
    let Ok(p) = Packet::decode(packet) else {
        return Err(ErrorReason::Malformed);
    };
    if p.kind == Kind::Ack {
        return Ok(());
    }
    let hash = pow::content_hash(packet);
    if pow::check(
        &hash,
        &p.mailbox,
        pow_nonce,
        pow_bits_for(policy, 0, p.tier, 0),
    ) {
        Ok(())
    } else {
        Err(ErrorReason::PowTooWeak)
    }
}

/// Difficulté qu'un pair de difficulté de base `pow_bits` exige d'un
/// message recopié de palier `tier` (spec §5.2, point 5).
pub fn copy_pow_bits(pow_bits: u8, tier: Tier) -> u8 {
    let policy = Policy {
        pow_bits,
        ..Policy::default()
    };
    pow_bits_for(&policy, 0, tier, 0)
}

/// Enregistre une copie reçue d'un pair (spec §5.2, points 6 et 7) : comme
/// `deposit`, sans la surcharge progressive. Quotas et déduplication sont
/// ceux du dépôt. La proximité (point 4) est vérifiée par l'appelant.
pub fn store_copy(
    store: &mut NodeStore,
    policy: &Policy,
    packet: &[u8],
    pow_nonce: u64,
    now: u64,
) -> Result<core::result::Result<(), ErrorReason>> {
    let p = match parse_checked(packet, now) {
        Ok(p) => p,
        Err(r) => return Ok(Err(r)),
    };
    match p.kind {
        Kind::Message => {
            deposit_message(store, policy, &p, packet, pow_nonce, now, Difficulty::Base)
        }
        Kind::Ack => deposit_ack(store, policy, &p, packet),
    }
}

/// Une page d'empreintes : (empreintes, curseur suivant).
pub type HoldingsPage = (Vec<[u8; 32]>, Option<u64>);

/// Page des empreintes tenues pour une boîte : paquets (par `seq`) puis
/// accusés (`ACK_BASE + seq`), même ordre de curseur que `fetch`. L'empreinte
/// d'un paquet est la colonne `hash`, celle d'un accusé `content_hash` de ses
/// octets.
pub fn holdings(
    store: &NodeStore,
    mailbox: &MailboxId,
    cursor: Option<u64>,
) -> Result<core::result::Result<HoldingsPage, ErrorReason>> {
    let after = cursor.unwrap_or(0);
    let conn = store.conn();
    // (curseur, empreinte), une ligne de plus que la page pour savoir s'il reste
    // quelque chose.
    let want = MAX_HOLDINGS + 1;
    let mut items: Vec<(u64, [u8; 32])> = Vec::with_capacity(want);
    for (table, base) in [("packets", 0u64), ("acks", ACK_BASE)] {
        if table == "packets" && after >= ACK_BASE {
            continue;
        }
        let left = want - items.len();
        if left == 0 {
            break;
        }
        let column = if table == "packets" { "hash" } else { "bytes" };
        let mut st = conn.prepare_cached(&format!(
            "SELECT seq, {column} FROM {table} WHERE mailbox=?1 AND seq>?2 ORDER BY seq LIMIT ?3"
        ))?;
        let mut rows = st.query(params![
            &mailbox.0[..],
            i(after.saturating_sub(base)),
            i(left as u64)
        ])?;
        while let Some(row) = rows.next()? {
            let seq = u64::try_from(row.get::<_, i64>(0)?).unwrap_or(0);
            let blob: Vec<u8> = row.get(1)?;
            let hash = if table == "packets" {
                // Une empreinte de longueur inattendue (base abîmée) est recalculée
                // à défaut : on ne ment pas au pair sur ce qu'on tient.
                <[u8; 32]>::try_from(blob.as_slice()).unwrap_or_else(|_| pow::content_hash(&blob))
            } else {
                pow::content_hash(&blob)
            };
            items.push((base + seq, hash));
        }
    }
    let more = items.len() > MAX_HOLDINGS;
    items.truncate(MAX_HOLDINGS);
    let next = if more {
        items.last().map(|(c, _)| *c)
    } else {
        None
    };
    Ok(Ok((items.into_iter().map(|(_, h)| h).collect(), next)))
}

/// Un élément à recopier chez un responsable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyItem {
    pub bytes: Vec<u8>,
    /// Nonce de preuve gardé au dépôt (0 pour un accusé ou une ligne migrée).
    pub pow: u64,
    pub hash: [u8; 32],
    pub is_ack: bool,
    /// Palier (accusé : S ; colonne illisible : L, le supplément le plus
    /// fort).
    pub tier: Tier,
}

/// Tout ce que le nœud tient pour `mailbox` et qui n'a pas expiré : les
/// accusés d'abord, puis les paquets (spec §5.2, point 6).
pub fn copy_items(
    store: &NodeStore,
    mailbox: &MailboxId,
    now: u64,
) -> Result<core::result::Result<Vec<CopyItem>, ErrorReason>> {
    let conn = store.conn();
    let now = i(now);
    let mut out = Vec::new();
    let mut st = conn
        .prepare_cached("SELECT bytes FROM acks WHERE mailbox=?1 AND expires_at>?2 ORDER BY seq")?;
    let mut rows = st.query(params![&mailbox.0[..], now])?;
    while let Some(row) = rows.next()? {
        let bytes: Vec<u8> = row.get(0)?;
        let hash = pow::content_hash(&bytes);
        out.push(CopyItem {
            bytes,
            pow: 0,
            hash,
            is_ack: true,
            tier: Tier::S,
        });
    }
    let mut st = conn.prepare_cached(
        "SELECT bytes, pow, hash, tier FROM packets WHERE mailbox=?1 AND expires_at>?2 ORDER BY seq",
    )?;
    let mut rows = st.query(params![&mailbox.0[..], now])?;
    while let Some(row) = rows.next()? {
        let bytes: Vec<u8> = row.get(0)?;
        let nonce: i64 = row.get(1)?;
        let hash = <[u8; 32]>::try_from(row.get::<_, Vec<u8>>(2)?.as_slice())
            .unwrap_or_else(|_| pow::content_hash(&bytes));
        let tier = u8::try_from(row.get::<_, i64>(3)?)
            .ok()
            .and_then(tier_from_byte)
            .unwrap_or(Tier::L);
        out.push(CopyItem {
            bytes,
            pow: nonce as u64,
            hash,
            is_ack: false,
            tier,
        });
    }
    Ok(Ok(out))
}

#[cfg(test)]
mod tests;
