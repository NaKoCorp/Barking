//! Stockage chiffré SQLCipher.
//!
//! Partage des méthodes typées : elles sont définies une seule fois dans le
//! trait [`Queries`] (méthodes par défaut au-dessus d'une `&Connection`), que
//! [`Store`] (appel simple) et [`Tx`] (dans [`Store::transaction`]) implémentent.
//! Le trait doit être importé (`use barking_core::store::Queries`).
//! Tout `Err` renvoyé par la fermeture de `transaction` annule toutes les
//! écritures (rollback).

mod schema;

use std::fmt;
use std::path::Path;

use rusqlite::{Connection, ErrorCode, OptionalExtension, params};
use serde::Serialize;
use serde::de::DeserializeOwned;
use zeroize::Zeroize;

use crate::identity::device::DeviceId;
use crate::identity::root::Fingerprint;
use crate::packet::{Kind, Packet, PacketId};
use crate::{CoreError, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageStatus {
    Queued = 0,
    Sent = 1,
    Delivered = 3,
    Failed = 5,
}

impl MessageStatus {
    fn from_i64(v: i64) -> Result<Self> {
        match v {
            0 => Ok(Self::Queued),
            1 => Ok(Self::Sent),
            3 => Ok(Self::Delivered),
            5 => Ok(Self::Failed),
            _ => Err(CoreError::Store("statut inconnu".into())),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Out = 0,
    In = 1,
}

impl Direction {
    fn from_i64(v: i64) -> Result<Self> {
        match v {
            0 => Ok(Self::Out),
            1 => Ok(Self::In),
            _ => Err(CoreError::Store("direction inconnue".into())),
        }
    }
}

/// Contact stocké : `card` est le postcard de `ContactCard` (opaque ici).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContactRow {
    pub fp: Fingerprint,
    pub card: Vec<u8>,
    pub alias: String,
    pub verified: bool,
}

/// Session stockée. `state` est le postcard de `RatchetState` et
/// `pending_initial` celui de `InitialMessage` ; Core les (dé)sérialise.
/// Ne dérive pas `Debug` : contient des secrets.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionRow {
    pub contact_device: DeviceId,
    pub contact_fp: Fingerprint,
    pub session_id: [u8; 16],
    pub state: Vec<u8>,
    pub mailbox_secret: [u8; 32],
    pub ad: Vec<u8>,
    pub pending_initial: Option<Vec<u8>>,
    pub last_rx: u64,
    pub created_at: u64,
}

impl fmt::Debug for SessionRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionRow")
            .field("contact_device", &self.contact_device)
            .field("contact_fp", &self.contact_fp)
            .field("session_id", &self.session_id)
            .finish_non_exhaustive()
    }
}

impl Drop for SessionRow {
    fn drop(&mut self) {
        self.state.zeroize();
        self.mailbox_secret.zeroize();
        self.ad.zeroize();
        if let Some(p) = self.pending_initial.as_mut() {
            p.zeroize();
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct MessageRow {
    pub id: i64,
    pub contact_fp: Fingerprint,
    pub direction: Direction,
    pub body: String,
    pub status: MessageStatus,
    pub at: u64,
    pub packet_id: Option<PacketId>,
}

impl fmt::Debug for MessageRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Le texte du message n'apparaît jamais : seulement sa taille.
        f.debug_struct("MessageRow")
            .field("id", &self.id)
            .field("contact_fp", &self.contact_fp)
            .field("direction", &self.direction)
            .field("body", &format_args!("<{} octets>", self.body.len()))
            .field("status", &self.status)
            .field("at", &self.at)
            .field("packet_id", &self.packet_id)
            .finish()
    }
}

fn map_err(e: rusqlite::Error) -> CoreError {
    if let rusqlite::Error::SqliteFailure(f, _) = &e
        && f.code == ErrorCode::NotADatabase
    {
        return CoreError::StoreLocked;
    }
    // Le message SQLite ne contient pas de données utilisateur ni de clé.
    CoreError::Store(e.to_string())
}

fn ser<T: Serialize>(v: &T) -> Result<Vec<u8>> {
    postcard::to_allocvec(v).map_err(|_| CoreError::Store("sérialisation".into()))
}

fn arr<const N: usize>(b: Vec<u8>) -> Result<[u8; N]> {
    b.try_into()
        .map_err(|_| CoreError::Store("longueur de champ invalide".into()))
}

fn to_i64(v: u64) -> i64 {
    // Les secondes Unix tiennent largement dans i64.
    i64::try_from(v).unwrap_or(i64::MAX)
}

fn to_u64(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

pub struct Store {
    conn: Connection,
}

impl fmt::Debug for Store {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Store").finish_non_exhaustive()
    }
}

/// Poignée de transaction, passée à la fermeture de [`Store::transaction`].
pub struct Tx<'a> {
    conn: &'a Connection,
}

impl Store {
    /// Ouvre (ou crée) la base chiffrée avec une clé de 32 octets.
    pub fn open(path: &Path, key: &[u8; 32]) -> Result<Store> {
        let conn = Connection::open(path).map_err(map_err)?;
        let mut hex = data_encoding::HEXLOWER.encode(key);
        let mut pragma = format!("PRAGMA key = \"x'{hex}'\";");
        let r = conn.execute_batch(&pragma);
        hex.zeroize();
        pragma.zeroize();
        r.map_err(map_err)?;
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| {
            r.get::<_, i64>(0)
        })
        .map_err(map_err)?;
        // Pages libérées écrasées par des zéros (messages, sessions supprimés).
        conn.execute_batch("PRAGMA secure_delete = ON;")
            .map_err(map_err)?;
        let store = Store { conn };
        store.apply_schema()?;
        Ok(store)
    }

    fn apply_schema(&self) -> Result<()> {
        self.conn
            .execute_batch(schema::SCHEMA_V1)
            .map_err(map_err)?;
        if self.get_meta::<u32>("schema_version")?.is_none() {
            self.put_meta("schema_version", &schema::SCHEMA_VERSION)?;
        }
        Ok(())
    }

    /// Exécute `f` dans une transaction unique ; `Err` => rollback complet.
    pub fn transaction<R>(&mut self, f: impl FnOnce(&Tx) -> Result<R>) -> Result<R> {
        let txn = self.conn.transaction().map_err(map_err)?;
        let out = f(&Tx { conn: &txn });
        match out {
            Ok(v) => {
                txn.commit().map_err(map_err)?;
                Ok(v)
            }
            Err(e) => {
                let _ = txn.rollback();
                Err(e)
            }
        }
    }
}

/// Méthodes typées, communes à [`Store`] et [`Tx`].
pub trait Queries {
    #[doc(hidden)]
    fn conn(&self) -> &Connection;

    fn put_meta<T: Serialize>(&self, k: &str, v: &T) -> Result<()> {
        let mut bytes = ser(v)?;
        let r = self.conn().execute(
            "INSERT INTO meta(k, v) VALUES (?1, ?2) \
             ON CONFLICT(k) DO UPDATE SET v = excluded.v",
            params![k, bytes],
        );
        bytes.zeroize();
        r.map_err(map_err)?;
        Ok(())
    }

    fn get_meta<T: DeserializeOwned>(&self, k: &str) -> Result<Option<T>> {
        let mut raw: Option<Vec<u8>> = self
            .conn()
            .query_row("SELECT v FROM meta WHERE k = ?1", params![k], |r| r.get(0))
            .optional()
            .map_err(map_err)?;
        let out = match raw.as_deref() {
            None => Ok(None),
            Some(b) => postcard::from_bytes(b)
                .map(Some)
                .map_err(|_| CoreError::Store("donnée meta corrompue".into())),
        };
        if let Some(r) = raw.as_mut() {
            r.zeroize();
        }
        out
    }

    fn upsert_contact(
        &self,
        fp: Fingerprint,
        card: &[u8],
        alias: &str,
        verified: bool,
    ) -> Result<()> {
        self.conn()
            .execute(
                "INSERT INTO contacts(fp, card, alias, verified) VALUES (?1, ?2, ?3, ?4) \
                 ON CONFLICT(fp) DO UPDATE SET card = excluded.card, \
                 alias = excluded.alias, verified = excluded.verified",
                params![fp.0.as_slice(), card, alias, verified],
            )
            .map_err(map_err)?;
        Ok(())
    }

    fn get_contact(&self, fp: Fingerprint) -> Result<Option<ContactRow>> {
        let row = self
            .conn()
            .query_row(
                "SELECT fp, card, alias, verified FROM contacts WHERE fp = ?1",
                params![fp.0.as_slice()],
                contact_raw,
            )
            .optional()
            .map_err(map_err)?;
        row.map(contact_from_raw).transpose()
    }

    fn list_contacts(&self) -> Result<Vec<ContactRow>> {
        let mut stmt = self
            .conn()
            .prepare("SELECT fp, card, alias, verified FROM contacts ORDER BY alias, fp")
            .map_err(map_err)?;
        let raws = stmt
            .query_map([], contact_raw)
            .map_err(map_err)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(map_err)?;
        raws.into_iter().map(contact_from_raw).collect()
    }

    fn find_contact_by_alias(&self, alias: &str) -> Result<Option<ContactRow>> {
        let row = self
            .conn()
            .query_row(
                "SELECT fp, card, alias, verified FROM contacts WHERE alias = ?1 \
                 ORDER BY fp LIMIT 1",
                params![alias],
                contact_raw,
            )
            .optional()
            .map_err(map_err)?;
        row.map(contact_from_raw).transpose()
    }

    fn put_session(&self, s: &SessionRow) -> Result<()> {
        self.conn()
            .execute(
                "INSERT INTO sessions(contact_device, contact_fp, session_id, state, \
                 mailbox_secret, ad, pending_initial, last_rx, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9) \
                 ON CONFLICT(contact_fp, contact_device, session_id) DO UPDATE SET \
                 state = excluded.state, \
                 mailbox_secret = excluded.mailbox_secret, ad = excluded.ad, \
                 pending_initial = excluded.pending_initial, \
                 last_rx = excluded.last_rx, created_at = excluded.created_at",
                params![
                    s.contact_device.0.as_slice(),
                    s.contact_fp.0.as_slice(),
                    s.session_id.as_slice(),
                    s.state,
                    s.mailbox_secret.as_slice(),
                    s.ad,
                    s.pending_initial,
                    to_i64(s.last_rx),
                    to_i64(s.created_at)
                ],
            )
            .map_err(map_err)?;
        Ok(())
    }

    /// Sessions avec l'appareil `device` du contact `contact_fp`. Une session
    /// appartient toujours à un couple (contact, appareil) : un même appareil
    /// revendiqué par deux contacts ne partage jamais de session.
    fn sessions_for(&self, contact_fp: Fingerprint, device: DeviceId) -> Result<Vec<SessionRow>> {
        query_sessions(
            self.conn(),
            "WHERE contact_fp = ?1 AND contact_device = ?2 ORDER BY created_at, session_id",
            params![contact_fp.0.as_slice(), device.0.as_slice()],
        )
    }

    fn all_sessions(&self) -> Result<Vec<SessionRow>> {
        query_sessions(self.conn(), "ORDER BY created_at, session_id", [])
    }

    fn insert_message(
        &self,
        contact_fp: Fingerprint,
        direction: Direction,
        body: &str,
        status: MessageStatus,
        at: u64,
        packet_id: Option<PacketId>,
    ) -> Result<i64> {
        self.conn()
            .execute(
                "INSERT INTO messages(contact_fp, direction, body, status, at, packet_id) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    contact_fp.0.as_slice(),
                    direction as i64,
                    body,
                    status as i64,
                    to_i64(at),
                    packet_id.map(|p| p.0.to_vec())
                ],
            )
            .map_err(map_err)?;
        Ok(self.conn().last_insert_rowid())
    }

    fn set_status_by_packet(&self, packet_id: PacketId, status: MessageStatus) -> Result<()> {
        self.conn()
            .execute(
                "UPDATE messages SET status = ?1 WHERE packet_id = ?2",
                params![status as i64, packet_id.0.as_slice()],
            )
            .map_err(map_err)?;
        Ok(())
    }

    /// Messages d'un contact, du plus ancien au plus récent.
    fn messages_with(&self, contact_fp: Fingerprint) -> Result<Vec<MessageRow>> {
        let mut stmt = self
            .conn()
            .prepare(
                "SELECT id, contact_fp, direction, body, status, at, packet_id \
                 FROM messages WHERE contact_fp = ?1 ORDER BY at, id",
            )
            .map_err(map_err)?;
        let raws = stmt
            .query_map(params![contact_fp.0.as_slice()], message_raw)
            .map_err(map_err)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(map_err)?;
        raws.into_iter().map(message_from_raw).collect()
    }

    /// `true` si le paquet est nouveau, `false` s'il était déjà vu.
    fn mark_seen(&self, packet_id: PacketId, at: u64) -> Result<bool> {
        let n = self
            .conn()
            .execute(
                "INSERT OR IGNORE INTO seen(packet_id, at) VALUES (?1, ?2)",
                params![packet_id.0.as_slice(), to_i64(at)],
            )
            .map_err(map_err)?;
        Ok(n == 1)
    }

    /// `true` si le paquet a déjà été vu (sans l'enregistrer).
    fn is_seen(&self, packet_id: PacketId) -> Result<bool> {
        let n: i64 = self
            .conn()
            .query_row(
                "SELECT count(*) FROM seen WHERE packet_id = ?1",
                params![packet_id.0.as_slice()],
                |r| r.get(0),
            )
            .map_err(map_err)?;
        Ok(n > 0)
    }

    /// Supprime les paquets vus avant `before` ; renvoie le nombre de lignes supprimées.
    fn purge_seen(&self, before: u64) -> Result<usize> {
        self.conn()
            .execute("DELETE FROM seen WHERE at < ?1", params![to_i64(before)])
            .map_err(map_err)
    }

    /// Met un paquet en file d'envoi ; sans effet s'il y est déjà.
    fn outbox_put(
        &self,
        packet_id: PacketId,
        bytes: &[u8],
        kind: Kind,
        expires_at: u64,
        now: u64,
    ) -> Result<()> {
        self.conn()
            .execute(
                "INSERT INTO outbox(packet_id, bytes, kind, expires_at, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT(packet_id) DO NOTHING",
                params![
                    packet_id.0.as_slice(),
                    bytes,
                    kind as i64,
                    to_i64(expires_at),
                    to_i64(now)
                ],
            )
            .map_err(map_err)?;
        Ok(())
    }

    /// Retire un paquet de la file ; `true` s'il y était.
    fn outbox_remove(&self, packet_id: PacketId) -> Result<bool> {
        let n = self
            .conn()
            .execute(
                "DELETE FROM outbox WHERE packet_id = ?1",
                params![packet_id.0.as_slice()],
            )
            .map_err(map_err)?;
        Ok(n > 0)
    }

    /// Paquets non expirés (`expires_at >= now`), du plus ancien au plus récent.
    fn outbox_pending(&self, now: u64) -> Result<Vec<(PacketId, Vec<u8>)>> {
        let mut stmt = self
            .conn()
            .prepare(
                "SELECT packet_id, bytes FROM outbox WHERE expires_at >= ?1
                 ORDER BY created_at, rowid",
            )
            .map_err(map_err)?;
        let raws = stmt
            .query_map(params![to_i64(now)], |r| {
                Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?))
            })
            .map_err(map_err)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(map_err)?;
        raws.into_iter()
            .map(|(id, bytes)| Ok((PacketId(arr(id)?), bytes)))
            .collect()
    }

    /// Supprime les paquets expirés ; renvoie le nombre de lignes supprimées.
    fn outbox_purge_expired(&self, now: u64) -> Result<usize> {
        self.conn()
            .execute(
                "DELETE FROM outbox WHERE expires_at < ?1",
                params![to_i64(now)],
            )
            .map_err(map_err)
    }

    /// Message portant l'identifiant de paquet `packet_id`, s'il existe.
    fn message_by_packet(&self, packet_id: PacketId) -> Result<Option<MessageRow>> {
        let raw = self
            .conn()
            .query_row(
                "SELECT id, contact_fp, direction, body, status, at, packet_id \
                 FROM messages WHERE packet_id = ?1",
                params![packet_id.0.as_slice()],
                message_raw,
            )
            .optional()
            .map_err(map_err)?;
        raw.map(message_from_raw).transpose()
    }

    /// Supprime un contact, toutes ses sessions et ses paquets en file
    /// d'envoi : mes messages pour lui et mes accusés de ses messages
    /// (l'historique est gardé).
    fn delete_contact(&self, fp: Fingerprint) -> Result<()> {
        self.conn()
            .execute(
                "DELETE FROM outbox WHERE packet_id IN \
                 (SELECT packet_id FROM messages \
                  WHERE contact_fp = ?1 AND direction = ?2 AND packet_id IS NOT NULL)",
                params![fp.0.as_slice(), Direction::Out as i64],
            )
            .map_err(map_err)?;
        // Un accusé porte l'identifiant du message reçu qu'il confirme.
        let acks = {
            let mut stmt = self
                .conn()
                .prepare("SELECT packet_id, bytes FROM outbox WHERE kind = ?1")
                .map_err(map_err)?;
            stmt.query_map(params![Kind::Ack as i64], |r| {
                Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?))
            })
            .map_err(map_err)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(map_err)?
        };
        for (id, bytes) in acks {
            let Some(acked) = Packet::decode(&bytes)
                .ok()
                .and_then(|p| p.payload.get(..16).map(<[u8; 16]>::try_from))
                .and_then(core::result::Result::ok)
            else {
                continue;
            };
            if self
                .message_by_packet(PacketId(acked))?
                .is_some_and(|m| m.contact_fp == fp && m.direction == Direction::In)
            {
                self.outbox_remove(PacketId(arr(id)?))?;
            }
        }
        self.conn()
            .execute(
                "DELETE FROM sessions WHERE contact_fp = ?1",
                params![fp.0.as_slice()],
            )
            .map_err(map_err)?;
        self.conn()
            .execute(
                "DELETE FROM contacts WHERE fp = ?1",
                params![fp.0.as_slice()],
            )
            .map_err(map_err)?;
        Ok(())
    }

    /// Supprime une session.
    fn delete_session(
        &self,
        contact_fp: Fingerprint,
        device: DeviceId,
        session_id: &[u8; 16],
    ) -> Result<()> {
        self.conn()
            .execute(
                "DELETE FROM sessions WHERE contact_fp = ?1 AND contact_device = ?2 \
                 AND session_id = ?3",
                params![
                    contact_fp.0.as_slice(),
                    device.0.as_slice(),
                    session_id.as_slice()
                ],
            )
            .map_err(map_err)?;
        Ok(())
    }

    /// Supprime toutes les sessions avec un appareil d'un contact (appareil révoqué).
    fn delete_sessions_for_device(&self, contact_fp: Fingerprint, device: DeviceId) -> Result<()> {
        self.conn()
            .execute(
                "DELETE FROM sessions WHERE contact_fp = ?1 AND contact_device = ?2",
                params![contact_fp.0.as_slice(), device.0.as_slice()],
            )
            .map_err(map_err)?;
        Ok(())
    }

    /// Les `limit` événements les plus récents, du plus ancien au plus récent.
    fn recent_events(&self, limit: usize) -> Result<Vec<(u64, Vec<u8>)>> {
        let mut stmt = self
            .conn()
            .prepare(
                "SELECT at, event FROM (SELECT id, at, event FROM transparency \
                 ORDER BY id DESC LIMIT ?1) ORDER BY id",
            )
            .map_err(map_err)?;
        let rows = stmt
            .query_map(params![to_i64(limit as u64)], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?))
            })
            .map_err(map_err)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(map_err)?;
        Ok(rows.into_iter().map(|(a, e)| (to_u64(a), e)).collect())
    }

    /// Ajoute un événement de transparence (postcard opaque ici).
    fn append_event(&self, at: u64, packet_id: Option<PacketId>, event: &[u8]) -> Result<()> {
        self.conn()
            .execute(
                "INSERT INTO transparency(at, packet_id, event) VALUES (?1, ?2, ?3)",
                params![to_i64(at), packet_id.map(|p| p.0.to_vec()), event],
            )
            .map_err(map_err)?;
        Ok(())
    }

    /// Les `limit` premiers événements, dans l'ordre d'insertion : `(at, event)`.
    fn events(&self, limit: usize) -> Result<Vec<(u64, Vec<u8>)>> {
        let mut stmt = self
            .conn()
            .prepare("SELECT at, event FROM transparency ORDER BY id LIMIT ?1")
            .map_err(map_err)?;
        let rows = stmt
            .query_map(params![to_i64(limit as u64)], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?))
            })
            .map_err(map_err)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(map_err)?;
        Ok(rows.into_iter().map(|(a, e)| (to_u64(a), e)).collect())
    }
}

impl Queries for Store {
    fn conn(&self) -> &Connection {
        &self.conn
    }
}

impl Queries for Tx<'_> {
    fn conn(&self) -> &Connection {
        self.conn
    }
}

type MessageRaw = (i64, Vec<u8>, i64, String, i64, i64, Option<Vec<u8>>);

fn message_raw(r: &rusqlite::Row<'_>) -> rusqlite::Result<MessageRaw> {
    Ok((
        r.get(0)?,
        r.get(1)?,
        r.get(2)?,
        r.get(3)?,
        r.get(4)?,
        r.get(5)?,
        r.get(6)?,
    ))
}

fn message_from_raw((id, fp, dir, body, st, at, pid): MessageRaw) -> Result<MessageRow> {
    Ok(MessageRow {
        id,
        contact_fp: Fingerprint(arr(fp)?),
        direction: Direction::from_i64(dir)?,
        body,
        status: MessageStatus::from_i64(st)?,
        at: to_u64(at),
        packet_id: pid.map(|p| arr(p).map(PacketId)).transpose()?,
    })
}

type ContactRaw = (Vec<u8>, Vec<u8>, String, bool);

fn contact_raw(r: &rusqlite::Row<'_>) -> rusqlite::Result<ContactRaw> {
    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
}

fn contact_from_raw((fp, card, alias, verified): ContactRaw) -> Result<ContactRow> {
    Ok(ContactRow {
        fp: Fingerprint(arr(fp)?),
        card,
        alias,
        verified,
    })
}

fn query_sessions(
    conn: &Connection,
    tail: &str,
    p: impl rusqlite::Params,
) -> Result<Vec<SessionRow>> {
    let sql = format!(
        "SELECT contact_device, contact_fp, session_id, state, mailbox_secret, ad, \
         pending_initial, last_rx, created_at FROM sessions {tail}"
    );
    let mut stmt = conn.prepare(&sql).map_err(map_err)?;
    let raws = stmt
        .query_map(p, |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, Vec<u8>>(3)?,
                r.get::<_, Vec<u8>>(4)?,
                r.get::<_, Vec<u8>>(5)?,
                r.get::<_, Option<Vec<u8>>>(6)?,
                r.get::<_, i64>(7)?,
                r.get::<_, i64>(8)?,
            ))
        })
        .map_err(map_err)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(map_err)?;
    raws.into_iter()
        .map(|(dev, fp, sid, state, ms, ad, pi, rx, cr)| {
            Ok(SessionRow {
                contact_device: DeviceId(arr(dev)?),
                contact_fp: Fingerprint(arr(fp)?),
                session_id: arr(sid)?,
                state,
                mailbox_secret: arr(ms)?,
                ad,
                pending_initial: pi,
                last_rx: to_u64(rx),
                created_at: to_u64(cr),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests;
