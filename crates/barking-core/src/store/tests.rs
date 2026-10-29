use super::*;
use crate::CoreError;
use crate::identity::root::Fingerprint;
use crate::packet::PacketId;
use tempfile::tempdir;

const KEY: [u8; 32] = [7u8; 32];

fn open_tmp() -> (tempfile::TempDir, std::path::PathBuf, Store) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("db.sqlite");
    let store = Store::open(&path, &KEY).unwrap();
    (dir, path, store)
}

#[test]
fn reopen_persists() {
    let (_d, path, store) = open_tmp();
    store.put_meta("hello", &vec![1u8, 2, 3]).unwrap();
    drop(store);
    let store = Store::open(&path, &KEY).unwrap();
    assert_eq!(
        store.get_meta::<Vec<u8>>("hello").unwrap(),
        Some(vec![1, 2, 3])
    );
    assert_eq!(store.get_meta::<u32>("schema_version").unwrap(), Some(2));
    assert_eq!(store.get_meta::<u32>("absent").unwrap(), None);
}

#[test]
fn wrong_key_is_store_locked() {
    let (_d, path, store) = open_tmp();
    drop(store);
    let err = Store::open(&path, &[8u8; 32]).err().unwrap();
    assert_eq!(err, CoreError::StoreLocked);
}

#[test]
fn file_is_not_plaintext() {
    let (_d, path, store) = open_tmp();
    store.put_meta("k", &1u8).unwrap();
    drop(store);
    let bytes = std::fs::read(&path).unwrap();
    assert!(bytes.len() >= 16);
    assert!(!bytes[..16].starts_with(b"SQLite format 3"));
}

#[test]
fn mark_seen_once() {
    let (_d, _p, store) = open_tmp();
    let id = PacketId([9; 16]);
    assert!(store.mark_seen(id, 10).unwrap());
    assert!(!store.mark_seen(id, 11).unwrap());
    assert!(store.mark_seen(PacketId([1; 16]), 12).unwrap());
}

#[test]
fn transaction_rollback_on_error() {
    let (_d, _p, mut store) = open_tmp();
    let id = PacketId([3; 16]);
    let r: crate::Result<()> = store.transaction(|tx| {
        tx.put_meta("x", &5u8)?;
        tx.mark_seen(id, 1)?;
        Err(CoreError::Store("boom".into()))
    });
    assert!(r.is_err());
    assert_eq!(store.get_meta::<u8>("x").unwrap(), None);
    assert!(store.mark_seen(id, 2).unwrap());
    store.transaction(|tx| tx.put_meta("y", &6u8)).unwrap();
    assert_eq!(store.get_meta::<u8>("y").unwrap(), Some(6));
}

#[test]
fn contacts_sessions_messages_events() {
    let (_d, _p, store) = open_tmp();
    let fp = Fingerprint([4; 32]);
    store.upsert_contact(fp, b"card1", "alice", false).unwrap();
    store.upsert_contact(fp, b"card2", "alice", true).unwrap();
    let c = store.get_contact(fp).unwrap().unwrap();
    assert_eq!(c.card, b"card2");
    assert!(c.verified);
    assert_eq!(store.list_contacts().unwrap().len(), 1);
    assert_eq!(
        store.find_contact_by_alias("alice").unwrap().unwrap().fp,
        fp
    );
    assert!(store.find_contact_by_alias("bob").unwrap().is_none());

    let dev = crate::identity::device::DeviceId([5; 16]);
    let mut row = SessionRow {
        contact_device: dev,
        contact_fp: fp,
        session_id: [6; 16],
        state: vec![1, 2],
        mailbox_secret: [8; 32],
        ad: vec![3],
        pending_initial: Some(vec![9]),
        last_rx: 0,
        created_at: 1,
    };
    store.put_session(&row).unwrap();
    row.last_rx = 77;
    row.pending_initial = None;
    store.put_session(&row).unwrap();
    assert_eq!(store.sessions_for(fp, dev).unwrap(), vec![row.clone()]);
    assert_eq!(store.all_sessions().unwrap().len(), 1);

    let pid = PacketId([2; 16]);
    let mid = MessageId([6; 16]);
    assert!(
        store
            .insert_message(fp, Direction::Out, "salut", MessageStatus::Queued, 5, mid)
            .unwrap()
    );
    store.add_delivery(mid, pid, dev).unwrap();
    assert_eq!(store.mark_delivered_by_packet(pid).unwrap(), Some(mid));
    let m = store.messages_with(fp).unwrap();
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].status, MessageStatus::Delivered);
    assert_eq!(m[0].direction, Direction::Out);

    store
        .append_event(10, Some(pid), EventClass::Routine, b"ev1")
        .unwrap();
    store
        .append_event(11, None, EventClass::Routine, b"ev2")
        .unwrap();
    assert_eq!(
        store.events(10).unwrap(),
        vec![(10, b"ev1".to_vec()), (11, b"ev2".to_vec())]
    );
    assert_eq!(store.events(1).unwrap().len(), 1);
}

#[test]
fn debug_hides_key() {
    let (_d, _p, store) = open_tmp();
    let s = format!("{store:?}");
    assert!(!s.contains("0707"));
}

#[test]
fn seen_check_and_purge() {
    let (_d, _p, store) = open_tmp();
    let old = PacketId([1; 16]);
    let new = PacketId([2; 16]);
    assert!(!store.is_seen(old).unwrap());
    store.mark_seen(old, 10).unwrap();
    store.mark_seen(new, 100).unwrap();
    assert!(store.is_seen(old).unwrap());
    assert_eq!(store.purge_seen(50).unwrap(), 1);
    assert!(!store.is_seen(old).unwrap());
    assert!(store.is_seen(new).unwrap());
}

#[test]
fn message_lookup_and_deletions() {
    let (_d, _p, store) = open_tmp();
    let fp = Fingerprint([4; 32]);
    let pid = PacketId([2; 16]);
    assert!(store.message_by_packet(pid).unwrap().is_none());
    store
        .insert_message(
            fp,
            Direction::Out,
            "x",
            MessageStatus::Sent,
            5,
            MessageId([6; 16]),
        )
        .unwrap();
    store
        .add_delivery(
            MessageId([6; 16]),
            pid,
            crate::identity::device::DeviceId([5; 16]),
        )
        .unwrap();
    let m = store.message_by_packet(pid).unwrap().unwrap();
    assert_eq!(m.message_id, MessageId([6; 16]));
    assert_eq!(m.direction, Direction::Out);
    assert_eq!(m.status, MessageStatus::Sent);

    store.upsert_contact(fp, b"c", "a", false).unwrap();
    let dev = crate::identity::device::DeviceId([5; 16]);
    let row = |sid: u8| SessionRow {
        contact_device: dev,
        contact_fp: fp,
        session_id: [sid; 16],
        state: vec![],
        mailbox_secret: [0; 32],
        ad: vec![],
        pending_initial: None,
        last_rx: 0,
        created_at: u64::from(sid),
    };
    store.put_session(&row(1)).unwrap();
    store.put_session(&row(2)).unwrap();
    store.delete_session(fp, dev, &[1; 16]).unwrap();
    assert_eq!(store.sessions_for(fp, dev).unwrap().len(), 1);
    store.put_session(&row(3)).unwrap();
    store.delete_sessions_for_device(fp, dev).unwrap();
    assert!(store.sessions_for(fp, dev).unwrap().is_empty());
    store.put_session(&row(4)).unwrap();
    // Même appareil, autre contact : sessions distinctes, jamais écrasées.
    let other = Fingerprint([9; 32]);
    let mut foreign = row(4);
    foreign.contact_fp = other;
    store.put_session(&foreign).unwrap();
    assert_eq!(store.sessions_for(fp, dev).unwrap().len(), 1);
    assert_eq!(store.sessions_for(other, dev).unwrap().len(), 1);
    store.delete_sessions_for_device(other, dev).unwrap();
    assert_eq!(store.sessions_for(fp, dev).unwrap().len(), 1);
    store.put_session(&foreign).unwrap();
    store.delete_contact(fp).unwrap();
    assert_eq!(store.all_sessions().unwrap().len(), 1);
    store.delete_contact(other).unwrap();
    assert!(store.get_contact(fp).unwrap().is_none());
    assert!(store.all_sessions().unwrap().is_empty());
    // L'historique reste.
    assert_eq!(store.messages_with(fp).unwrap().len(), 1);
}

#[test]
fn recent_events_newest_window_in_order() {
    let (_d, _p, store) = open_tmp();
    for i in 0..5u8 {
        store
            .append_event(u64::from(i), None, EventClass::Routine, &[i])
            .unwrap();
    }
    assert_eq!(
        store.recent_events(2).unwrap(),
        vec![(3, vec![3]), (4, vec![4])]
    );
    assert_eq!(store.recent_events(10).unwrap().len(), 5);
}

#[test]
fn outbox_put_pending_remove_purge() {
    use crate::packet::Kind;
    let (_d, _p, store) = open_tmp();
    let (a, b, c) = (PacketId([1; 16]), PacketId([2; 16]), PacketId([3; 16]));
    store.outbox_put(b, b"bb", Kind::Message, 500, 20).unwrap();
    store.outbox_put(a, b"aa", Kind::Message, 500, 10).unwrap();
    store.outbox_put(c, b"cc", Kind::Ack, 100, 30).unwrap();
    // Du plus ancien au plus récent.
    assert_eq!(
        store.outbox_pending(50).unwrap(),
        vec![
            (a, b"aa".to_vec()),
            (b, b"bb".to_vec()),
            (c, b"cc".to_vec())
        ]
    );
    // Une entrée expirée n'est plus rendue.
    assert_eq!(store.outbox_pending(101).unwrap().len(), 2);
    assert_eq!(store.outbox_purge_expired(101).unwrap(), 1);
    assert_eq!(store.outbox_purge_expired(101).unwrap(), 0);
    assert!(store.outbox_remove(a).unwrap());
    assert!(!store.outbox_remove(a).unwrap());
    assert_eq!(
        store.outbox_pending(101).unwrap(),
        vec![(b, b"bb".to_vec())]
    );
    // Réinsérer le même identifiant ne duplique pas la ligne.
    store.outbox_put(b, b"bb", Kind::Message, 500, 20).unwrap();
    assert_eq!(store.outbox_pending(101).unwrap().len(), 1);
}

#[test]
fn outbox_put_rolls_back_with_transaction() {
    use crate::packet::Kind;
    let (_d, _p, mut store) = open_tmp();
    let r: crate::Result<()> = store.transaction(|tx| {
        tx.outbox_put(PacketId([1; 16]), b"x", Kind::Message, 500, 1)?;
        Err(CoreError::Store("boom".into()))
    });
    assert!(r.is_err());
    assert!(store.outbox_pending(2).unwrap().is_empty());
}

#[test]
fn secure_delete_enabled() {
    let (_d, _p, store) = open_tmp();
    let on: i64 = store
        .conn()
        .query_row("PRAGMA secure_delete", [], |r| r.get(0))
        .unwrap();
    assert_eq!(on, 1);
}

#[test]
fn message_row_debug_hides_body() {
    let (_d, _p, store) = open_tmp();
    let fp = Fingerprint([4; 32]);
    store
        .insert_message(
            fp,
            Direction::In,
            "secret du corps",
            MessageStatus::Delivered,
            5,
            MessageId([1; 16]),
        )
        .unwrap();
    let row = store.messages_with(fp).unwrap().remove(0);
    let dbg = format!("{row:?}");
    assert!(!dbg.contains("secret du corps"), "{dbg}");
    assert!(dbg.contains("15 octets"), "{dbg}");
}

/// Nombre de lignes de la classe donnée.
fn count_class(store: &Store, class: EventClass) -> i64 {
    store
        .conn()
        .query_row(
            "SELECT count(*) FROM transparency WHERE class = ?1",
            params![class as i64],
            |r| r.get(0),
        )
        .unwrap()
}

#[test]
fn log_keeps_at_most_max_rows() {
    let (_d, _p, mut store) = open_tmp();
    let t = 1_000_000_000u64;
    store
        .transaction(|tx| {
            for i in 0..10_050u32 {
                tx.append_event(t, None, EventClass::Routine, &i.to_be_bytes())?;
            }
            Ok(())
        })
        .unwrap();
    let rows = store.events(20_000).unwrap();
    assert_eq!(rows.len(), LOG_MAX_ROWS as usize);
    assert_eq!(rows[0].1, 50u32.to_be_bytes().to_vec());
    assert_eq!(rows.last().unwrap().1, 10_049u32.to_be_bytes().to_vec());
}

#[test]
fn log_row_cap_boundary() {
    for (class, cap) in [
        (EventClass::Routine, LOG_MAX_ROWS),
        (EventClass::Security, LOG_MAX_SECURITY_ROWS),
    ] {
        let (_d, _p, mut store) = open_tmp();
        let t = 1_000_000_000u64;
        let cap = u32::try_from(cap).unwrap();
        store
            .transaction(|tx| {
                for i in 0..cap {
                    tx.append_event(t, None, class, &i.to_be_bytes())?;
                }
                Ok(())
            })
            .unwrap();
        // Exactement le plafond : rien n'est supprimé.
        let rows = store.events(20_000).unwrap();
        assert_eq!(rows.len(), cap as usize);
        assert_eq!(rows[0].1, 0u32.to_be_bytes().to_vec());
        // Une de plus : seule la plus ancienne part.
        store
            .append_event(t, None, class, &cap.to_be_bytes())
            .unwrap();
        let rows = store.events(20_000).unwrap();
        assert_eq!(rows.len(), cap as usize);
        assert_eq!(rows[0].1, 1u32.to_be_bytes().to_vec());
    }
}

#[test]
fn log_cap_spares_security_events() {
    let (_d, _p, mut store) = open_tmp();
    let t = 1_000_000_000u64;
    store
        .append_event(t, None, EventClass::Security, b"cle changee")
        .unwrap();
    store
        .transaction(|tx| {
            for i in 0..10_050u32 {
                tx.append_event(t + 1, None, EventClass::Routine, &i.to_be_bytes())?;
            }
            Ok(())
        })
        .unwrap();
    let rows = store.events(20_000).unwrap();
    assert_eq!(rows[0], (t, b"cle changee".to_vec()));
    assert_eq!(
        count_class(&store, EventClass::Routine),
        LOG_MAX_ROWS as i64
    );
    assert_eq!(count_class(&store, EventClass::Security), 1);
}

#[test]
fn log_age_boundary_30_days() {
    let (_d, _p, store) = open_tmp();
    let t = 1_000_000_000u64;
    let day = 86_400u64;
    for class in [EventClass::Routine, EventClass::Security] {
        store.append_event(t, None, class, b"vieux").unwrap();
    }
    // Horloge qui avance d'un jour au plus par événement : pas de bornage.
    for d in 1..30 {
        store
            .append_event(t + d * day, None, EventClass::Routine, b"jour")
            .unwrap();
    }
    // Exactement 30 jours : conservé.
    store
        .append_event(t + 30 * day, None, EventClass::Routine, b"j30")
        .unwrap();
    let rows = store.events(100).unwrap();
    assert_eq!(rows.iter().filter(|r| r.1 == b"vieux").count(), 2);
    // 30 jours et 1 s : supprimé, sécurité comprise.
    store
        .append_event(t + 30 * day + 1, None, EventClass::Routine, b"j30+1")
        .unwrap();
    let rows = store.events(100).unwrap();
    assert!(rows.iter().all(|r| r.1 != b"vieux"), "{rows:?}");
    assert_eq!(rows.len(), 31);
}

#[test]
fn log_far_future_event_does_not_wipe() {
    let (_d, _p, store) = open_tmp();
    let t = 1_000_000_000u64;
    store
        .append_event(t, None, EventClass::Security, b"a")
        .unwrap();
    store
        .append_event(t + 10, None, EventClass::Routine, b"b")
        .unwrap();
    // Horloge locale déréglée : 10 ans d'avance.
    store
        .append_event(t + 3_650 * 86_400, None, EventClass::Routine, b"futur")
        .unwrap();
    assert_eq!(store.events(10).unwrap().len(), 3);
}

#[test]
fn log_survives_repeated_far_future_events() {
    let (_d, _p, mut store) = open_tmp();
    let t = 1_000_000_000u64;
    store
        .transaction(|tx| {
            for i in 0..100u32 {
                let class = if i % 10 == 0 {
                    EventClass::Security
                } else {
                    EventClass::Routine
                };
                tx.append_event(t, None, class, &i.to_be_bytes())?;
            }
            Ok(())
        })
        .unwrap();
    // Horloge locale bloquée 10 ans en avance, plusieurs événements de suite.
    let future = t + 3_650 * 86_400;
    for _ in 0..5 {
        store
            .append_event(future, None, EventClass::Routine, b"futur")
            .unwrap();
    }
    assert_eq!(store.events(1_000).unwrap().len(), 105);
    assert_eq!(count_class(&store, EventClass::Security), 10);
}

#[test]
fn log_still_purges_with_normal_clock() {
    let (_d, _p, store) = open_tmp();
    let t = 1_000_000_000u64;
    for d in 0..=40u64 {
        store
            .append_event(t + d * 86_400, None, EventClass::Routine, &d.to_be_bytes())
            .unwrap();
    }
    let rows = store.events(100).unwrap();
    // Jour 40 : tout ce qui a plus de 30 jours (jours 0 à 9) est parti.
    assert_eq!(rows.len(), 31);
    assert_eq!(rows[0].0, t + 10 * 86_400);
}

#[test]
fn log_sparse_retention_lags_then_catches_up() {
    let (_d, _p, store) = open_tmp();
    let t = 1_000_000_000u64;
    let day = 86_400u64;
    store
        .append_event(t, None, EventClass::Routine, b"vieux")
        .unwrap();
    // Un événement tous les 10 jours : l'horloge de purge n'avance que de
    // 2 jours par événement, l'entrée de plus de 30 jours est encore là.
    for k in 1..=4u64 {
        store
            .append_event(t + 10 * k * day, None, EventClass::Routine, b"rare")
            .unwrap();
    }
    let rows = store.events(100).unwrap();
    assert!(rows.iter().any(|r| r.1 == b"vieux"), "{rows:?}");
    // Activité quotidienne : l'horloge gagne un jour par jour et rattrape.
    let mut purged_on = None;
    for d in 41..=80u64 {
        store
            .append_event(t + d * day, None, EventClass::Routine, b"jour")
            .unwrap();
        if purged_on.is_none() && !store.events(100).unwrap().iter().any(|r| r.1 == b"vieux") {
            purged_on = Some(d);
        }
    }
    // Horloge de purge à t + 8 j après le 4e événement rare, puis +2 j par
    // jour d'activité : elle dépasse t + 30 j au jour 52 (purge), rattrape
    // l'heure réelle au jour 72 et la suit ensuite.
    assert_eq!(purged_on, Some(52));
    let rows = store.events(100).unwrap();
    assert!(rows.iter().all(|r| r.0 >= t + 50 * day), "{rows:?}");
}

#[test]
fn log_clock_set_back_after_future_still_records() {
    let (_d, _p, store) = open_tmp();
    let t = 1_000_000_000u64;
    store
        .append_event(t, None, EventClass::Security, b"a")
        .unwrap();
    for _ in 0..3 {
        store
            .append_event(t + 3_650 * 86_400, None, EventClass::Routine, b"futur")
            .unwrap();
    }
    // Horloge corrigée : les nouvelles entrées ne sont pas purgées d'emblée.
    store
        .append_event(t + 60, None, EventClass::Routine, b"maintenant")
        .unwrap();
    let rows = store.events(10).unwrap();
    assert_eq!(rows.len(), 5);
    assert!(rows.iter().any(|r| r.1 == b"maintenant"));
}

#[test]
fn log_class_column_added_to_old_database() {
    let (_d, path, store) = open_tmp();
    // Table du journal telle que créée avant la colonne `class`.
    store
        .conn()
        .execute_batch(
            "DROP TABLE transparency; \
             CREATE TABLE transparency (id INTEGER PRIMARY KEY, at INTEGER NOT NULL, \
             packet_id BLOB, event BLOB NOT NULL); \
             INSERT INTO transparency(at, event) VALUES (5, x'01');",
        )
        .unwrap();
    drop(store);
    let store = Store::open(&path, &KEY).unwrap();
    assert_eq!(count_class(&store, EventClass::Routine), 1);
    store
        .append_event(6, None, EventClass::Security, b"s")
        .unwrap();
    assert_eq!(count_class(&store, EventClass::Security), 1);
    // Réouverture : la migration est idempotente.
    drop(store);
    let store = Store::open(&path, &KEY).unwrap();
    assert_eq!(store.events(10).unwrap().len(), 2);
}

#[test]
fn log_purge_tolerates_clock_behind() {
    let (_d, _p, store) = open_tmp();
    let t = 1_000_000_000u64;
    store
        .append_event(t, None, EventClass::Routine, b"a")
        .unwrap();
    store
        .append_event(t - 86_400, None, EventClass::Routine, b"b")
        .unwrap();
    store
        .append_event(0, None, EventClass::Routine, b"c")
        .unwrap();
    assert_eq!(store.events(10).unwrap().len(), 3);
}

#[test]
fn insert_message_duplicate_id_returns_false() {
    let (_d, _p, store) = open_tmp();
    let fp = Fingerprint([4; 32]);
    let mid = MessageId([3; 16]);
    let ins = |body: &str| {
        store
            .insert_message(fp, Direction::In, body, MessageStatus::Delivered, 5, mid)
            .unwrap()
    };
    assert!(ins("a"));
    assert!(!ins("b"));
    assert_eq!(store.messages_with(fp).unwrap().len(), 1);
}

#[test]
fn newer_schema_refused() {
    let (_d, path, store) = open_tmp();
    store.put_meta("schema_version", &3u32).unwrap();
    drop(store);
    assert!(matches!(
        Store::open(&path, &KEY),
        Err(CoreError::Store(m)) if m.contains("plus récent")
    ));
    // Rien n'a été modifié.
    let raw = raw_conn(&path);
    let n: i64 = raw
        .query_row("SELECT count(*) FROM meta", [], |r| r.get(0))
        .unwrap();
    assert!(n >= 1);
}

fn raw_conn(path: &std::path::Path) -> Connection {
    let conn = Connection::open(path).unwrap();
    let hex = data_encoding::HEXLOWER.encode(&KEY);
    conn.execute_batch(&format!("PRAGMA key = \"x'{hex}'\";"))
        .unwrap();
    conn
}

#[test]
fn migration_v1_keeps_history_and_acks() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("v1.sqlite");
    let fp = Fingerprint([4; 32]);
    let (pin, pout, pnull) = ([1u8; 16], [2u8; 16], [3u8; 16]);
    {
        let raw = raw_conn(&path);
        raw.execute_batch(schema::SCHEMA_V1_LEGACY).unwrap();
        raw.execute(
            "INSERT INTO meta(k, v) VALUES ('schema_version', x'01')",
            [],
        )
        .unwrap();
        let ins = |dir: i64, body: &str, st: i64, at: i64, pid: Option<&[u8]>| {
            raw.execute(
                "INSERT INTO messages(contact_fp, direction, body, status, at, packet_id) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![fp.0.as_slice(), dir, body, st, at, pid],
            )
            .unwrap();
        };
        ins(1, "reçu", 3, 10, Some(&pin));
        ins(0, "en attente", 1, 20, Some(&pout));
        ins(1, "sans paquet", 3, 30, None);
        raw.execute(
            "INSERT INTO outbox(packet_id, bytes, kind, expires_at, created_at) \
             VALUES (?1, x'00', 0, 999, 20)",
            params![pout.as_slice()],
        )
        .unwrap();
        let _ = pnull;
    }
    let store = Store::open(&path, &KEY).unwrap();
    assert_eq!(store.get_meta::<u32>("schema_version").unwrap(), Some(2));
    let m = store.messages_with(fp).unwrap();
    let bodies: Vec<_> = m
        .iter()
        .map(|r| (r.body.as_str(), r.direction, r.status))
        .collect();
    assert_eq!(
        bodies,
        vec![
            ("reçu", Direction::In, MessageStatus::Delivered),
            ("en attente", Direction::Out, MessageStatus::Sent),
            ("sans paquet", Direction::In, MessageStatus::Delivered),
        ]
    );
    assert_eq!(
        m[1].message_id,
        MessageId::legacy_from_packet(PacketId(pout))
    );
    assert_eq!(store.outbox_pending(0).unwrap().len(), 1);
    // Le paquet v1 reçu retrouve son message (accusé émis, suppression du contact).
    let got = store.message_by_packet(PacketId(pin)).unwrap().unwrap();
    assert_eq!((got.body.as_str(), got.direction), ("reçu", Direction::In));
    // L'accusé du paquet v1 en attente marque le message livré.
    assert_eq!(
        store.mark_delivered_by_packet(PacketId(pout)).unwrap(),
        Some(m[1].message_id)
    );
    let after = store.messages_with(fp).unwrap();
    assert_eq!(after.len(), 3);
    assert_eq!(after[1].status, MessageStatus::Delivered);
    // Réouverture : la migration n'est pas rejouée.
    drop(store);
    let store = Store::open(&path, &KEY).unwrap();
    assert_eq!(store.messages_with(fp).unwrap().len(), 3);
}

#[test]
fn inbound_packets_map_to_their_message() {
    let (_d, _p, store) = open_tmp();
    let fp = Fingerprint([4; 32]);
    let mid = MessageId::incoming(&fp, &[1; 16]);
    // Lié à l'expéditeur : un autre expéditeur, même identifiant d'enveloppe, autre message.
    assert_ne!(mid, MessageId::incoming(&Fingerprint([5; 32]), &[1; 16]));
    store
        .insert_message(fp, Direction::In, "x", MessageStatus::Delivered, 5, mid)
        .unwrap();
    // Le message et son renvoi (deux paquets) mènent au même message.
    for pid in [PacketId([1; 16]), PacketId([2; 16])] {
        store.record_inbound(pid, mid).unwrap();
        let m = store.message_by_packet(pid).unwrap().unwrap();
        assert_eq!((m.message_id, m.direction), (mid, Direction::In));
    }
    // Un paquet reçu n'est jamais une de mes livraisons.
    assert!(!store.is_my_packet(PacketId([1; 16])).unwrap());
    assert!(
        store
            .mark_delivered_by_packet(PacketId([1; 16]))
            .unwrap()
            .is_none()
    );
}
