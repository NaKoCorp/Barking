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
            .insert_message(fp, Direction::Out, "hi", MessageStatus::Queued, 5, mid)
            .unwrap()
    );
    store.add_delivery(mid, pid, dev, false).unwrap();
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
            false,
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
    // Same device, other contact: distinct sessions, never overwritten.
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
    // The history remains.
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
    // From oldest to newest.
    assert_eq!(
        store.outbox_pending(50).unwrap(),
        vec![
            (a, b"aa".to_vec()),
            (b, b"bb".to_vec()),
            (c, b"cc".to_vec())
        ]
    );
    // An expired entry is no longer returned.
    assert_eq!(store.outbox_pending(101).unwrap().len(), 2);
    assert_eq!(store.outbox_purge_expired(101).unwrap(), 1);
    assert_eq!(store.outbox_purge_expired(101).unwrap(), 0);
    assert!(store.outbox_remove(a).unwrap());
    assert!(!store.outbox_remove(a).unwrap());
    assert_eq!(
        store.outbox_pending(101).unwrap(),
        vec![(b, b"bb".to_vec())]
    );
    // Reinserting the same identifier does not duplicate the row.
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
            "the body secret",
            MessageStatus::Delivered,
            5,
            MessageId([1; 16]),
        )
        .unwrap();
    let row = store.messages_with(fp).unwrap().remove(0);
    let dbg = format!("{row:?}");
    assert!(!dbg.contains("the body secret"), "{dbg}");
    assert!(dbg.contains("15 bytes"), "{dbg}");
}

/// Number of rows of the given class.
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
        // Exactly the cap: nothing is deleted.
        let rows = store.events(20_000).unwrap();
        assert_eq!(rows.len(), cap as usize);
        assert_eq!(rows[0].1, 0u32.to_be_bytes().to_vec());
        // One more: only the oldest goes.
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
        store.append_event(t, None, class, b"old").unwrap();
    }
    // Clock advancing by at most one day per event: no clamping.
    for d in 1..30 {
        store
            .append_event(t + d * day, None, EventClass::Routine, b"day")
            .unwrap();
    }
    // Exactly 30 days: kept.
    store
        .append_event(t + 30 * day, None, EventClass::Routine, b"j30")
        .unwrap();
    let rows = store.events(100).unwrap();
    assert_eq!(rows.iter().filter(|r| r.1 == b"old").count(), 2);
    // 30 days and 1 s: deleted, security included.
    store
        .append_event(t + 30 * day + 1, None, EventClass::Routine, b"j30+1")
        .unwrap();
    let rows = store.events(100).unwrap();
    assert!(rows.iter().all(|r| r.1 != b"old"), "{rows:?}");
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
    // Misadjusted local clock: 10 years ahead.
    store
        .append_event(t + 3_650 * 86_400, None, EventClass::Routine, b"future")
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
    // Local clock stuck 10 years ahead, several events in a row.
    let future = t + 3_650 * 86_400;
    for _ in 0..5 {
        store
            .append_event(future, None, EventClass::Routine, b"future")
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
    // Day 40: everything older than 30 days (days 0 to 9) is gone.
    assert_eq!(rows.len(), 31);
    assert_eq!(rows[0].0, t + 10 * 86_400);
}

#[test]
fn log_sparse_retention_lags_then_catches_up() {
    let (_d, _p, store) = open_tmp();
    let t = 1_000_000_000u64;
    let day = 86_400u64;
    store
        .append_event(t, None, EventClass::Routine, b"old")
        .unwrap();
    // One event every 10 days: the purge clock only advances by
    // 2 days per event, the entry older than 30 days is still there.
    for k in 1..=4u64 {
        store
            .append_event(t + 10 * k * day, None, EventClass::Routine, b"rare")
            .unwrap();
    }
    let rows = store.events(100).unwrap();
    assert!(rows.iter().any(|r| r.1 == b"old"), "{rows:?}");
    // Daily activity: the clock gains a day per day and catches up.
    let mut purged_on = None;
    for d in 41..=80u64 {
        store
            .append_event(t + d * day, None, EventClass::Routine, b"day")
            .unwrap();
        if purged_on.is_none() && !store.events(100).unwrap().iter().any(|r| r.1 == b"old") {
            purged_on = Some(d);
        }
    }
    // Purge clock at t + 8 d after the 4th rare event, then +2 d per
    // day of activity: it exceeds t + 30 d on day 52 (purge), catches up with
    // real time on day 72 and follows it afterwards.
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
            .append_event(t + 3_650 * 86_400, None, EventClass::Routine, b"future")
            .unwrap();
    }
    // Clock corrected: new entries are not purged right away.
    store
        .append_event(t + 60, None, EventClass::Routine, b"now")
        .unwrap();
    let rows = store.events(10).unwrap();
    assert_eq!(rows.len(), 5);
    assert!(rows.iter().any(|r| r.1 == b"now"));
}

#[test]
fn log_class_column_added_to_old_database() {
    let (_d, path, store) = open_tmp();
    // Log table as created before the `class` column.
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
    // Reopening: the migration is idempotent.
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
        Err(CoreError::Store(m)) if m.contains("newer")
    ));
    // Nothing was modified.
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
    let (pin, pout) = ([1u8; 16], [2u8; 16]);
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
        ins(1, "received", 3, 10, Some(&pin));
        ins(0, "en attente", 1, 20, Some(&pout));
        ins(1, "no packet", 3, 30, None);
        raw.execute(
            "INSERT INTO outbox(packet_id, bytes, kind, expires_at, created_at) \
             VALUES (?1, x'00', 0, 999, 20)",
            params![pout.as_slice()],
        )
        .unwrap();
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
            ("received", Direction::In, MessageStatus::Delivered),
            ("en attente", Direction::Out, MessageStatus::Sent),
            ("no packet", Direction::In, MessageStatus::Delivered),
        ]
    );
    assert_eq!(
        m[1].message_id,
        MessageId::legacy_from_packet(PacketId(pout))
    );
    assert_eq!(store.outbox_pending(0).unwrap().len(), 1);
    // The received v1 packet finds its message (acknowledgement emitted, contact deletion).
    let got = store.message_by_packet(PacketId(pin)).unwrap().unwrap();
    assert_eq!(
        (got.body.as_str(), got.direction),
        ("received", Direction::In)
    );
    // The acknowledgement of the pending v1 packet marks the message as delivered.
    assert_eq!(
        store.mark_delivered_by_packet(PacketId(pout)).unwrap(),
        Some(m[1].message_id)
    );
    let after = store.messages_with(fp).unwrap();
    assert_eq!(after.len(), 3);
    assert_eq!(after[1].status, MessageStatus::Delivered);
    // Reopening: the migration is not replayed.
    drop(store);
    let store = Store::open(&path, &KEY).unwrap();
    assert_eq!(store.messages_with(fp).unwrap().len(), 3);
}

#[test]
fn migration_from_pre_1a_database() {
    // v1 database as written before batch 1A: no `class` column in the
    // log, no `schema_version`.
    let dir = tempdir().unwrap();
    let path = dir.path().join("v1-pre-1a.sqlite");
    let fp = Fingerprint([4; 32]);
    let pre_1a = schema::SCHEMA_V1_LEGACY.replace(
        ",\n    -- 0: regular, 1: security (see `EventClass`).\n    \
         class INTEGER NOT NULL DEFAULT 0",
        "",
    );
    assert!(!pre_1a.contains("class INTEGER"));
    {
        let raw = raw_conn(&path);
        raw.execute_batch(&pre_1a).unwrap();
        raw.execute(
            "INSERT INTO messages(contact_fp, direction, body, status, at, packet_id) \
             VALUES (?1, 1, 'old', 3, 10, ?2)",
            params![fp.0.as_slice(), [1u8; 16].as_slice()],
        )
        .unwrap();
        raw.execute(
            "INSERT INTO transparency(at, packet_id, event) VALUES (7, NULL, x'02')",
            [],
        )
        .unwrap();
    }
    let store = Store::open(&path, &KEY).unwrap();
    assert_eq!(store.get_meta::<u32>("schema_version").unwrap(), Some(2));
    let m = store.messages_with(fp).unwrap();
    assert_eq!(m.len(), 1);
    assert_eq!(
        (m[0].body.as_str(), m[0].direction, m[0].status, m[0].at),
        ("old", Direction::In, MessageStatus::Delivered, 10)
    );
    assert_eq!(
        m[0].message_id,
        MessageId::legacy_from_packet(PacketId([1; 16]))
    );
    // Old log kept, classed as regular; the new tables work.
    assert_eq!(store.events(10).unwrap(), vec![(7, vec![2])]);
    assert_eq!(count_class(&store, EventClass::Routine), 1);
    store
        .append_event(8, None, EventClass::Security, b"s")
        .unwrap();
    assert_eq!(count_class(&store, EventClass::Security), 1);
    store
        .record_inbound(PacketId([9; 16]), m[0].message_id)
        .unwrap();
    assert!(
        store
            .message_by_packet(PacketId([1; 16]))
            .unwrap()
            .is_some()
    );
    // Reopening: nothing is replayed.
    drop(store);
    let store = Store::open(&path, &KEY).unwrap();
    assert_eq!(store.messages_with(fp).unwrap().len(), 1);
    assert_eq!(store.events(10).unwrap().len(), 2);
}

#[test]
fn inbound_packets_map_to_their_message() {
    let (_d, _p, store) = open_tmp();
    let fp = Fingerprint([4; 32]);
    let mid = MessageId::incoming(&fp, &[1; 16]);
    // Bound to the sender: another sender, same envelope identifier, another message.
    assert_ne!(mid, MessageId::incoming(&Fingerprint([5; 32]), &[1; 16]));
    store
        .insert_message(fp, Direction::In, "x", MessageStatus::Delivered, 5, mid)
        .unwrap();
    // The message and its resend (two packets) lead to the same message.
    for pid in [PacketId([1; 16]), PacketId([2; 16])] {
        store.record_inbound(pid, mid).unwrap();
        let m = store.message_by_packet(pid).unwrap().unwrap();
        assert_eq!((m.message_id, m.direction), (mid, Direction::In));
    }
    // A received packet is never one of my deliveries.
    assert!(!store.is_my_packet(PacketId([1; 16])).unwrap());
    assert!(
        store
            .mark_delivered_by_packet(PacketId([1; 16]))
            .unwrap()
            .is_none()
    );
}

#[test]
fn v2_database_without_inbound_gets_it() {
    // Development v2 database created before the `inbound` table was added.
    let (_d, path, store) = open_tmp();
    drop(store);
    raw_conn(&path)
        .execute_batch("DROP TABLE inbound;")
        .unwrap();
    let store = Store::open(&path, &KEY).unwrap();
    assert_eq!(store.get_meta::<u32>("schema_version").unwrap(), Some(2));
    let fp = Fingerprint([4; 32]);
    let mid = MessageId::incoming(&fp, &[1; 16]);
    store
        .insert_message(fp, Direction::In, "x", MessageStatus::Delivered, 5, mid)
        .unwrap();
    store.record_inbound(PacketId([1; 16]), mid).unwrap();
    assert!(
        store
            .message_by_packet(PacketId([1; 16]))
            .unwrap()
            .is_some()
    );
}

#[test]
fn own_delivery_never_aggregates_and_survives_contact_removal() {
    let (_d, path, store) = open_tmp();
    let fp = Fingerprint([4; 32]);
    let mid = MessageId([6; 16]);
    let dev = crate::identity::device::DeviceId([5; 16]);
    let mine = crate::identity::device::DeviceId([8; 16]);
    let (to_bob, to_me) = (PacketId([1; 16]), PacketId([2; 16]));
    store
        .insert_message(fp, Direction::Out, "x", MessageStatus::Sent, 5, mid)
        .unwrap();
    store.add_delivery(mid, to_bob, dev, false).unwrap();
    store.add_delivery(mid, to_me, mine, true).unwrap();
    for id in [to_bob, to_me] {
        store.outbox_put(id, b"p", Kind::Message, 999, 5).unwrap();
    }
    // My device's acknowledgement: delivery recorded, message still `Sent`.
    assert_eq!(store.mark_delivered_by_packet(to_me).unwrap(), Some(mid));
    assert!(store.delivery_acked(to_me).unwrap());
    assert_eq!(
        store.messages_with(fp).unwrap()[0].status,
        MessageStatus::Sent
    );
    // Contact deletion: the copy for my device stays in the queue.
    store.upsert_contact(fp, b"c", "", false).unwrap();
    store.delete_contact(fp).unwrap();
    let left: Vec<PacketId> = store
        .outbox_pending(0)
        .unwrap()
        .into_iter()
        .map(|(id, _)| id)
        .collect();
    assert_eq!(left, vec![to_me]);
    // v2 database created before the `own` column: it is added on open.
    drop(store);
    let raw = raw_conn(&path);
    raw.execute_batch(
        "DROP TABLE deliveries; CREATE TABLE deliveries (message_id BLOB NOT NULL, \
         packet_id BLOB UNIQUE NOT NULL, device BLOB NOT NULL, status INTEGER NOT NULL); \
         DROP TABLE contact_clock; \
         CREATE TABLE contact_clock (fp BLOB PRIMARY KEY NOT NULL, at INTEGER NOT NULL, \
         removed INTEGER NOT NULL); \
         INSERT INTO contact_clock(fp, at, removed) VALUES (x'0909090909090909090909090909090909090909090909090909090909090909', 3, 0);",
    )
    .unwrap();
    drop(raw);
    let store = Store::open(&path, &KEY).unwrap();
    store.add_delivery(mid, to_me, mine, true).unwrap();
    // Column `writer` added: unknown author (null) for the old row.
    let zero = crate::identity::device::DeviceId([0; 16]);
    assert_eq!(
        store.contact_clock(Fingerprint([9; 32])).unwrap(),
        Some(ContactClock {
            at: 3,
            removed: false,
            writer: zero
        })
    );
    let clock = ContactClock {
        at: 7,
        removed: true,
        writer: mine,
    };
    store.set_contact_clock(fp, &clock).unwrap();
    assert_eq!(store.contact_clock(fp).unwrap(), Some(clock));
}

#[test]
fn contact_clock_order_breaks_ties() {
    let d = |b| crate::identity::device::DeviceId([b; 16]);
    let c = |at, removed, w| ContactClock {
        at,
        removed,
        writer: d(w),
    };
    assert!(c(1, false, 0).newer_than(None));
    assert!(c(2, false, 0).newer_than(Some(&c(1, true, 9))));
    assert!(c(2, true, 0).newer_than(Some(&c(2, false, 9))));
    assert!(c(2, false, 5).newer_than(Some(&c(2, false, 4))));
    assert!(!c(2, false, 4).newer_than(Some(&c(2, false, 5))));
    // The same operation is not more recent than itself.
    assert!(!c(2, false, 4).newer_than(Some(&c(2, false, 4))));
}

#[test]
fn arr_refuses_wrong_length() {
    assert_eq!(arr::<4>(vec![1, 2, 3, 4]).unwrap(), [1, 2, 3, 4]);
    assert_eq!(
        arr::<32>(vec![7; 31]),
        Err(CoreError::Store("invalid field length".into()))
    );
}
