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
    assert_eq!(
        store.get_meta::<u32>("schema_version").unwrap(),
        Some(schema::SCHEMA_VERSION)
    );
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
            .insert_message(fp, Direction::Out, "hi", MessageStatus::Pending, 5, mid)
            .unwrap()
    );
    store.add_delivery(mid, pid, dev, false, 5, 1024).unwrap();
    assert_eq!(store.mark_delivered_by_packet(pid, 9).unwrap(), Some(mid));
    crate::core::delivery::recompute_message_status(&store, mid).unwrap();
    let m = store.messages_with(fp, 0).unwrap();
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].status, MessageStatus::Received);
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
            MessageStatus::OnNetwork,
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
            5,
            1024,
        )
        .unwrap();
    let m = store.message_by_packet(pid).unwrap().unwrap();
    assert_eq!(m.message_id, MessageId([6; 16]));
    assert_eq!(m.direction, Direction::Out);
    assert_eq!(m.status, MessageStatus::OnNetwork);

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
    assert_eq!(store.messages_with(fp, 0).unwrap().len(), 1);
}

#[test]
fn transparency_page_filters_and_pages() {
    let (_d, _p, store) = open_tmp();
    for i in 0..250u32 {
        let class = if i % 25 == 0 {
            EventClass::Security
        } else {
            EventClass::Routine
        };
        store
            .append_event(u64::from(i), None, class, &i.to_be_bytes())
            .unwrap();
    }
    let p1 = store.transparency_page(100, None, false).unwrap();
    assert_eq!(p1.len(), 100);
    let p2 = store.transparency_page(100, Some(p1[99].0), false).unwrap();
    assert_eq!(p2.len(), 100);
    let p3 = store.transparency_page(100, Some(p2[99].0), false).unwrap();
    assert_eq!(p3.len(), 50);
    assert!(
        store
            .transparency_page(100, Some(p3[49].0), false)
            .unwrap()
            .is_empty()
    );
    let sec = store.transparency_page(100, None, true).unwrap();
    assert_eq!(sec.len(), 10);
    // Newest first, security only.
    assert_eq!(sec[0].1, 225);
    assert_eq!(sec[9].1, 0);
    assert_eq!(p1[0].1, 249);
    assert_eq!(p1[99].1, 150);
    assert_eq!(p2[0].1, 149);
}

/// Events appended (or purged) between two pages neither repeat nor skip a
/// row: the next page starts from the id of the last row seen.
#[test]
fn transparency_paging_is_stable_while_the_log_moves() {
    let (_d, _p, store) = open_tmp();
    for i in 0..30u32 {
        store
            .append_event(u64::from(i), None, EventClass::Routine, &i.to_be_bytes())
            .unwrap();
    }
    let p1 = store.transparency_page(10, None, false).unwrap();
    // 5 new events arrive while the user scrolls.
    for i in 30..35u32 {
        store
            .append_event(u64::from(i), None, EventClass::Routine, &i.to_be_bytes())
            .unwrap();
    }
    let p2 = store.transparency_page(10, Some(p1[9].0), false).unwrap();
    let ats: Vec<u64> = p1.iter().chain(p2.iter()).map(|r| r.1).collect();
    assert_eq!(
        ats,
        (10..30).rev().collect::<Vec<u64>>(),
        "no overlap, no gap"
    );
    // The oldest rows go away (purge): the next page has no gap either.
    store
        .conn()
        .execute("DELETE FROM transparency WHERE at < 5", [])
        .unwrap();
    let p3 = store.transparency_page(10, Some(p2[9].0), false).unwrap();
    assert_eq!(
        p3.iter().map(|r| r.1).collect::<Vec<_>>(),
        (5..10).rev().collect::<Vec<u64>>()
    );
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
    store
        .outbox_put(b, b"bb", Kind::Message, 500, 20, None)
        .unwrap();
    store
        .outbox_put(a, b"aa", Kind::Message, 500, 10, None)
        .unwrap();
    store
        .outbox_put(c, b"cc", Kind::Ack, 100, 30, None)
        .unwrap();
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
    store
        .outbox_put(b, b"bb", Kind::Message, 500, 20, None)
        .unwrap();
    assert_eq!(store.outbox_pending(101).unwrap().len(), 1);
}

#[test]
fn outbox_put_rolls_back_with_transaction() {
    use crate::packet::Kind;
    let (_d, _p, mut store) = open_tmp();
    let r: crate::Result<()> = store.transaction(|tx| {
        tx.outbox_put(PacketId([1; 16]), b"x", Kind::Message, 500, 1, None)?;
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
            MessageStatus::Received,
            5,
            MessageId([1; 16]),
        )
        .unwrap();
    let row = store.messages_with(fp, 0).unwrap().remove(0);
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
            .insert_message(fp, Direction::In, body, MessageStatus::Received, 5, mid)
            .unwrap()
    };
    assert!(ins("a"));
    assert!(!ins("b"));
    assert_eq!(store.messages_with(fp, 0).unwrap().len(), 1);
}

#[test]
fn newer_schema_refused() {
    let (_d, path, store) = open_tmp();
    store
        .put_meta("schema_version", &(schema::SCHEMA_VERSION + 1))
        .unwrap();
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
    assert_eq!(
        store.get_meta::<u32>("schema_version").unwrap(),
        Some(schema::SCHEMA_VERSION)
    );
    let m = store.messages_with(fp, 0).unwrap();
    let bodies: Vec<_> = m
        .iter()
        .map(|r| (r.body.as_str(), r.direction, r.status))
        .collect();
    assert_eq!(
        bodies,
        vec![
            ("received", Direction::In, MessageStatus::Received),
            // Still queued without a known deposit: pending (v3 backfill).
            ("en attente", Direction::Out, MessageStatus::Pending),
            ("no packet", Direction::In, MessageStatus::Received),
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
        store.mark_delivered_by_packet(PacketId(pout), 50).unwrap(),
        Some(m[1].message_id)
    );
    crate::core::delivery::recompute_message_status(&store, m[1].message_id).unwrap();
    let after = store.messages_with(fp, 0).unwrap();
    assert_eq!(after.len(), 3);
    assert_eq!(after[1].status, MessageStatus::Received);
    // Reopening: the migration is not replayed.
    drop(store);
    let store = Store::open(&path, &KEY).unwrap();
    assert_eq!(store.messages_with(fp, 0).unwrap().len(), 3);
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
    assert_eq!(
        store.get_meta::<u32>("schema_version").unwrap(),
        Some(schema::SCHEMA_VERSION)
    );
    let m = store.messages_with(fp, 0).unwrap();
    assert_eq!(m.len(), 1);
    assert_eq!(
        (m[0].body.as_str(), m[0].direction, m[0].status, m[0].at),
        ("old", Direction::In, MessageStatus::Received, 10)
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
        .record_inbound(PacketId([9; 16]), m[0].message_id, Fingerprint([0; 32]))
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
    assert_eq!(store.messages_with(fp, 0).unwrap().len(), 1);
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
        .insert_message(fp, Direction::In, "x", MessageStatus::Received, 5, mid)
        .unwrap();
    // The message and its resend (two packets) lead to the same message.
    for pid in [PacketId([1; 16]), PacketId([2; 16])] {
        store
            .record_inbound(pid, mid, Fingerprint([0; 32]))
            .unwrap();
        let m = store.message_by_packet(pid).unwrap().unwrap();
        assert_eq!((m.message_id, m.direction), (mid, Direction::In));
    }
    // A received packet is never one of my deliveries.
    assert!(!store.is_my_packet(PacketId([1; 16])).unwrap());
    assert!(
        store
            .mark_delivered_by_packet(PacketId([1; 16]), 5)
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
    assert_eq!(
        store.get_meta::<u32>("schema_version").unwrap(),
        Some(schema::SCHEMA_VERSION)
    );
    let fp = Fingerprint([4; 32]);
    let mid = MessageId::incoming(&fp, &[1; 16]);
    store
        .insert_message(fp, Direction::In, "x", MessageStatus::Received, 5, mid)
        .unwrap();
    store
        .record_inbound(PacketId([1; 16]), mid, Fingerprint([0; 32]))
        .unwrap();
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
        .insert_message(fp, Direction::Out, "x", MessageStatus::Pending, 5, mid)
        .unwrap();
    store
        .add_delivery(mid, to_bob, dev, false, 5, 1024)
        .unwrap();
    store.add_delivery(mid, to_me, mine, true, 5, 1024).unwrap();
    for id in [to_bob, to_me] {
        store
            .outbox_put(id, b"p", Kind::Message, 999, 5, None)
            .unwrap();
    }
    // My device's acknowledgement: delivery recorded, message still `Pending`.
    assert_eq!(store.mark_delivered_by_packet(to_me, 6).unwrap(), Some(mid));
    crate::core::delivery::recompute_message_status(&store, mid).unwrap();
    assert!(store.delivery_acked(to_me).unwrap());
    assert_eq!(
        store.messages_with(fp, 0).unwrap()[0].status,
        MessageStatus::Pending
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
    // v2 database created before the `own` column: it is added on open
    // (then the v3 migration runs, from a v2 queue).
    drop(store);
    let raw = raw_conn(&path);
    raw.execute_batch(
        "UPDATE meta SET v = x'02' WHERE k = 'schema_version'; \
         DROP TABLE outbox; CREATE TABLE outbox (packet_id BLOB PRIMARY KEY NOT NULL, \
         bytes BLOB NOT NULL, kind INTEGER NOT NULL, expires_at INTEGER NOT NULL, \
         created_at INTEGER NOT NULL); \
         DROP TABLE deliveries; CREATE TABLE deliveries (message_id BLOB NOT NULL, \
         packet_id BLOB UNIQUE NOT NULL, device BLOB NOT NULL, status INTEGER NOT NULL); \
         DROP TABLE contact_clock; \
         CREATE TABLE contact_clock (fp BLOB PRIMARY KEY NOT NULL, at INTEGER NOT NULL, \
         removed INTEGER NOT NULL); \
         INSERT INTO contact_clock(fp, at, removed) VALUES (x'0909090909090909090909090909090909090909090909090909090909090909', 3, 0);",
    )
    .unwrap();
    drop(raw);
    let store = Store::open(&path, &KEY).unwrap();
    assert_eq!(
        store.get_meta::<u32>("schema_version").unwrap(),
        Some(schema::SCHEMA_VERSION)
    );
    store.add_delivery(mid, to_me, mine, true, 5, 1024).unwrap();
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

// --- Schema v3: delivery times and honest message states.

/// Reference v2 database for the v2 → v3 migration, committed under
/// `tests/data` and regenerated by `make_v2_fixture`.
fn v2_fixture_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/v2-deliveries.sqlite")
}

/// Contact of every fixture message.
const FX_FP: [u8; 32] = [4; 32];
/// Short node identifiers of the fixture's `Deposited` steps.
const FX_NODE: &str = "K7QX2M4A";
const FX_NODE_LATE: &str = "ZZ2Q7M4B";

/// Builds an empty v2 database on `conn` with the v2 schema code only (the
/// v1 schema, the v1 → v2 migration and the v2 additions applied at open),
/// so that the fixture stays reproducible once the store opens v3.
fn build_v2_schema(conn: &Connection) {
    conn.execute_batch(schema::SCHEMA_V1_LEGACY).unwrap();
    schema::migrate_v1_to_v2(conn).unwrap();
    conn.execute_batch(schema::CONTACTS_ADD_VERIFIED_AT)
        .unwrap();
    conn.execute_batch(schema::TRANSPARENCY_INDEXES).unwrap();
    conn.execute_batch(schema::ROUTE_STEPS).unwrap();
}

/// Writes the v2 reference database (`tests/data/v2-deliveries.sqlite`,
/// encrypted with `KEY`). Run on demand:
/// `cargo nextest run -p barking-core --run-ignored only make_v2_fixture`.
///
/// Content (contact `FX_FP`, statuses as stored by v2: deliveries 1 or 3):
/// - message 0x11 (out, 3, at 100): delivery 0xA1 to device 0xD1, acked
///   (steps Sealed 101 size 2048, Deposited 110 on `FX_NODE`, Deposited 115
///   on `FX_NODE_LATE`, AckVerified 130; left the queue); delivery 0xA2 to
///   device 0xD2 (Sealed 101 size 2048, still queued, never deposited); own
///   copy 0xA3 to my device 0xE1 (OwnCopy 102, Deposited 112 on `FX_NODE`,
///   still queued);
/// - message 0x22 (out, 1, at 200): delivery 0xB1 (Sealed 200 size 1024),
///   still queued without a deposit;
/// - message 0x33 (out, 1, at 300): delivery 0xC1 without any route row,
///   no longer queued;
/// - message 0x44 (out, 3, at 400): delivery 0xC2 acked, route purged;
/// - message 0x55 (out, 1, at 500): delivery 0xC3 (Sealed 500 size 1024,
///   Deposited 510 on `FX_NODE`), still queued;
/// - card update 0x66 (no message row): delivery 0xC4 still queued, no route;
/// - message 0x77 (in, 3, at 600);
/// - message 0x88 (out, 1, at 700) sent from another of my devices: no delivery;
/// - a queued receipt 0xF1 (kind ack), without a delivery.
#[test]
#[ignore = "writes the committed v2 fixture"]
fn make_v2_fixture() {
    let path = v2_fixture_path();
    let _ = std::fs::remove_file(&path);
    let conn = raw_conn(&path);
    build_v2_schema(&conn);
    let fp = FX_FP.as_slice();
    let msg = |mid: u8, dir: i64, status: i64, at: i64| {
        conn.execute(
            "INSERT INTO messages(message_id, contact_fp, direction, body, status, at) \
             VALUES (?1, ?2, ?3, 'm', ?4, ?5)",
            params![[mid; 16].as_slice(), fp, dir, status, at],
        )
        .unwrap();
    };
    let delivery = |mid: u8, pid: u8, dev: u8, status: i64, own: i64| {
        conn.execute(
            "INSERT INTO deliveries(message_id, packet_id, device, status, own) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                [mid; 16].as_slice(),
                [pid; 16].as_slice(),
                [dev; 16].as_slice(),
                status,
                own
            ],
        )
        .unwrap();
    };
    let step = |pid: u8, at: i64, step: i64, node: Option<&str>, size: Option<i64>| {
        conn.execute(
            "INSERT INTO route_steps(packet_id, at, step, node, size) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![[pid; 16].as_slice(), at, step, node, size],
        )
        .unwrap();
    };
    let queued = |pid: u8, kind: i64, created: i64| {
        conn.execute(
            "INSERT INTO outbox(packet_id, bytes, kind, expires_at, created_at) \
             VALUES (?1, x'00', ?2, 999999, ?3)",
            params![[pid; 16].as_slice(), kind, created],
        )
        .unwrap();
    };
    // Steps as stored by `RouteStep`: Sealed 0, Deposited 1, AckVerified 4, OwnCopy 5.
    msg(0x11, 0, 3, 100);
    delivery(0x11, 0xA1, 0xD1, 3, 0);
    step(0xA1, 101, 0, None, Some(2048));
    step(0xA1, 115, 1, Some(FX_NODE_LATE), None);
    step(0xA1, 110, 1, Some(FX_NODE), None);
    step(0xA1, 130, 4, None, None);
    delivery(0x11, 0xA2, 0xD2, 1, 0);
    step(0xA2, 101, 0, None, Some(2048));
    queued(0xA2, 0, 101);
    delivery(0x11, 0xA3, 0xE1, 1, 1);
    step(0xA3, 102, 5, None, None);
    step(0xA3, 112, 1, Some(FX_NODE), None);
    queued(0xA3, 0, 102);
    msg(0x22, 0, 1, 200);
    delivery(0x22, 0xB1, 0xD1, 1, 0);
    step(0xB1, 200, 0, None, Some(1024));
    queued(0xB1, 0, 200);
    msg(0x33, 0, 1, 300);
    delivery(0x33, 0xC1, 0xD1, 1, 0);
    msg(0x44, 0, 3, 400);
    delivery(0x44, 0xC2, 0xD1, 3, 0);
    msg(0x55, 0, 1, 500);
    delivery(0x55, 0xC3, 0xD1, 1, 0);
    step(0xC3, 500, 0, None, Some(1024));
    step(0xC3, 510, 1, Some(FX_NODE), None);
    queued(0xC3, 0, 500);
    delivery(0x66, 0xC4, 0xD1, 1, 0);
    queued(0xC4, 0, 550);
    msg(0x77, 1, 3, 600);
    msg(0x88, 0, 1, 700);
    queued(0xF1, 1, 650);
    let version: Vec<u8> = conn
        .query_row("SELECT v FROM meta WHERE k = 'schema_version'", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(version, postcard::to_allocvec(&2u32).unwrap());
}

/// Copy of the v2 fixture in a fresh directory.
fn v2_fixture_copy() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("v2.sqlite");
    std::fs::copy(v2_fixture_path(), &path).unwrap();
    (dir, path)
}

/// Delivery columns of packet `[pid; 16]`: status, sealed_at, deposited_at,
/// node, size, acked_at, expired_at.
type DeliveryCols = (
    i64,
    i64,
    Option<i64>,
    Option<String>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
);

fn delivery_cols(conn: &Connection, pid: u8) -> DeliveryCols {
    conn.query_row(
        "SELECT status, sealed_at, deposited_at, node, size, acked_at, expired_at \
         FROM deliveries WHERE packet_id = ?1",
        params![[pid; 16].as_slice()],
        |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
            ))
        },
    )
    .unwrap()
}

fn outbox_cols(conn: &Connection, pid: u8) -> (Option<i64>, Option<Vec<u8>>) {
    conn.query_row(
        "SELECT deposited_at, ref FROM outbox WHERE packet_id = ?1",
        params![[pid; 16].as_slice()],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .unwrap()
}

fn message_status(conn: &Connection, mid: u8) -> i64 {
    conn.query_row(
        "SELECT status FROM messages WHERE message_id = ?1",
        params![[mid; 16].as_slice()],
        |r| r.get(0),
    )
    .unwrap()
}

fn has_column(conn: &Connection, table: &str, column: &str) -> bool {
    conn.query_row(
        "SELECT count(*) > 0 FROM pragma_table_info(?1) WHERE name = ?2",
        params![table, column],
        |r| r.get(0),
    )
    .unwrap()
}

fn has_object(conn: &Connection, kind: &str, name: &str) -> bool {
    conn.query_row(
        "SELECT count(*) > 0 FROM sqlite_master WHERE type = ?1 AND name = ?2",
        params![kind, name],
        |r| r.get(0),
    )
    .unwrap()
}

#[test]
fn migrate_v2_to_v3_backfills_from_route_steps() {
    let (_d, path) = v2_fixture_copy();
    let store = Store::open(&path, &KEY).unwrap();
    assert_eq!(
        store.get_meta::<u32>("schema_version").unwrap(),
        Some(schema::SCHEMA_VERSION)
    );
    let c = store.conn();
    let node = Some(FX_NODE.to_owned());
    // Acked: first deposit (min(at)) and its node, Sealed size, AckVerified time.
    assert_eq!(
        delivery_cols(c, 0xA1),
        (3, 101, Some(110), node.clone(), Some(2048), Some(130), None)
    );
    // Still queued without a deposit: back to Pending.
    assert_eq!(
        delivery_cols(c, 0xA2),
        (0, 101, None, None, Some(2048), None, None)
    );
    // Own copy: sealed at its OwnCopy step, deposited, no size.
    assert_eq!(
        delivery_cols(c, 0xA3),
        (1, 102, Some(112), node.clone(), None, None, None)
    );
    assert_eq!(
        delivery_cols(c, 0xB1),
        (0, 200, None, None, Some(1024), None, None)
    );
    // No route row, out of the queue: sealed at the message's time, status kept.
    assert_eq!(
        delivery_cols(c, 0xC1),
        (1, 300, None, None, None, None, None)
    );
    // Acked with its route purged: acked at its sealing time.
    assert_eq!(
        delivery_cols(c, 0xC2),
        (3, 400, None, None, None, Some(400), None)
    );
    assert_eq!(
        delivery_cols(c, 0xC3),
        (1, 500, Some(510), node, Some(1024), None, None)
    );
    // Card update: no step, no message row.
    assert_eq!(delivery_cols(c, 0xC4), (0, 0, None, None, None, None, None));
    // The queue takes the deposit of its packet's delivery; a receipt has none.
    assert_eq!(outbox_cols(c, 0xA2), (None, None));
    assert_eq!(outbox_cols(c, 0xA3), (Some(112), None));
    assert_eq!(outbox_cols(c, 0xB1), (None, None));
    assert_eq!(outbox_cols(c, 0xC3), (Some(510), None));
    assert_eq!(outbox_cols(c, 0xC4), (None, None));
    assert_eq!(outbox_cols(c, 0xF1), (None, None));
    // Messages recomputed from their contact deliveries; the own copy of
    // 0x11 does not count. Received and deliveryless messages untouched.
    let statuses: Vec<i64> = [0x11, 0x22, 0x33, 0x44, 0x55, 0x77, 0x88]
        .into_iter()
        .map(|m| message_status(c, m))
        .collect();
    assert_eq!(statuses, vec![3, 0, 1, 3, 1, 3, 1]);
    assert!(has_object(c, "table", "deleted_messages"));
    assert!(has_column(c, "outbox", "deposit_tried_at"));
    assert!(has_object(c, "index", "messages_delivery"));
    assert!(has_object(c, "index", "outbox_waiting"));
    // Reopening: the migration is not replayed.
    drop(store);
    let store = Store::open(&path, &KEY).unwrap();
    assert_eq!(
        store.get_meta::<u32>("schema_version").unwrap(),
        Some(schema::SCHEMA_VERSION)
    );
    assert_eq!(delivery_cols(store.conn(), 0xA2).0, 0);
    assert_eq!(message_status(store.conn(), 0x22), 0);
}

#[test]
fn migration_is_one_transaction() {
    let (_d, path) = v2_fixture_copy();
    {
        let conn = raw_conn(&path);
        let failed = schema::migrate_v2_to_v3_hooked(&conn, |_| {
            Err(rusqlite::Error::InvalidParameterName("injected".into()))
        });
        assert!(failed.is_err());
        let version: Vec<u8> = conn
            .query_row("SELECT v FROM meta WHERE k = 'schema_version'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(version, postcard::to_allocvec(&2u32).unwrap());
        assert!(!has_column(&conn, "deliveries", "sealed_at"));
        assert!(!has_column(&conn, "outbox", "ref"));
        assert!(!has_column(&conn, "outbox", "deposit_tried_at"));
        assert!(!has_object(&conn, "table", "deleted_messages"));
        assert_eq!(delivery_cols_v2_status(&conn, 0xA2), 1);
    }
    // The untouched v2 database still migrates on the next open.
    let store = Store::open(&path, &KEY).unwrap();
    assert_eq!(
        store.get_meta::<u32>("schema_version").unwrap(),
        Some(schema::SCHEMA_VERSION)
    );
    assert_eq!(delivery_cols(store.conn(), 0xA2).0, 0);
}

fn delivery_cols_v2_status(conn: &Connection, pid: u8) -> i64 {
    conn.query_row(
        "SELECT status FROM deliveries WHERE packet_id = ?1",
        params![[pid; 16].as_slice()],
        |r| r.get(0),
    )
    .unwrap()
}

#[test]
fn v3_database_without_deposit_tried_at_gets_it() {
    let (_d, path) = v2_fixture_copy();
    drop(Store::open(&path, &KEY).unwrap());
    // A development database migrated to v3 before the column existed.
    {
        let conn = raw_conn(&path);
        conn.execute_batch("ALTER TABLE outbox DROP COLUMN deposit_tried_at;")
            .unwrap();
        assert!(!has_column(&conn, "outbox", "deposit_tried_at"));
    }
    let store = Store::open(&path, &KEY).unwrap();
    assert!(has_column(store.conn(), "outbox", "deposit_tried_at"));
    assert_eq!(
        store.get_meta::<u32>("schema_version").unwrap(),
        Some(schema::SCHEMA_VERSION)
    );
}

#[test]
fn v4_database_without_superseded_gets_it() {
    let (_d, path, store) = open_tmp();
    // A development database at v4 before the column existed.
    store
        .conn()
        .execute_batch("ALTER TABLE reaction_sends DROP COLUMN superseded;")
        .unwrap();
    assert!(!has_column(store.conn(), "reaction_sends", "superseded"));
    drop(store);
    let store = Store::open(&path, &KEY).unwrap();
    assert!(has_column(store.conn(), "reaction_sends", "superseded"));
    drop(store);
    Store::open(&path, &KEY).unwrap();
}

#[test]
fn v4_database_without_reaction_sends_target_gets_it() {
    let (_d, path, store) = open_tmp();
    assert!(has_object(store.conn(), "index", "reaction_sends_target"));
    // A development database at v4 before the index existed.
    store
        .conn()
        .execute_batch("DROP INDEX IF EXISTS reaction_sends_target;")
        .unwrap();
    drop(store);
    let store = Store::open(&path, &KEY).unwrap();
    assert!(has_object(store.conn(), "index", "reaction_sends_target"));
    drop(store);
    Store::open(&path, &KEY).unwrap();
}

#[test]
fn v3_database_upgrades_to_v4() {
    let (_d, path, store) = open_tmp();
    // Turn the fresh database back into a v3 one.
    store
        .conn()
        .execute_batch(
            "DROP TABLE reactions; DROP TABLE reaction_sends; \
             ALTER TABLE messages DROP COLUMN wire_id; \
             ALTER TABLE messages DROP COLUMN reply_to; \
             ALTER TABLE messages DROP COLUMN reply_ref; \
             ALTER TABLE messages DROP COLUMN placeholder;",
        )
        .unwrap();
    store.put_meta("schema_version", &3u32).unwrap();
    drop(store);
    assert_eq!(
        Store::open_read(&path, &KEY).err().unwrap(),
        CoreError::Store("database schema not current".into())
    );
    let store = Store::open(&path, &KEY).unwrap();
    assert_eq!(
        store.get_meta::<u32>("schema_version").unwrap(),
        Some(schema::SCHEMA_VERSION)
    );
    let cols: Vec<String> = store
        .conn()
        .prepare("SELECT name FROM pragma_table_info('messages')")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    for c in ["wire_id", "reply_to", "reply_ref", "placeholder"] {
        assert!(cols.iter().any(|n| n == c), "{c} missing");
    }
    for t in ["reactions", "reaction_sends"] {
        assert!(has_object(store.conn(), "table", t), "{t} missing");
    }
    drop(store);
    Store::open_read(&path, &KEY).unwrap();
}

#[test]
fn migrates_v4_to_v5() {
    let (_d, path, store) = open_tmp();
    // Turn the fresh database back into a v4 one.
    store
        .conn()
        .execute_batch(
            "DROP INDEX messages_expire; DROP TABLE pending_seen; \
             ALTER TABLE messages DROP COLUMN ttl_secs; \
             ALTER TABLE messages DROP COLUMN seen_at; \
             ALTER TABLE messages DROP COLUMN expire_at;",
        )
        .unwrap();
    store.put_meta("schema_version", &4u32).unwrap();
    drop(store);
    assert_eq!(
        Store::open_read(&path, &KEY).err().unwrap(),
        CoreError::Store("database schema not current".into())
    );
    let store = Store::open(&path, &KEY).unwrap();
    assert_eq!(
        store.get_meta::<u32>("schema_version").unwrap(),
        Some(schema::SCHEMA_VERSION)
    );
    for c in ["ttl_secs", "seen_at", "expire_at"] {
        assert!(has_column(store.conn(), "messages", c), "{c} missing");
    }
    for (kind, name) in [
        ("table", "pending_seen"),
        ("index", "pending_seen_contact"),
        ("index", "messages_expire"),
    ] {
        assert!(has_object(store.conn(), kind, name), "{name} missing");
    }
    for c in ["message_id", "contact_fp", "seen_at", "received_at"] {
        assert!(has_column(store.conn(), "pending_seen", c), "{c} missing");
    }
    drop(store);
    Store::open_read(&path, &KEY).unwrap();
}

#[test]
fn migrates_v5_to_v6() {
    let (_d, path, store) = open_tmp();
    // Turn the fresh database back into a v5 one.
    store
        .conn()
        .execute_batch(
            "DROP TABLE contact_requests; DROP TABLE pending_initials; \
             DROP TABLE refused_requests; DROP TABLE invites; DROP TABLE invite_packets;",
        )
        .unwrap();
    store.put_meta("schema_version", &5u32).unwrap();
    drop(store);
    assert_eq!(
        Store::open_read(&path, &KEY).err().unwrap(),
        CoreError::Store("database schema not current".into())
    );
    let store = Store::open(&path, &KEY).unwrap();
    assert_eq!(
        store.get_meta::<u32>("schema_version").unwrap(),
        Some(schema::SCHEMA_VERSION)
    );
    for t in [
        "contact_requests",
        "pending_initials",
        "refused_requests",
        "invites",
        "invite_packets",
    ] {
        assert!(has_object(store.conn(), "table", t), "{t} missing");
    }
    for i in ["pending_initials_ik", "pending_initials_fp"] {
        assert!(has_object(store.conn(), "index", i), "{i} missing");
    }
    drop(store);
    Store::open_read(&path, &KEY).unwrap();
    // Replaying the migration on a newer database is harmless: it only
    // creates what is missing (and writes its own version back).
    let store = Store::open(&path, &KEY).unwrap();
    schema::migrate_v5_to_v6(store.conn()).unwrap();
    assert_eq!(store.get_meta::<u32>("schema_version").unwrap(), Some(6));
}

#[test]
fn migration_adds_gif_column() {
    let (_d, path, store) = open_tmp();
    let fp = Fingerprint([4; 32]);
    assert!(
        store
            .insert_message(
                fp,
                Direction::In,
                "old",
                MessageStatus::Received,
                100,
                MessageId([1; 16]),
            )
            .unwrap()
    );
    // Turn the fresh database back into a v8 one.
    store
        .conn()
        .execute_batch("ALTER TABLE messages DROP COLUMN gif;")
        .unwrap();
    store.put_meta("schema_version", &8u32).unwrap();
    drop(store);
    assert_eq!(
        Store::open_read(&path, &KEY).err().unwrap(),
        CoreError::Store("database schema not current".into())
    );
    let store = Store::open(&path, &KEY).unwrap();
    assert_eq!(
        store.get_meta::<u32>("schema_version").unwrap(),
        Some(schema::SCHEMA_VERSION)
    );
    assert_eq!(schema::SCHEMA_VERSION, 9);
    assert!(has_column(store.conn(), "messages", "gif"));
    let rows = store.messages_with(fp, 100).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].body, "old");
    assert_eq!(rows[0].gif, None);
    drop(store);
    Store::open_read(&path, &KEY).unwrap();
    // Replaying the migration on a v9 database is harmless.
    let store = Store::open(&path, &KEY).unwrap();
    schema::migrate_v8_to_v9(store.conn()).unwrap();
    assert_eq!(store.get_meta::<u32>("schema_version").unwrap(), Some(9));
}

#[test]
fn gif_column_round_trips() {
    let (_d, _path, store) = open_tmp();
    let fp = Fingerprint([4; 32]);
    let gif = crate::gif::GifRef {
        provider: 1,
        id: "hello-hi-662".into(),
        width: 480,
        height: 270,
    };
    assert!(
        store
            .insert_message_row(&MessageInsert {
                contact_fp: fp,
                direction: Direction::In,
                body: String::new(),
                status: MessageStatus::Received,
                at: 100,
                message_id: MessageId([2; 16]),
                wire_id: None,
                reply_to: None,
                reply_ref: None,
                placeholder: false,
                ttl_secs: None,
                seen_at: None,
                expire_at: None,
                gif: Some(gif.clone()),
            })
            .unwrap()
    );
    let row = store.messages_with(fp, 100).unwrap().remove(0);
    assert_eq!(row.gif, Some(gif.clone()));
    assert_eq!(
        store.message_by_row(row.id).unwrap().unwrap().gif,
        Some(gif)
    );
    // `Debug` never shows the identifier.
    assert!(!format!("{row:?}").contains("hello-hi-662"));
}

#[test]
fn v5_migration_adds_only_missing_columns() {
    let (_d, path, store) = open_tmp();
    // A database with some of the v5 columns already (a development build).
    store
        .conn()
        .execute_batch("DROP INDEX messages_expire; ALTER TABLE messages DROP COLUMN expire_at;")
        .unwrap();
    store.put_meta("schema_version", &4u32).unwrap();
    drop(store);
    let store = Store::open(&path, &KEY).unwrap();
    assert!(has_column(store.conn(), "messages", "expire_at"));
    assert!(has_object(store.conn(), "index", "messages_expire"));
}

#[test]
fn ephemeral_columns_round_trip() {
    let (_d, _path, store) = open_tmp();
    let fp = Fingerprint([4; 32]);
    let insert = |id: u8, ttl: Option<u32>, seen: Option<u64>, expire: Option<u64>| {
        assert!(
            store
                .insert_message_row(&MessageInsert {
                    contact_fp: fp,
                    direction: Direction::In,
                    body: format!("m{id}"),
                    status: MessageStatus::Received,
                    at: 100 + u64::from(id),
                    message_id: MessageId([id; 16]),
                    wire_id: None,
                    reply_to: None,
                    reply_ref: None,
                    placeholder: false,
                    ttl_secs: ttl,
                    seen_at: seen,
                    expire_at: expire,
                    gif: None,
                })
                .unwrap()
        );
    };
    insert(1, None, None, None);
    insert(2, Some(300), None, Some(604_900));
    insert(3, Some(60), Some(150), Some(210));
    let got: Vec<_> = store
        .messages_with(fp, 0)
        .unwrap()
        .into_iter()
        .map(|m| (m.ttl_secs, m.seen_at, m.expire_at))
        .collect();
    assert_eq!(
        got,
        [
            (None, None, None),
            (Some(300), None, Some(604_900)),
            (Some(60), Some(150), Some(210)),
        ]
    );
    let row = store.messages_with(fp, 0).unwrap()[2].clone();
    assert_eq!(store.message_by_row(row.id).unwrap(), Some(row.clone()));
    assert_eq!(store.message_in(fp, row.message_id, 0).unwrap(), Some(row));
}

/// A message row to insert carries plaintext: dropped, it is wiped
/// (history import, `record_message`, sends).
#[test]
fn message_insert_wipes_its_body() {
    fn assert_zod<T: zeroize::ZeroizeOnDrop>() {}
    assert_zod::<MessageInsert>();
}

#[test]
fn journal_is_not_wal() {
    let (_d, _p, store) = open_tmp();
    let mode: String = store
        .conn()
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .unwrap();
    assert_ne!(mode.to_lowercase(), "wal");
    assert_eq!(mode.to_lowercase(), "delete");
}

/// Marker text of `expired_text_absent_from_decrypted_pages`.
const MARKER: &str = "ZQX-ephemeral-marker-7d1f0c-QXZ";

/// An unencrypted store at `path` (`secure_delete` as given) holding two
/// ephemerals carrying `MARKER` (one short, one long enough to spill onto
/// overflow pages) among plain messages, seen once (their cells rewritten),
/// then erased by the production sweep. Returns the raw file bytes after
/// the insert and after the store is closed.
fn erase_marked(path: &std::path::Path, secure_delete: bool) -> (Vec<u8>, Vec<u8>) {
    let mut store = Store::open_unencrypted(path).unwrap();
    if !secure_delete {
        store
            .conn()
            .execute_batch("PRAGMA secure_delete = OFF;")
            .unwrap();
    }
    let fp = Fingerprint([4; 32]);
    let long = format!("{MARKER} {}", "x".repeat(3_000)) + MARKER;
    let bodies = [
        (1u8, "plain before".to_owned(), None),
        (2, format!("short {MARKER}"), Some(60)),
        (3, long, Some(60)),
        (4, "plain after".to_owned(), None),
    ];
    store
        .transaction(|tx| {
            for (id, body, ttl) in &bodies {
                tx.insert_message_row(&MessageInsert {
                    contact_fp: fp,
                    direction: Direction::In,
                    body: body.clone(),
                    status: MessageStatus::Received,
                    at: 100,
                    message_id: MessageId([*id; 16]),
                    wire_id: Some([*id; 16]),
                    reply_to: None,
                    reply_ref: None,
                    placeholder: false,
                    ttl_secs: *ttl,
                    seen_at: None,
                    expire_at: ttl.map(|_| 100 + 604_800),
                    gif: None,
                })?;
            }
            Ok(())
        })
        .unwrap();
    // Seen (as `Core::mark_seen` writes it): the cells are rewritten.
    store
        .conn()
        .execute(
            "UPDATE messages SET seen_at = 200, expire_at = 260 WHERE ttl_secs IS NOT NULL",
            [],
        )
        .unwrap();
    let before = std::fs::read(path).unwrap();
    let erased = store
        .transaction(|tx| crate::core::ephemeral::sweep(tx, 260))
        .unwrap();
    assert_eq!(erased.len(), 2);
    assert_eq!(store.messages_with(fp, 0).unwrap().len(), 2);
    drop(store);
    let mut journal = path.as_os_str().to_owned();
    journal.push("-journal");
    assert!(
        !std::path::Path::new(&journal).exists(),
        "no rollback journal left"
    );
    (before, std::fs::read(path).unwrap())
}

fn holds(bytes: &[u8], needle: &str) -> bool {
    bytes.windows(needle.len()).any(|w| w == needle.as_bytes())
}

/// An expired ephemeral's text is in no page of the database, free pages
/// included.
///
/// Method: the bundled SQLCipher is built without
/// `SQLITE_ENABLE_DBPAGE_VTAB` (`sqlite_dbpage` is absent, checked first),
/// so the pages are read through the fallback the plan allows: an
/// unencrypted test store (`Store::open_unencrypted`: the production
/// opening, schema and `secure_delete = ON`, only the key step left out),
/// whose raw file is every page in clear. The positive control finds the
/// marker in the file before the erasure; a control store with
/// `secure_delete = OFF` still holds it after the same erasure, which
/// shows the scan sees freed pages.
#[test]
fn expired_text_absent_from_decrypted_pages() {
    let (_d, _p, encrypted) = open_tmp();
    assert!(
        encrypted
            .conn()
            .query_row("SELECT count(*) FROM sqlite_dbpage", [], |r| r
                .get::<_, i64>(0))
            .is_err(),
        "sqlite_dbpage exists: read the encrypted pages through it instead"
    );
    drop(encrypted);
    let dir = tempdir().unwrap();
    let (before, after) = erase_marked(&dir.path().join("plain.sqlite"), true);
    assert!(holds(&before, MARKER), "positive control");
    assert!(!holds(&after, MARKER), "text left in the pages");
    assert!(!holds(&after, "short "), "text left in the pages");
    let (_, control) = erase_marked(&dir.path().join("control.sqlite"), false);
    assert!(
        holds(&control, MARKER),
        "without secure_delete the freed cells keep the text"
    );
}

/// The v7 `contact_avatars` table, as the local-only build created it.
const V7_AVATARS: &str = "
DROP TABLE contact_avatars;
CREATE TABLE contact_avatars (
    fp BLOB PRIMARY KEY NOT NULL,
    kind INTEGER NOT NULL,
    data BLOB NOT NULL
);
";

#[test]
fn migrates_v6_to_v7() {
    let (_d, path, store) = open_tmp();
    // Turn the fresh database back into a v6 one.
    store
        .conn()
        .execute_batch("DROP TABLE contact_avatars;")
        .unwrap();
    store.put_meta("schema_version", &6u32).unwrap();
    drop(store);
    assert_eq!(
        Store::open_read(&path, &KEY).err().unwrap(),
        CoreError::Store("database schema not current".into())
    );
    // Through v7, v8, then v9.
    let store = Store::open(&path, &KEY).unwrap();
    assert_eq!(
        store.get_meta::<u32>("schema_version").unwrap(),
        Some(schema::SCHEMA_VERSION)
    );
    assert!(has_object(store.conn(), "table", "contact_avatars"));
    for c in ["fp", "kind", "data", "at"] {
        assert!(
            has_column(store.conn(), "contact_avatars", c),
            "{c} missing"
        );
    }
    drop(store);
    Store::open_read(&path, &KEY).unwrap();
}

#[test]
fn migrates_v7_to_v8_keeping_avatars() {
    let (_d, path, store) = open_tmp();
    // Turn the fresh database back into a v7 one, with two avatars.
    store.conn().execute_batch(V7_AVATARS).unwrap();
    let (a, b) = (Fingerprint([1; 32]), Fingerprint([2; 32]));
    for fp in [a, b] {
        store.upsert_contact(fp, b"card", "", false).unwrap();
    }
    store
        .conn()
        .execute(
            "INSERT INTO contact_avatars(fp, kind, data) VALUES (?1, 0, ?2), (?3, 1, ?4)",
            rusqlite::params![
                a.0.as_slice(),
                "x".as_bytes(),
                b.0.as_slice(),
                [0xFFu8, 0xD8, 1].as_slice()
            ],
        )
        .unwrap();
    store.put_meta("schema_version", &7u32).unwrap();
    drop(store);
    assert_eq!(
        Store::open_read(&path, &KEY).err().unwrap(),
        CoreError::Store("database schema not current".into())
    );
    let store = Store::open(&path, &KEY).unwrap();
    assert_eq!(
        store.get_meta::<u32>("schema_version").unwrap(),
        Some(schema::SCHEMA_VERSION)
    );
    assert!(has_column(store.conn(), "contact_avatars", "at"));
    // Rows kept, dated 0.
    assert_eq!(
        store.contact_avatars().unwrap(),
        vec![
            (a, AvatarKind::Emoji, b"x".to_vec()),
            (b, AvatarKind::Photo, vec![0xFF, 0xD8, 1]),
        ]
    );
    assert_eq!(
        store.contact_avatar(b).unwrap(),
        Some(AvatarRegister {
            at: 0,
            value: Some((AvatarKind::Photo, vec![0xFF, 0xD8, 1]))
        })
    );
    // `kind` and `data` now take a tombstone.
    store.put_contact_avatar(a, None, 5).unwrap();
    assert_eq!(
        store.contact_avatar(a).unwrap(),
        Some(AvatarRegister { at: 5, value: None })
    );
    drop(store);
    Store::open_read(&path, &KEY).unwrap();
    // Replaying the migration on a v8 database keeps the dates.
    let store = Store::open(&path, &KEY).unwrap();
    schema::migrate_v7_to_v8(store.conn()).unwrap();
    assert_eq!(store.get_meta::<u32>("schema_version").unwrap(), Some(8));
    assert_eq!(
        store.contact_avatar(a).unwrap(),
        Some(AvatarRegister { at: 5, value: None })
    );
}

#[test]
fn contact_avatar_rows_replace_list_and_delete() {
    let (_d, _path, store) = open_tmp();
    let (a, b, c) = (
        Fingerprint([1; 32]),
        Fingerprint([2; 32]),
        Fingerprint([3; 32]),
    );
    for fp in [a, b] {
        store.upsert_contact(fp, b"card", "", false).unwrap();
    }
    store
        .put_contact_avatar(b, Some((AvatarKind::Photo, &[0xFF, 0xD8])), 1)
        .unwrap();
    store
        .put_contact_avatar(a, Some((AvatarKind::Emoji, "x".as_bytes())), 1)
        .unwrap();
    store
        .put_contact_avatar(a, Some((AvatarKind::Emoji, "y".as_bytes())), 2)
        .unwrap();
    // Not a contact (yet): kept, not listed.
    store
        .put_contact_avatar(c, Some((AvatarKind::Emoji, "z".as_bytes())), 3)
        .unwrap();
    assert_eq!(
        store.contact_avatars().unwrap(),
        vec![
            (a, AvatarKind::Emoji, b"y".to_vec()),
            (b, AvatarKind::Photo, vec![0xFF, 0xD8]),
        ]
    );
    assert_eq!(store.contact_avatar(c).unwrap().map(|r| r.at), Some(3));
    // A tombstone is not listed.
    store.put_contact_avatar(a, None, 4).unwrap();
    assert_eq!(
        store.contact_avatars().unwrap(),
        vec![(b, AvatarKind::Photo, vec![0xFF, 0xD8])]
    );
    store.delete_contact_avatar(a).unwrap();
    store.delete_contact_avatar(a).unwrap();
    assert_eq!(store.contact_avatar(a).unwrap(), None);
    store.delete_contact(b).unwrap();
    assert!(store.contact_avatars().unwrap().is_empty());
    assert_eq!(store.contact_avatar(b).unwrap(), None);
}
