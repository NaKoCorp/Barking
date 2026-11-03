use super::*;
use std::sync::atomic::AtomicUsize;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use barking_packet::{DEFAULT_HOPS, Kind, MailboxId, Packet, PacketId, Tier};
use barking_proto::pow;
use rusqlite::params;
use tokio::task::JoinSet;

use crate::rules;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn policy() -> Policy {
    Policy {
        pow_bits: 0,
        ..Policy::default()
    }
}

fn writer(dir: &tempfile::TempDir, max_batch: usize) -> Writer {
    let store = NodeStore::open(dir.path().join("node.db")).unwrap();
    Writer::spawn(store, policy(), max_batch).unwrap()
}

fn reopen(dir: &tempfile::TempDir) -> NodeStore {
    NodeStore::open(dir.path().join("node.db")).unwrap()
}

fn meta_rows(s: &NodeStore) -> i64 {
    s.conn()
        .query_row("SELECT COUNT(*) FROM meta WHERE k LIKE 'job%'", [], |r| {
            r.get(0)
        })
        .unwrap()
}

/// Inserts a `meta` row named `job<n>`.
fn insert(n: usize) -> impl FnOnce(&mut NodeStore, &Policy) -> Result<()> + Send + 'static {
    move |s, _| {
        s.conn().execute(
            "INSERT INTO meta(k,v) VALUES(?1, 0)",
            params![format!("job{n}")],
        )?;
        Ok(())
    }
}

/// Holds the writer so that the next operations queue into one batch.
fn slow() -> impl FnOnce(&mut NodeStore, &Policy) -> Result<()> + Send + 'static {
    |_, _| {
        std::thread::sleep(Duration::from_millis(100));
        Ok(())
    }
}

/// Packet `n` of tier `tier` and its proof at the base difficulty, at most
/// 50 packets per mailbox (no per-mailbox surcharge).
fn packet(n: usize, tier: Tier, bits: u8) -> (Vec<u8>, u64, PacketId) {
    let mut id = [0u8; 16];
    id[..8].copy_from_slice(&(n as u64).to_le_bytes());
    let mut mailbox = [0xA5u8; 16];
    mailbox[..8].copy_from_slice(&((n / 50) as u64).to_le_bytes());
    let p = Packet {
        kind: Kind::Message,
        hops: DEFAULT_HOPS,
        tier,
        id: PacketId(id),
        expires_at: u32::try_from(now() + 86_400).unwrap(),
        mailbox: MailboxId(mailbox),
        payload: vec![0x5a; 64],
    };
    let bytes = p.encode();
    let bits = bits + pow::tier_surcharge(tier);
    let nonce = pow::solve(&pow::content_hash(&bytes), &p.mailbox, bits).unwrap();
    (bytes, nonce, p.id)
}

#[tokio::test(flavor = "multi_thread")]
async fn batches_concurrent_jobs() {
    let dir = tempfile::tempdir().unwrap();
    let w = writer(&dir, MAX_BATCH);
    let mut set = JoinSet::new();
    let first = w.clone();
    set.spawn(async move { first.run(slow(), ()).await });
    tokio::time::sleep(Duration::from_millis(20)).await;
    for n in 0..64 {
        let w = w.clone();
        set.spawn(async move { w.run(insert(n), ()).await });
    }
    while let Some(r) = set.join_next().await {
        assert!(matches!(r.unwrap(), Some(Ok(()))));
    }
    assert!(w.commits() < 64, "{} commits", w.commits());
    assert_eq!(meta_rows(&reopen(&dir)), 64);
}

#[tokio::test(flavor = "multi_thread")]
async fn failed_job_does_not_abort_batch() {
    let dir = tempfile::tempdir().unwrap();
    let w = writer(&dir, MAX_BATCH);
    let held = w.clone();
    let hold = tokio::spawn(async move { held.run(slow(), ()).await });
    tokio::time::sleep(Duration::from_millis(20)).await;
    let bad = |s: &mut NodeStore, _: &Policy| -> Result<()> {
        s.conn()
            .execute("INSERT INTO meta(k,v) VALUES('job-bad', 0)", [])?;
        s.conn().execute("INSERT INTO nowhere VALUES(1)", [])?;
        Ok(())
    };
    let (a, b, c) = tokio::join!(w.run(insert(1), ()), w.run(bad, ()), w.run(insert(2), ()));
    hold.await.unwrap();
    assert!(matches!(a, Some(Ok(()))));
    assert!(matches!(b, Some(Err(_))));
    assert!(matches!(c, Some(Ok(()))));
    // The failed operation's first insert is undone with it.
    assert_eq!(meta_rows(&reopen(&dir)), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn panicking_job_is_isolated() {
    let dir = tempfile::tempdir().unwrap();
    let w = writer(&dir, MAX_BATCH);
    let held = w.clone();
    let hold = tokio::spawn(async move { held.run(slow(), ()).await });
    tokio::time::sleep(Duration::from_millis(20)).await;
    let boom = |s: &mut NodeStore, _: &Policy| -> Result<()> {
        s.conn()
            .execute("INSERT INTO meta(k,v) VALUES('job-boom', 0)", [])?;
        panic!("operation panics");
    };
    let (a, b) = tokio::join!(w.run(insert(1), ()), w.run(boom, ()));
    hold.await.unwrap();
    assert!(matches!(a, Some(Ok(()))));
    assert!(b.is_none());
    // The writer still serves the next operation.
    assert!(matches!(w.run(insert(2), ()).await, Some(Ok(()))));
    assert_eq!(meta_rows(&reopen(&dir)), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn full_disk_never_acknowledges_lost_writes() {
    let dir = tempfile::tempdir().unwrap();
    let w = writer(&dir, MAX_BATCH);
    // A few pages of room: the deposits below run out of space mid-batch.
    let cap = |s: &mut NodeStore, _: &Policy| -> Result<()> {
        let pages: i64 = s.conn().query_row("PRAGMA page_count", [], |r| r.get(0))?;
        s.conn()
            .query_row(&format!("PRAGMA max_page_count={}", pages + 8), [], |_| {
                Ok(())
            })?;
        Ok(())
    };
    assert!(matches!(w.run(cap, ()).await, Some(Ok(()))));
    let mut set = JoinSet::new();
    for n in 0..400 {
        let (bytes, nonce, id) = packet(n, Tier::S, 0);
        let w = w.clone();
        set.spawn(async move {
            let r = w
                .run(move |s, p| rules::deposit(s, p, &bytes, nonce, now()), ())
                .await;
            (id, matches!(r, Some(Ok(Ok(())))))
        });
    }
    let mut acked = Vec::new();
    let mut refused = 0;
    while let Some(r) = set.join_next().await {
        match r.unwrap() {
            (id, true) => acked.push(id),
            _ => refused += 1,
        }
    }
    assert!(
        !acked.is_empty() && refused > 0,
        "{} acked, {refused} refused",
        acked.len()
    );
    drop(w);
    let s = reopen(&dir);
    for id in acked {
        let held: bool = s
            .conn()
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM packets WHERE id=?1)",
                params![&id.0[..]],
                |r| r.get(0),
            )
            .unwrap();
        assert!(held, "acknowledged deposit lost");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn dropped_caller_releases_slots() {
    struct Slot(Arc<AtomicUsize>);
    impl Drop for Slot {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let w = writer(&dir, MAX_BATCH);
    let dropped = Arc::new(AtomicUsize::new(0));
    let abandoned = tokio::time::timeout(
        Duration::from_millis(10),
        w.run(slow(), Slot(Arc::clone(&dropped))),
    )
    .await;
    assert!(abandoned.is_err());
    let deadline = Instant::now() + Duration::from_secs(5);
    while dropped.load(Ordering::SeqCst) == 0 {
        assert!(Instant::now() < deadline, "slot never released");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(matches!(w.run(insert(1), ()).await, Some(Ok(()))));
}

/// Deposit throughput under concurrent load, one commit per operation
/// (`max_batch` = 1, as before) against group commit. Database in
/// `BARKING_BENCH_DIR` (the disk to measure), else a temporary directory:
/// `cargo test --release -p barking-node bench_group_commit -- --ignored --nocapture`
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn bench_group_commit() {
    const DEPOSITS: usize = 20_000;
    const TASKS: usize = 64;
    let base = std::env::var_os("BARKING_BENCH_DIR");
    for max_batch in [1, MAX_BATCH] {
        let dir = match &base {
            Some(b) => tempfile::tempdir_in(b).unwrap(),
            None => tempfile::tempdir().unwrap(),
        };
        let packets: Vec<_> = (0..DEPOSITS).map(|n| packet(n, Tier::M, 0)).collect();
        let w = writer(&dir, max_batch);
        let start = Instant::now();
        let mut set = JoinSet::new();
        for chunk in packets.chunks(DEPOSITS / TASKS + 1) {
            let chunk = chunk.to_vec();
            let w = w.clone();
            set.spawn(async move {
                for (bytes, nonce, _) in chunk {
                    let r = w
                        .run(move |s, p| rules::deposit(s, p, &bytes, nonce, now()), ())
                        .await;
                    assert!(matches!(r, Some(Ok(Ok(())))));
                }
            });
        }
        while let Some(r) = set.join_next().await {
            r.unwrap();
        }
        let secs = start.elapsed().as_secs_f64();
        println!(
            "max_batch {max_batch:>3}: {DEPOSITS} deposits in {secs:.2} s = {:.0}/s, {} commits",
            DEPOSITS as f64 / secs,
            w.commits()
        );
    }
}
