//! `barking sync`: for each configured node, polls the watched mailboxes
//! and processes what was received, then drops the send queue (including the
//! receipts produced).
//!
//! **Polling.** First the session mailboxes (and the receipts expected on a
//! session), with the client's full budget, then the introduction
//! mailboxes, with `INTRO_FETCH_BYTES`: an introduction mailbox is computed
//! from a public key, so anyone can fill it with junk. For each node and
//! each mailbox, the position reached (`seen`) is kept and resumed the next
//! time, even if the list of mailboxes has changed. Only an incomplete
//! session poll prevents `mark_polled`: a flooded introduction mailbox only
//! delays first contacts. A `RateLimited` on a poll makes it partial,
//! without failing the node.
//!
//! **Deposits**, after polling: receipts first (without proof of work),
//! then the packets never deposited on this node, then the old ones. After
//! an outcome on a node, a packet is only redeposited there after a delay
//! (`retry_after`): 24 h if it was accepted (or refused for good), 10 min
//! if the node or the mailbox was full, 1 h for a receipt that arrived
//! before its packet. Proof budget exhausted: the remaining packets that
//! need proof wait, the others go out. `RateLimited`: deposits on this node
//! stop for this sync, without failure.
//!
//! Positions and deposits are kept in the core's encrypted database
//! (`Core::transport_state`), never in the clear: they contain mailbox and
//! packet identifiers. An old plaintext file (`sync_state.toml`,
//! `fetch_cursors.toml`) is migrated then erased. Each node gets
//! `SYNC_NODE_DEADLINE`; the whole sync has `SYNC_POW_BUDGET` proof-of-work
//! attempts.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::time::Duration;

use barking_core::Core;
use barking_core::mailbox::MailboxId;
use barking_core::packet::{Kind, Packet};
use barking_core::transparency::TransparencyEvent;
use barking_proto::ErrorReason;
use barking_proto::client::{Client, ClientError, FetchResume, MAX_FETCH_BYTES, Session};
use serde::{Deserialize, Serialize};

use super::nodes::{self, NodeEntry};
use super::{AckSink, CliError, CliResult, fail, now, open_core, printable, show_outcome};

/// Maximum bytes polled per sync from the introduction mailboxes.
pub const INTRO_FETCH_BYTES: usize = 8 << 20;
/// Maximum duration of the sync with a node.
pub const SYNC_NODE_DEADLINE: Duration = Duration::from_secs(180);
/// Proof-of-work allowed per sync (expected attempts): about 1,000
/// deposits at 18 bits, 16 at 24 bits.
pub const SYNC_POW_BUDGET: u64 = 1 << 28;
/// Delay before redepositing on a node a packet it already accepted or
/// refused for good (in case it lost it).
pub const REDEPOSIT_AFTER_SECS: u64 = 86_400;
/// Delay after a `NodeFull` or `MailboxFull` refusal (room may come back).
pub const FULL_RETRY_SECS: u64 = 600;
/// Delay after a receipt that arrived before its packet (`UnknownAckTarget`).
pub const DEFERRED_ACK_RETRY_SECS: u64 = 3_600;
/// Share of `SYNC_NODE_DEADLINE` for polling the sessions.
pub const SESSION_FETCH_SLICE: Duration = Duration::from_secs(90);
/// Share of `SYNC_NODE_DEADLINE` for polling the introductions: beyond it,
/// the poll is partial, without failing the node.
pub const INTRO_FETCH_SLICE: Duration = Duration::from_secs(45);

/// Key of the state in the core's database.
const STATE_KEY: &str = "netsync";
/// Old plaintext state files (migrated then erased).
const LEGACY_FILES: [&str; 2] = ["sync_state.toml", "fetch_cursors.toml"];

/// What happened with a node, even if it failed along the way.
#[derive(Default)]
struct Report {
    deposited: u32,
    refused: u32,
    /// Packets recently deposited on this node: not redeposited.
    already: u32,
    /// `Some((mailboxes, items received))` once the poll is finished.
    fetched: Option<(u32, u32)>,
    /// The session poll did not run to the end (cap, rate limit): the
    /// rest waits.
    truncated: bool,
    /// A polled session item could not be processed (local error, for
    /// example database busy): it must not leave the polling window.
    receive_failed: bool,
    /// The introductions were not fully polled (cap, error, unprocessed
    /// item): no effect on `mark_polled`.
    intro_partial: bool,
    /// Proof-of-work budget exhausted: packets needing proof postponed.
    pow_exhausted: bool,
    /// Deposits stopped by the node (rate limit) or by an error or the deadline.
    deposits_stopped: Option<String>,
    pow_spent: u64,
}

impl Report {
    /// The session mailboxes were fully polled and everything was
    /// processed: the only case where `mark_polled` may advance the polling window.
    fn fully_polled(&self) -> bool {
        self.fetched.is_some() && !self.truncated && !self.receive_failed
    }
}

/// Fate of a deposit, as seen by the summary.
#[derive(Debug, PartialEq, Eq)]
enum DepositTally {
    Deposited,
    Refused,
    /// Receipt that arrived before its packet on this node (network ordering
    /// between two nodes): neither deposit nor refusal, it will be redeposited at the next sync.
    Deferred,
}

fn tally(is_ack: bool, result: &Result<(), ErrorReason>) -> DepositTally {
    match result {
        Ok(()) => DepositTally::Deposited,
        Err(ErrorReason::UnknownAckTarget) if is_ack => DepositTally::Deferred,
        Err(_) => DepositTally::Refused,
    }
}

/// Position of a mailbox on a node (see `FetchResume`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Seen {
    mailbox: String,
    seq: u64,
}

/// Packet deposited (accepted, refused or deferred) on a node: no new
/// deposit before `until`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Deposited {
    id: String,
    #[serde(alias = "at")]
    until: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct NodeState {
    id: String,
    #[serde(default)]
    sessions: Vec<Seen>,
    #[serde(default)]
    intro: Vec<Seen>,
    #[serde(default)]
    deposited: Vec<Deposited>,
}

fn to_resume(seen: &[Seen]) -> FetchResume {
    let mut r = FetchResume::default();
    for s in seen {
        if let Ok(b) = data_encoding::HEXLOWER.decode(s.mailbox.as_bytes())
            && let Ok(k) = <[u8; 16]>::try_from(b.as_slice())
        {
            r.seen.insert(k, s.seq);
        }
    }
    r
}

/// Positions of the `current` mailboxes only, in a stable order.
fn from_resume(r: &FetchResume, current: &[MailboxId]) -> Vec<Seen> {
    let mut v: Vec<Seen> = current
        .iter()
        .filter_map(|m| {
            r.seen.get(&m.0).filter(|s| **s > 0).map(|s| Seen {
                mailbox: data_encoding::HEXLOWER.encode(&m.0),
                seq: *s,
            })
        })
        .collect();
    v.sort_by(|a, b| a.mailbox.cmp(&b.mailbox));
    v.dedup();
    v
}

#[derive(Default, Serialize, Deserialize)]
struct StateFile {
    #[serde(default, rename = "node")]
    nodes: Vec<NodeState>,
}

/// State kept in the database; absent or unreadable: from the start. An
/// old plaintext file is first migrated (if the database has no state),
/// then overwritten with zeros and erased.
fn load_state(home: &Path, core: &mut Core) -> CliResult<Vec<NodeState>> {
    let parse = |t: &str| toml::from_str::<StateFile>(t).ok().map(|f| f.nodes);
    let mut nodes = core
        .transport_state(STATE_KEY)?
        .and_then(|b| String::from_utf8(b).ok())
        .and_then(|t| parse(&t));
    for name in LEGACY_FILES {
        let path = home.join(name);
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        if nodes.is_none() {
            nodes = parse(&text);
            if let Some(n) = &nodes {
                save_state(core, n)?;
            }
        }
        wipe(&path);
    }
    Ok(nodes.unwrap_or_default())
}

/// Overwrites a file with zeros then erases it (best effort).
fn wipe(path: &Path) {
    if let Ok(meta) = fs::metadata(path)
        && let Ok(mut f) = fs::OpenOptions::new().write(true).open(path)
    {
        let len = usize::try_from(meta.len()).unwrap_or(0);
        let _ = f.write_all(&vec![0u8; len]);
        let _ = f.sync_all();
    }
    let _ = fs::remove_file(path);
}

/// Writes the state to the core's encrypted database.
fn save_state(core: &mut Core, nodes: &[NodeState]) -> CliResult<()> {
    let text = toml::to_string(&StateFile {
        nodes: nodes.to_vec(),
    })
    .map_err(|_| CliError("Error: cannot write the sync state".into()))?;
    core.set_transport_state(STATE_KEY, text.as_bytes())?;
    Ok(())
}

fn intro_slice() -> Duration {
    // Adjustable in test builds only.
    #[cfg(debug_assertions)]
    if let Some(ms) = std::env::var("BARKING_TEST_INTRO_SLICE_MS")
        .ok()
        .and_then(|v| v.parse().ok())
    {
        return Duration::from_millis(ms);
    }
    INTRO_FETCH_SLICE
}

fn pow_budget() -> u64 {
    // Adjustable in test builds only.
    #[cfg(debug_assertions)]
    if let Some(b) = std::env::var("BARKING_TEST_POW_BUDGET")
        .ok()
        .and_then(|v| v.parse().ok())
    {
        return b;
    }
    SYNC_POW_BUDGET
}

pub fn sync(home: &Path) -> CliResult<()> {
    let nodes = nodes::load(home)?;
    if nodes.is_empty() {
        return fail("No node configured: run `barking node add <address:port> <identifier>`");
    }
    let mut core = open_core(home)?;
    // State of the configured nodes only.
    let mut state: Vec<NodeState> = load_state(home, &mut core)?
        .into_iter()
        .filter(|c| nodes.iter().any(|n| n.id == c.id))
        .collect();
    // The runtime only exists for the duration of the sync.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| CliError(format!("I/O error: {e}")))?;
    let mut ok_nodes = 0usize;
    let mut all_polled = true;
    let mut pow_left = pow_budget();
    for node in &nodes {
        let short = node.short_id();
        let mut report = Report::default();
        let k = match state.iter().position(|c| c.id == node.id) {
            Some(k) => k,
            None => {
                state.push(NodeState {
                    id: node.id.clone(),
                    ..NodeState::default()
                });
                state.len() - 1
            }
        };
        let result = rt.block_on(sync_node(
            &mut core,
            node,
            &mut report,
            &mut state[k],
            pow_left,
        ));
        pow_left = pow_left.saturating_sub(report.pow_spent);
        log_report(&mut core, &short, &report)?;
        save_state(&mut core, &state)?;
        match result {
            Ok(()) => {
                ok_nodes += 1;
                if !report.fully_polled() {
                    all_polled = false;
                }
                let mut notes = String::new();
                if report.receive_failed {
                    notes += " (item not processed: it will be polled again at the next sync)";
                } else if report.truncated {
                    notes += " (partial poll: the rest at the next sync)";
                }
                if report.intro_partial {
                    notes += " (introductions: partial poll, the rest at the next sync)";
                }
                if report.pow_exhausted {
                    notes +=
                        " (proof-of-work budget exhausted: remaining deposits at the next sync)";
                }
                if let Some(why) = &report.deposits_stopped {
                    notes += &format!(
                        " (deposits interrupted: {}; the rest at the next sync)",
                        printable(why)
                    );
                }
                println!(
                    "Node {short}: {} deposited ({} refused, {} already present), {} mailboxes polled, {} items received{notes}",
                    report.deposited,
                    report.refused,
                    report.already,
                    report.fetched.map_or(0, |f| f.0),
                    report.fetched.map_or(0, |f| f.1),
                );
            }
            Err(msg) => {
                all_polled = false;
                eprintln!("Node {short}: {}", printable(&msg));
            }
        }
    }
    // A proof of work still being computed is not waited for.
    rt.shutdown_timeout(Duration::from_secs(1));
    if all_polled {
        core.mark_polled(now())?;
        println!("Poll recorded");
    } else {
        println!("Poll not recorded: a node did not respond in full");
    }
    if ok_nodes == 0 {
        return fail("No node responded");
    }
    Ok(())
}

fn log_report(core: &mut Core, short: &str, r: &Report) -> CliResult<()> {
    if r.deposited + r.refused > 0 {
        core.log_transport_event(
            TransparencyEvent::NodeDeposit {
                node: short.to_owned(),
                count: r.deposited,
                refused: r.refused,
            },
            now(),
        )?;
    }
    if let Some((mailboxes, received)) = r.fetched {
        core.log_transport_event(
            TransparencyEvent::NodeFetch {
                node: short.to_owned(),
                mailboxes,
                received,
            },
            now(),
        )?;
    }
    Ok(())
}

/// A packet from the send queue, ready to deposit.
#[derive(Debug, PartialEq, Eq)]
struct Planned {
    bytes: Vec<u8>,
    /// Identifier (hex); `None` if the packet is unreadable.
    id: Option<String>,
    /// Receipt (without proof of work).
    ack: bool,
}

/// Delay before a new deposit on this node, depending on the outcome of the last.
fn retry_after(tally: &DepositTally, result: &Result<(), ErrorReason>) -> u64 {
    match (tally, result) {
        (DepositTally::Deferred, _) => DEFERRED_ACK_RETRY_SECS,
        (_, Err(ErrorReason::NodeFull | ErrorReason::MailboxFull)) => FULL_RETRY_SECS,
        _ => REDEPOSIT_AFTER_SECS,
    }
}

/// Order of deposits on a node: receipts, packets never deposited here,
/// then old deposits to redo; whatever is still within its delay
/// (`retry_after`) is set aside (counted in the second term).
fn plan_deposits(outbox: Vec<Vec<u8>>, deposited: &[Deposited], now: u64) -> (Vec<Planned>, u32) {
    let until: HashMap<&str, u64> = deposited.iter().map(|d| (d.id.as_str(), d.until)).collect();
    let (mut acks, mut new, mut old) = (Vec::new(), Vec::new(), Vec::new());
    let mut skipped = 0;
    for bytes in outbox {
        let p = Packet::decode(&bytes).ok();
        let id = p.as_ref().map(|p| data_encoding::HEXLOWER.encode(&p.id.0));
        let ack = p.as_ref().is_some_and(|p| p.kind == Kind::Ack);
        let last = id.as_deref().and_then(|i| until.get(i).copied());
        if last.is_some_and(|t| now < t) {
            skipped += 1;
            continue;
        }
        let item = Planned { bytes, id, ack };
        if ack {
            acks.push(item);
        } else if last.is_none() {
            new.push(item);
        } else {
            old.push(item);
        }
    }
    acks.append(&mut new);
    acks.append(&mut old);
    (acks, skipped)
}

/// Deposits `plan` in order and records each final outcome in
/// `deposited`. Proof budget exhausted: the following packets needing proof
/// are skipped, the others go out. `RateLimited` or error: deposits stop.
async fn deposit_all(
    session: &mut Session,
    plan: &[Planned],
    deposited: &mut Vec<Deposited>,
    report: &mut Report,
) {
    for item in plan {
        if !item.ack && report.pow_exhausted {
            continue;
        }
        let r = session.deposit(&item.bytes).await;
        report.pow_spent = session.pow_spent();
        let result = match r {
            Ok(Err(ErrorReason::RateLimited)) => {
                report.deposits_stopped = Some("too many requests".into());
                return;
            }
            Ok(result) => result,
            Err(ClientError::PowBudget) => {
                report.pow_exhausted = true;
                continue;
            }
            Err(e) => {
                report.deposits_stopped = Some(e.to_string());
                return;
            }
        };
        let t = tally(item.ack, &result);
        match t {
            DepositTally::Deposited => report.deposited += 1,
            DepositTally::Refused => report.refused += 1,
            DepositTally::Deferred => {}
        }
        if let Some(id) = &item.id {
            deposited.retain(|d| &d.id != id);
            deposited.push(Deposited {
                id: id.clone(),
                until: now().saturating_add(retry_after(&t, &result)),
            });
        }
    }
}

/// Passes each polled item to `receive`. False if an item could not be
/// processed.
fn receive_all(core: &mut Core, items: &[Vec<u8>], label: &str) -> Result<bool, String> {
    let mut all = true;
    for item in items {
        // A receipt may arrive in a mailbox other than those polled
        // for it: everything goes through `receive`, which decides.
        match core.receive(item, "nœud", now(), &mut rand::rng()) {
            Ok(outcome) => {
                show_outcome(label, outcome, AckSink::Queued).map_err(|e| e.0)?;
            }
            Err(e) => {
                all = false;
                eprintln!("{label}: item ignored ({})", printable(&e.to_string()));
            }
        }
    }
    Ok(all)
}

/// Poll of a group of mailboxes.
enum Fetched {
    /// Items, and whether the poll ran to the end.
    Items(Vec<Vec<u8>>, bool),
    /// Rate limit exhausted before the first page.
    RateLimited,
}

async fn fetch_group(
    session: &mut Session,
    mailboxes: &[MailboxId],
    resume: &mut FetchResume,
    max_bytes: usize,
    slice: Duration,
) -> Result<Fetched, ClientError> {
    if mailboxes.is_empty() {
        return Ok(Fetched::Items(Vec::new(), true));
    }
    // Elapsed time makes the poll partial, with what was taken.
    session.set_fetch_deadline(slice);
    match session.fetch_resumable(mailboxes, resume, max_bytes).await {
        Ok(items) => Ok(Fetched::Items(items, !session.last_fetch_truncated())),
        Err(ClientError::Refused(ErrorReason::RateLimited)) => Ok(Fetched::RateLimited),
        Err(e) => Err(e),
    }
}

async fn sync_node(
    core: &mut Core,
    node: &NodeEntry,
    report: &mut Report,
    state: &mut NodeState,
    pow_budget: u64,
) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + SYNC_NODE_DEADLINE;
    let timed_out = || "sync deadline exceeded (3 min)".to_string();
    let id = node.node_id().map_err(|e| e.0)?;
    let mut session = tokio::time::timeout_at(deadline, Client::connect(node.addr, id))
        .await
        .map_err(|_| timed_out())?
        .map_err(|e| e.to_string())?;
    session.set_pow_budget(Some(pow_budget));
    let label = format!("node {}", node.short_id());

    // Polling: sessions first, introductions next.
    let fetch = async {
        let mut groups = core.watched_mailbox_groups(now());
        groups.sessions.sort_unstable_by_key(|m| m.0);
        groups.intro.sort_unstable_by_key(|m| m.0);
        let mut received = 0usize;
        let mut limited = false;

        let mut resume = to_resume(&state.sessions);
        match fetch_group(
            &mut session,
            &groups.sessions,
            &mut resume,
            MAX_FETCH_BYTES,
            SESSION_FETCH_SLICE,
        )
        .await
        .map_err(|e| e.to_string())?
        {
            Fetched::Items(items, complete) => {
                report.truncated = !complete;
                if receive_all(core, &items, &label)? {
                    state.sessions = from_resume(&resume, &groups.sessions);
                } else {
                    report.receive_failed = true;
                }
                received += items.len();
            }
            Fetched::RateLimited => {
                report.truncated = true;
                limited = true;
            }
        }

        // Rate limit exhausted: no second refused request in a row.
        let mut resume = to_resume(&state.intro);
        let intro = if limited {
            Ok(Fetched::RateLimited)
        } else {
            fetch_group(
                &mut session,
                &groups.intro,
                &mut resume,
                INTRO_FETCH_BYTES,
                intro_slice(),
            )
            .await
        };
        match intro {
            Ok(Fetched::Items(items, complete)) => {
                report.intro_partial = !complete;
                if receive_all(core, &items, &label)? {
                    state.intro = from_resume(&resume, &groups.intro);
                } else {
                    report.intro_partial = true;
                }
                received += items.len();
            }
            Ok(Fetched::RateLimited) => {
                report.intro_partial = true;
                limited = true;
            }
            Err(e) => {
                report.intro_partial = true;
                eprintln!(
                    "{label}: introduction poll interrupted ({})",
                    printable(&e.to_string())
                );
            }
        }
        report.fetched = Some((
            u32::try_from(groups.sessions.len() + groups.intro.len()).unwrap_or(u32::MAX),
            u32::try_from(received).unwrap_or(u32::MAX),
        ));
        Ok::<bool, String>(limited)
    };
    let limited = tokio::time::timeout_at(deadline, fetch)
        .await
        .map_err(|_| timed_out())??;

    // Deposits: the whole queue (including receipts produced by the poll),
    // except what this node already got recently.
    let outbox = core.pending_outbox(now()).map_err(|e| e.to_string())?;
    let live: HashSet<String> = outbox
        .iter()
        .filter_map(|b| Packet::decode(b).ok())
        .map(|p| data_encoding::HEXLOWER.encode(&p.id.0))
        .collect();
    // Packets acknowledged or expired (out of the queue): forgotten.
    state.deposited.retain(|d| live.contains(&d.id));
    let (plan, skipped) = plan_deposits(outbox, &state.deposited, now());
    report.already = skipped;
    if limited && !plan.is_empty() {
        report.deposits_stopped = Some("too many requests".into());
    } else if tokio::time::timeout_at(
        deadline,
        deposit_all(&mut session, &plan, &mut state.deposited, report),
    )
    .await
    .is_err()
    {
        report.deposits_stopped = Some(timed_out());
    }
    session.close().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use barking_core::packet::{DEFAULT_HOPS, PacketId, Tier};

    #[test]
    fn receive_failure_or_truncation_blocks_mark_polled() {
        let ok = Report {
            fetched: Some((3, 1)),
            ..Report::default()
        };
        assert!(ok.fully_polled());
        assert!(
            !Report {
                receive_failed: true,
                ..ok_clone(&ok)
            }
            .fully_polled()
        );
        assert!(
            !Report {
                truncated: true,
                ..ok_clone(&ok)
            }
            .fully_polled()
        );
        assert!(!Report::default().fully_polled());
    }

    fn ok_clone(r: &Report) -> Report {
        Report {
            fetched: r.fetched,
            ..Report::default()
        }
    }

    #[test]
    fn intro_partial_or_stopped_deposits_do_not_block_mark_polled() {
        let r = Report {
            fetched: Some((3, 1)),
            intro_partial: true,
            pow_exhausted: true,
            deposits_stopped: Some("x".into()),
            ..Report::default()
        };
        assert!(r.fully_polled());
    }

    #[test]
    fn seen_positions_roundtrip_and_prune() {
        let m = |b: u8| MailboxId([b; 16]);
        let mut r = FetchResume::default();
        r.seen.insert([1; 16], 7);
        r.seen.insert([2; 16], 0);
        r.seen.insert([3; 16], 9);
        // Only the mailboxes still watched, zero positions omitted.
        let s = from_resume(&r, &[m(1), m(2)]);
        assert_eq!(s.len(), 1);
        let back = to_resume(&s);
        assert_eq!(back.seen.get(&[1; 16]), Some(&7));
        assert!(!back.seen.contains_key(&[3; 16]));
    }

    fn pkt(n: u8, kind: Kind) -> Vec<u8> {
        Packet {
            kind,
            hops: DEFAULT_HOPS,
            tier: Tier::S,
            id: PacketId([n; 16]),
            expires_at: 2_000_000_000,
            mailbox: MailboxId([n; 16]),
            payload: vec![n; 8],
        }
        .encode()
    }

    #[test]
    fn deposit_plan_order_and_backoff() {
        let now = 1_800_000_000;
        let hex = |n: u8| data_encoding::HEXLOWER.encode(&[n; 16]);
        let outbox = vec![
            pkt(1, Kind::Message), // old, to redo
            pkt(2, Kind::Message), // deposited recently: set aside
            pkt(3, Kind::Ack),     // receipt never deposited
            pkt(4, Kind::Message), // new
            pkt(5, Kind::Ack),     // receipt deposited recently: set aside
        ];
        let done = vec![
            Deposited {
                id: hex(1),
                until: now,
            },
            Deposited {
                id: hex(2),
                until: now + 10,
            },
            Deposited {
                id: hex(5),
                until: now + 10,
            },
        ];
        let (plan, skipped) = plan_deposits(outbox, &done, now);
        assert_eq!(skipped, 2);
        let ids: Vec<String> = plan.iter().map(|p| p.id.clone().unwrap()).collect();
        assert_eq!(ids, vec![hex(3), hex(4), hex(1)]);
        assert!(plan[0].ack && !plan[1].ack);
    }

    #[test]
    fn backoff_by_outcome() {
        let ok = Ok(());
        let full = Err(ErrorReason::NodeFull);
        let mfull = Err(ErrorReason::MailboxFull);
        let bad = Err(ErrorReason::Malformed);
        let early = Err(ErrorReason::UnknownAckTarget);
        let r = |ack, res: &Result<(), ErrorReason>| retry_after(&tally(ack, res), res);
        assert_eq!(r(false, &ok), REDEPOSIT_AFTER_SECS);
        assert_eq!(r(true, &ok), REDEPOSIT_AFTER_SECS);
        assert_eq!(r(false, &full), FULL_RETRY_SECS);
        assert_eq!(r(false, &mfull), FULL_RETRY_SECS);
        assert_eq!(r(false, &bad), REDEPOSIT_AFTER_SECS);
        assert_eq!(r(true, &early), DEFERRED_ACK_RETRY_SECS);
        assert_eq!((FULL_RETRY_SECS, DEFERRED_ACK_RETRY_SECS), (600, 3_600));
        // Old format (`at`) read back as a deadline.
        let d: Deposited = toml::from_str("id = \"x\"\nat = 5").unwrap();
        assert_eq!(d.until, 5);
    }

    #[test]
    fn early_ack_is_deferred_not_refused() {
        let early = Err(ErrorReason::UnknownAckTarget);
        assert_eq!(tally(true, &early), DepositTally::Deferred);
        assert_eq!(tally(false, &early), DepositTally::Refused);
        assert_eq!(tally(true, &Ok(())), DepositTally::Deposited);
        assert_eq!(
            tally(true, &Err(ErrorReason::PowTooWeak)),
            DepositTally::Refused
        );
    }
}
