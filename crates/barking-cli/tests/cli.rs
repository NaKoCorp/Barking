//! End-to-end tests of the `barking` binary (transport: files).

use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

const PASS: &str = "test";

fn barking(home: &Path) -> Command {
    let mut cmd = Command::cargo_bin("barking").unwrap();
    // The test nodes listen on 127.0.0.1: non-routable addresses accepted.
    cmd.env("BARKING_PASSPHRASE", PASS)
        .env("BARKING_TEST_ALLOW_PRIVATE", "1")
        .arg("--home")
        .arg(home);
    cmd
}

/// Runs a command that must succeed and returns its standard output.
fn ok(home: &Path, args: &[&str]) -> String {
    let out = barking(home)
        .args(args)
        .assert()
        .success()
        .get_output()
        .clone();
    String::from_utf8(out.stdout).unwrap()
}

/// An initialized device.
fn party(name: &str) -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    ok(&home, &["init", "--name", name]);
    (dir, home)
}

fn card(home: &Path, display: &str) -> String {
    ok(home, &["card", "--display-name", display])
        .trim()
        .to_owned()
}

/// A and B know each other: `bob` at A, `alice` at B.
fn pair() -> ((TempDir, PathBuf), (TempDir, PathBuf)) {
    let a = party("tel-a");
    let b = party("tel-b");
    ok(&a.1, &["add", &card(&b.1, "Bob"), "--alias", "bob"]);
    ok(&b.1, &["add", &card(&a.1, "Alice"), "--alias", "alice"]);
    (a, b)
}

/// The `.pkt` files of a directory, sorted.
fn packets(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "pkt"))
        .collect();
    v.sort();
    v
}

fn path_arg(p: &Path) -> &str {
    p.to_str().unwrap()
}

#[test]
fn full_conversation() {
    let ((da, a), (db, b)) = pair();
    let out_a = da.path().join("out");
    let out_b = db.path().join("out");

    let sent = ok(&a, &["send", "bob", "hello", "--out", path_arg(&out_a)]);
    let pkts = packets(&out_a);
    assert_eq!(pkts.len(), 1);
    assert!(sent.contains(path_arg(&pkts[0])), "{sent}");
    let name = pkts[0].file_stem().unwrap().to_str().unwrap();
    assert_eq!(name.len(), 32);
    assert!(name.chars().all(|c| c.is_ascii_hexdigit()));

    let got = ok(
        &b,
        &["receive", path_arg(&pkts[0]), "--out", path_arg(&out_b)],
    );
    assert!(got.contains("[alice] hello"), "{got}");
    let acks = packets(&out_b);
    assert_eq!(acks.len(), 1);

    let ack = ok(&a, &["receive", path_arg(&acks[0])]);
    assert!(ack.contains("delivered"), "{ack}");
}

#[test]
fn wrong_passphrase_exits_nonzero() {
    let (_d, home) = party("tel");
    barking(&home)
        .env("BARKING_PASSPHRASE", "wrong")
        .arg("whoami")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Incorrect passphrase"));
    // The right passphrase still works.
    barking(&home).arg("whoami").assert().success();
}

#[test]
fn init_twice_refused() {
    let (_d, home) = party("tel");
    let before = ok(&home, &["whoami"]);
    barking(&home)
        .args(["init", "--name", "autre"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));
    assert_eq!(ok(&home, &["whoami"]), before);
}

#[test]
fn init_shows_fingerprint_and_recovery_phrase() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let out = ok(&home, &["init", "--name", "tel"]);
    assert!(out.contains("Write it down offline"), "{out}");
    let phrase = out
        .lines()
        .find(|l| l.split_whitespace().count() == 24)
        .expect("24-word phrase");
    let fp = ok(&home, &["whoami"]);
    assert!(out.contains(fp.trim()), "{out}");

    // `recover` reads the phrase back from standard input and recovers the identity.
    let other = dir.path().join("autre");
    barking(&other)
        .args(["recover", "--name", "nouveau"])
        .write_stdin(format!("{phrase}\n"))
        .assert()
        .success();
    assert_eq!(ok(&other, &["whoami"]), fp);
}

#[test]
fn log_shows_relay_view() {
    let ((da, a), (db, b)) = pair();
    let out_a = da.path().join("out");
    let out_b = db.path().join("out");
    ok(&a, &["send", "bob", "hello", "--out", path_arg(&out_a)]);
    ok(
        &b,
        &[
            "receive",
            path_arg(&packets(&out_a)[0]),
            "--out",
            path_arg(&out_b),
        ],
    );
    for home in [&a, &b] {
        let log = ok(home, &["log"]);
        assert!(log.contains("Relays see"), "{log}");
        assert!(!log.contains("hello"), "the log does not show the text");
    }
    let limited = ok(&a, &["log", "--limit", "1"]);
    assert_eq!(limited.lines().count(), 1, "{limited}");
}

#[test]
fn contacts_and_safety_verification() {
    let ((_da, a), (_db, b)) = pair();
    let list = ok(&a, &["contacts"]);
    assert!(list.contains("bob"), "{list}");
    assert!(list.contains(ok(&b, &["whoami"]).trim()), "{list}");
    assert!(list.contains("unverified"), "{list}");

    let code = ok(&a, &["safety", "bob"]);
    assert_eq!(code, ok(&b, &["safety", "alice"]));
    let again = ok(&a, &["safety", "bob", "--verified"]);
    assert!(again.contains(code.trim()), "{again}");
    let list = ok(&a, &["contacts"]);
    assert!(!list.contains("unverified"), "{list}");
    assert!(list.contains("verified"), "{list}");
}

#[test]
fn unknown_contact_and_invalid_card_exit_nonzero() {
    let (d, home) = party("tel");
    let out = d.path().join("out");
    barking(&home)
        .args(["send", "personne", "x", "--out", path_arg(&out)])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Unknown contact"));
    barking(&home)
        .args(["safety", "personne"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Unknown contact"));
    barking(&home)
        .args(["add", "not-a-card"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Invalid contact card"));
    barking(&home)
        .args(["add", "barking1:AAAA"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Invalid contact card"));
    assert!(!out.exists() || packets(&out).is_empty());
}

#[test]
fn receive_reports_duplicate_and_not_for_us() {
    let ((da, a), (db, b)) = pair();
    let out_a = da.path().join("out");
    let out_b = db.path().join("out");
    ok(&a, &["send", "bob", "hello", "--out", path_arg(&out_a)]);
    let pkt = packets(&out_a).remove(0);

    ok(&b, &["receive", path_arg(&pkt), "--out", path_arg(&out_b)]);
    let again = ok(&b, &["receive", path_arg(&pkt), "--out", path_arg(&out_b)]);
    assert!(again.contains("duplicate"), "{again}");
    assert!(!again.contains("hello"), "{again}");

    // My own packet is not for me.
    let mine = ok(&a, &["receive", path_arg(&pkt)]);
    assert!(mine.contains("not for you"), "{mine}");

    // An unreadable file is not for me either.
    let junk = da.path().join("junk.pkt");
    fs::write(&junk, b"anything").unwrap();
    let out = ok(&b, &["receive", path_arg(&junk)]);
    assert!(out.contains("not for you"), "{out}");
}

#[test]
fn remove_then_readd() {
    let ((da, a), (db, b)) = pair();
    let out_a = da.path().join("out");
    let out_b = db.path().join("out");

    ok(&a, &["send", "bob", "un", "--out", path_arg(&out_a)]);
    ok(
        &b,
        &[
            "receive",
            path_arg(&packets(&out_a)[0]),
            "--out",
            path_arg(&out_b),
        ],
    );

    let removed = ok(&a, &["remove", "bob"]);
    assert!(removed.contains("removed"), "{removed}");
    assert!(!ok(&a, &["contacts"]).contains("bob"));
    barking(&a)
        .args(["send", "bob", "deux", "--out", path_arg(&out_a)])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Unknown contact"));
    barking(&a)
        .args(["remove", "bob"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Unknown contact"));

    // Added back, they become reachable again.
    ok(&a, &["add", &card(&b, "Bob"), "--alias", "bob"]);
    let before = packets(&out_a).len();
    ok(&a, &["send", "bob", "trois", "--out", path_arg(&out_a)]);
    let all = packets(&out_a);
    assert_eq!(all.len(), before + 1);
    let delivered = all.iter().any(|p| {
        ok(&b, &["receive", path_arg(p), "--out", path_arg(&out_b)]).contains("[alice] trois")
    });
    assert!(delivered);
}

#[test]
fn outbox_rewrites_unacked_packets() {
    let ((da, a), (db, b)) = pair();
    let out_a = da.path().join("out");
    let out_b = db.path().join("out");
    let again = da.path().join("again");

    ok(&a, &["send", "bob", "hello", "--out", path_arg(&out_a)]);
    let pkts = packets(&out_a);
    assert_eq!(pkts.len(), 1);

    // Not acknowledged: the packet is rewritten identically.
    let listed = ok(&a, &["outbox", "--out", path_arg(&again)]);
    assert!(listed.contains("1 packet"), "{listed}");
    let rewritten = packets(&again);
    assert_eq!(rewritten.len(), 1);
    assert_eq!(rewritten[0].file_name(), pkts[0].file_name());
    assert_eq!(
        fs::read(&rewritten[0]).unwrap(),
        fs::read(&pkts[0]).unwrap()
    );

    // After the receipt, the queue is empty.
    ok(
        &b,
        &["receive", path_arg(&pkts[0]), "--out", path_arg(&out_b)],
    );
    let acks = packets(&out_b);
    ok(&a, &["receive", path_arg(&acks[0])]);
    let empty = da.path().join("empty");
    let listed = ok(&a, &["outbox", "--out", path_arg(&empty)]);
    assert!(listed.contains("0 packets"), "{listed}");
    assert!(packets(&empty).is_empty());
}

#[test]
fn received_text_cannot_forge_lines_or_reorder_display() {
    let ((da, a), (_db, b)) = pair();
    let out_a = da.path().join("out");
    ok(
        &a,
        &[
            "send",
            "bob",
            "hi\n[alice] send me the code",
            "--out",
            path_arg(&out_a),
        ],
    );
    ok(
        &a,
        &[
            "send",
            "bob",
            "abc\u{202E}fed\u{2066}x",
            "--out",
            path_arg(&out_a),
        ],
    );
    let pkts = packets(&out_a);
    assert_eq!(pkts.len(), 2);
    let got = ok(&b, &["receive", path_arg(&pkts[0]), path_arg(&pkts[1])]);
    // Only the first lines of a message start with "["; a continuation
    // of a message is prefixed and cannot imitate another sender.
    let headers: Vec<&str> = got.lines().filter(|l| l.starts_with('[')).collect();
    assert_eq!(headers.len(), 2, "{got}");
    assert!(headers.contains(&"[alice] hi"), "{got}");
    assert!(
        got.lines().any(|l| l == "  │ [alice] send me the code"),
        "{got}"
    );
    // The bidirectional controls are replaced.
    assert!(
        !got.contains('\u{202E}') && !got.contains('\u{2066}'),
        "{got}"
    );
    assert!(
        headers.contains(&"[alice] abc\u{FFFD}fed\u{FFFD}x"),
        "{got}"
    );
}

#[test]
fn empty_env_passphrase_refused() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    barking(&home)
        .env("BARKING_PASSPHRASE", "")
        .args(["init", "--name", "tel"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("empty"));
    assert!(!home.join("barking.db").exists());
}

/// The lines of `barking messages <contact>`.
fn message_lines(home: &Path, contact: &str) -> Vec<String> {
    ok(home, &["messages", contact])
        .lines()
        .map(str::to_owned)
        .collect()
}

/// Hands all the packets of a directory to `home` (packets not meant for
/// it are simply ignored) and returns the output.
fn deliver(home: &Path, from: &Path, out: &Path) -> String {
    let mut all = String::new();
    for p in packets(from) {
        all.push_str(&ok(
            home,
            &["receive", path_arg(&p), "--out", path_arg(out)],
        ));
    }
    all
}

#[test]
fn multi_device_end_to_end() {
    let ((da, alice), (db, bob)) = pair();
    let out_a = da.path().join("out");
    let out_b = db.path().join("out");
    let dt = tempfile::tempdir().unwrap();
    let tablet = dt.path().join("home");
    let out_t = dt.path().join("out");

    // 1. Alice and Bob exchange a message before the link.
    ok(
        &alice,
        &["send", "bob", "before linking", "--out", path_arg(&out_a)],
    );
    deliver(&bob, &out_a, &out_b);
    deliver(&alice, &out_b, &out_a);
    ok(
        &bob,
        &["send", "alice", "reply from bob", "--out", path_arg(&out_b)],
    );
    // Bob's packets received by Alice (the previous receipt is already processed).
    let got = deliver(&alice, &out_b, &out_a);
    assert!(got.contains("[bob] reply from bob"), "{got}");
    let before = message_lines(&alice, "bob");
    assert_eq!(before.len(), 2, "{before:?}");

    // 2. Linking the tablet, with the history.
    let files = dt.path().join("files");
    fs::create_dir_all(&files).unwrap();
    let offer = files.join("offer.bin");
    let request = files.join("request.bin");
    let bundle = files.join("link.bin");
    let history = files.join("history.bin");
    let shown = ok(&alice, &["link", "offer", "--out", path_arg(&offer)]);
    let secret = fs::read(&offer).unwrap();
    assert!(!shown.is_empty());
    assert!(
        !shown
            .as_bytes()
            .windows(8)
            .any(|w| secret.windows(8).any(|s| s == w)),
        "the offer must not be displayed"
    );
    ok(
        &tablet,
        &[
            "link",
            "request",
            "--offer",
            path_arg(&offer),
            "--name",
            "tablet",
            "--out",
            path_arg(&request),
        ],
    );
    let link_out = da.path().join("link-out");
    let accepted = ok(
        &alice,
        &[
            "link",
            "accept",
            "--request",
            path_arg(&request),
            "--out",
            path_arg(&bundle),
            "--history",
            path_arg(&history),
            "--packets",
            path_arg(&link_out),
        ],
    );
    assert!(accepted.contains("Device linked"), "{accepted}");
    // The tablet refuses to act before the link is finished.
    barking(&tablet)
        .args(["messages", "bob"])
        .assert()
        .failure();
    let finished = ok(
        &tablet,
        &[
            "link",
            "finish",
            "--bundle",
            path_arg(&bundle),
            "--history",
            path_arg(&history),
        ],
    );
    assert!(finished.contains("Delete the link files now"), "{finished}");

    // 3. Bob receives Alice's new card, then writes to her: the tablet receives.
    let got = deliver(&bob, &link_out, &out_b);
    assert!(got.contains("device list"), "{got}");
    let to_alice = db.path().join("to-alice");
    ok(
        &bob,
        &[
            "send",
            "alice",
            "bonjour aux deux",
            "--out",
            path_arg(&to_alice),
        ],
    );
    assert_eq!(packets(&to_alice).len(), 2);
    let got_t = deliver(&tablet, &to_alice, &out_t);
    assert!(got_t.contains("[bob] bonjour aux deux"), "{got_t}");
    let got_a = deliver(&alice, &to_alice, &out_a);
    assert!(got_a.contains("[bob] bonjour aux deux"), "{got_a}");

    // 4. Alice writes from the phone: the tablet sees the message.
    let from_a = da.path().join("from-a");
    ok(
        &alice,
        &["send", "bob", "from the phone", "--out", path_arg(&from_a)],
    );
    let got_t = deliver(&tablet, &from_a, &out_t);
    assert!(got_t.contains("synced"), "{got_t}");
    deliver(&bob, &from_a, &out_b);

    // 5. History present on the tablet, one line per message.
    let on_t = message_lines(&tablet, "bob");
    let on_a = message_lines(&alice, "bob");
    assert_eq!(on_t.len(), 4, "{on_t:?}");
    assert_eq!(on_a.len(), 4, "{on_a:?}");
    for text in [
        "before linking",
        "reply from bob",
        "bonjour aux deux",
        "from the phone",
    ] {
        assert_eq!(
            on_t.iter().filter(|l| l.contains(text)).count(),
            1,
            "{text} : {on_t:?}"
        );
    }
    // The direction is displayed.
    assert!(
        on_t.iter()
            .any(|l| l.contains('→') && l.contains("before linking"))
    );
    assert!(
        on_t.iter()
            .any(|l| l.contains('←') && l.contains("reply from bob"))
    );
}

#[cfg(unix)]
#[test]
fn link_files_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let (d, alice) = party("tel-a");
    let offer = d.path().join("offer.bin");
    ok(&alice, &["link", "offer", "--out", path_arg(&offer)]);
    let mode = fs::metadata(&offer).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn link_request_refuses_existing_home_and_oversized_files() {
    let (d, alice) = party("tel-a");
    let offer = d.path().join("offer.bin");
    ok(&alice, &["link", "offer", "--out", path_arg(&offer)]);
    // The directory already contains an identity: nothing is modified.
    let before = ok(&alice, &["whoami"]);
    barking(&alice)
        .args([
            "link",
            "request",
            "--offer",
            path_arg(&offer),
            "--name",
            "x",
            "--out",
        ])
        .arg(d.path().join("request.bin"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));
    assert_eq!(ok(&alice, &["whoami"]), before);
    // Oversized file: refused before reading, before creating the directory.
    let big = d.path().join("big.bin");
    fs::write(&big, vec![0u8; 100 * 1024]).unwrap();
    let tablet = d.path().join("tablet");
    barking(&tablet)
        .args([
            "link",
            "request",
            "--offer",
            path_arg(&big),
            "--name",
            "x",
            "--out",
        ])
        .arg(d.path().join("request.bin"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("too large"));
    assert!(!tablet.exists());
}

#[test]
fn alias_command_renames_contact() {
    let ((_da, alice), (_db, _bob)) = pair();
    ok(&alice, &["alias", "bob", "robert"]);
    let list = ok(&alice, &["contacts"]);
    assert!(list.contains("robert"), "{list}");
    assert!(!list.contains("bob "), "{list}");
    barking(&alice)
        .args(["alias", "inconnu", "x"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Unknown contact"));
}

#[test]
fn link_accept_unusable_output_keeps_offer_usable() {
    let (d, alice) = party("tel-a");
    let dt = tempfile::tempdir().unwrap();
    let tablet = dt.path().join("home");
    let offer = d.path().join("offer.bin");
    let request = d.path().join("request.bin");
    ok(&alice, &["link", "offer", "--out", path_arg(&offer)]);
    ok(
        &tablet,
        &[
            "link",
            "request",
            "--offer",
            path_arg(&offer),
            "--name",
            "t",
            "--out",
            path_arg(&request),
        ],
    );
    let missing = d.path().join("absent").join("link.bin");
    let bundle = d.path().join("link.bin");
    // Unusable output: refused, nothing is consumed.
    barking(&alice)
        .args(["link", "accept", "--request", path_arg(&request), "--out"])
        .arg(&missing)
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot write"));
    // Same for the packets directory (a file in place of a directory).
    let blocker = d.path().join("bloque");
    fs::write(&blocker, b"x").unwrap();
    barking(&alice)
        .args(["link", "accept", "--request", path_arg(&request), "--out"])
        .arg(&bundle)
        .args(["--packets"])
        .arg(blocker.join("paquets"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("packets directory"));
    assert!(!bundle.exists());
    // A second, correct accept succeeds with the same offer.
    ok(
        &alice,
        &[
            "link",
            "accept",
            "--request",
            path_arg(&request),
            "--out",
            path_arg(&bundle),
        ],
    );
    ok(&tablet, &["link", "finish", "--bundle", path_arg(&bundle)]);
}

#[cfg(unix)]
#[test]
fn link_request_unwritable_output_leaves_no_home() {
    use std::os::unix::fs::PermissionsExt;
    let (d, alice) = party("tel-a");
    let offer = d.path().join("offer.bin");
    ok(&alice, &["link", "offer", "--out", path_arg(&offer)]);
    let ro = d.path().join("ro");
    fs::create_dir(&ro).unwrap();
    fs::set_permissions(&ro, fs::Permissions::from_mode(0o500)).unwrap();
    let tablet = d.path().join("tablet");
    let r = barking(&tablet)
        .args([
            "link",
            "request",
            "--offer",
            path_arg(&offer),
            "--name",
            "t",
            "--out",
        ])
        .arg(ro.join("request.bin"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot write"));
    drop(r);
    fs::set_permissions(&ro, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(!tablet.exists());
    // A new attempt is possible, and the hint to delete the offer is displayed.
    let out = ok(
        &tablet,
        &[
            "link",
            "request",
            "--offer",
            path_arg(&offer),
            "--name",
            "t",
            "--out",
            path_arg(&d.path().join("request.bin")),
        ],
    );
    assert!(out.contains("Delete"), "{out}");
}

#[test]
fn log_neutralises_control_characters_in_names() {
    // The device name comes from the link request (chosen by T) and
    // comes back in the admin's log.
    let (d, alice) = party("tel-a");
    let offer = d.path().join("offer.bin");
    let request = d.path().join("request.bin");
    let bundle = d.path().join("link.bin");
    let tablet = d.path().join("tablet");
    ok(&alice, &["link", "offer", "--out", path_arg(&offer)]);
    ok(
        &tablet,
        &[
            "link",
            "request",
            "--offer",
            path_arg(&offer),
            "--name",
            "tab\u{1b}[2Jlette",
            "--out",
            path_arg(&request),
        ],
    );
    ok(
        &alice,
        &[
            "link",
            "accept",
            "--request",
            path_arg(&request),
            "--out",
            path_arg(&bundle),
        ],
    );
    let log = ok(&alice, &["log"]);
    assert!(!log.contains('\u{1b}'), "{log:?}");
    assert!(log.contains("tab\u{FFFD}[2Jlette"), "{log}");
}

// --- Sync through the nodes (network transport) ---

mod node {
    use std::net::{SocketAddr, UdpSocket};
    use std::time::Duration;

    use barking_dht::BootstrapEntry;
    use barking_node::config::{DEFAULT_REPLICATION_BYTES_PER_HOUR, DhtConfig};
    use barking_node::server::{self, ServerConfig};
    use barking_node::{NodeStore, Policy};
    use barking_proto::NodeId;
    use ed25519_dalek::SigningKey;
    use tokio::sync::oneshot;

    use super::*;

    /// Key seeds that solve the 20-bit identity puzzle (the first keys of
    /// `generate_node_key` on `StdRng::seed_from_u64(4243)`, as in
    /// barking-node's tests): drawing them at runtime takes ~15 s each.
    const SEEDS: [[u8; 32]; 2] = [
        [
            66, 125, 129, 83, 32, 106, 225, 91, 180, 232, 72, 26, 247, 131, 101, 82, 217, 244, 181,
            75, 156, 236, 14, 63, 198, 19, 50, 80, 99, 40, 172, 214,
        ],
        [
            132, 124, 253, 169, 65, 12, 180, 150, 216, 192, 72, 216, 245, 177, 206, 219, 134, 97,
            245, 5, 63, 158, 43, 124, 74, 232, 33, 130, 79, 123, 173, 159,
        ],
    ];

    fn key(n: usize) -> SigningKey {
        SigningKey::from_bytes(&SEEDS[n])
    }

    #[test]
    fn test_keys_solve_puzzle() {
        for n in 0..SEEDS.len() {
            assert!(
                NodeId::from_public_key(&key(n).verifying_key()).puzzle_ok(),
                "key {n}"
            );
        }
    }

    /// A real node in this process, on 127.0.0.1 (free port), with its
    /// hash table on (it answers `Ping` with its record).
    struct TestNode {
        addr: SocketAddr,
        id: String,
        db: PathBuf,
        _dir: TempDir,
        stop: Option<oneshot::Sender<()>>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl TestNode {
        fn start(n: usize) -> TestNode {
            Self::start_with(n, |_| {})
        }

        fn start_with(n: usize, tweak: impl FnOnce(&mut ServerConfig)) -> TestNode {
            let dir = tempfile::tempdir().unwrap();
            let db = dir.path().join("node.db");
            let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            let addr = socket.local_addr().unwrap();
            let key = key(n);
            let id = NodeId::from_public_key(&key.verifying_key()).to_string();
            let mut cfg = ServerConfig::new(vec![socket], key);
            cfg.dht = Some(DhtConfig {
                public_v4: match addr {
                    SocketAddr::V4(a) => Some(a),
                    SocketAddr::V6(_) => None,
                },
                public_v6: None,
                bootstrap: Vec::new(),
                allow_private_addrs: true,
                replication_bytes_per_hour: DEFAULT_REPLICATION_BYTES_PER_HOUR,
            });
            tweak(&mut cfg);
            let store = NodeStore::open(&db).unwrap();
            let policy = Policy {
                pow_bits: 4,
                ..Policy::default()
            };
            let (tx, rx) = oneshot::channel::<()>();
            let thread = std::thread::spawn(move || {
                let rt = tokio::runtime::Runtime::new().unwrap();
                let _ = rt.block_on(server::run(cfg, store, policy, async move {
                    let _ = rx.await;
                }));
            });
            TestNode {
                addr,
                id,
                db,
                _dir: dir,
                stop: Some(tx),
                thread: Some(thread),
            }
        }

        fn stats(&self) -> barking_node::Stats {
            NodeStore::open(&self.db).unwrap().stats().unwrap()
        }

        fn entry(&self) -> BootstrapEntry {
            BootstrapEntry {
                id: self.id.parse().unwrap(),
                addr: self.addr,
            }
        }
    }

    impl Drop for TestNode {
        fn drop(&mut self) {
            if let Some(tx) = self.stop.take() {
                let _ = tx.send(());
            }
            if let Some(t) = self.thread.take() {
                let _ = t.join();
            }
        }
    }

    fn node_add(home: &Path, addr: SocketAddr, id: &str) {
        ok(home, &["node", "add", &addr.to_string(), id]);
    }

    #[test]
    fn two_clis_talk_via_node() {
        let node = TestNode::start(0);
        let ((da, a), (_db, b)) = pair();
        node_add(&a, node.addr, &node.id);
        node_add(&b, node.addr, &node.id);

        let out = da.path().join("out");
        ok(&a, &["send", "bob", "hi via node", "--out", path_arg(&out)]);
        let sync_a = ok(&a, &["sync"]);
        assert!(
            sync_a.contains("deposited 1 (first copies 1, extra 0)"),
            "{sync_a}"
        );
        assert_eq!(node.stats().packets, 1);

        let sync_b = ok(&b, &["sync"]);
        assert!(sync_b.contains("[alice] hi via node"), "{sync_b}");
        // A first contact arrives in an introduction mailbox, fetched after
        // the deposits: the receipt goes out at the next sync, and erases
        // the packet from the node.
        let sync_b2 = ok(&b, &["sync"]);
        let st = node.stats();
        assert_eq!((st.packets, st.acks), (0, 1), "{sync_b2}");

        let sync_a2 = ok(&a, &["sync"]);
        assert!(sync_a2.contains("delivered"), "{sync_a2}");
        assert_eq!(node.stats().packets, 0);
        assert!(ok(&a, &["messages", "bob"]).contains("delivered"));

        let log = ok(&a, &["log"]);
        assert!(log.contains("packets deposited on node"), "{log}");
        assert!(log.contains("Mailboxes fetched from node"), "{log}");
        // Neither mailbox nor address in the log.
        assert!(!log.contains("127.0.0.1"), "{log}");
        // No mailbox identifier (hex or base32): no long alphanumeric run.
        assert!(
            log.split(|c: char| !c.is_ascii_alphanumeric())
                .all(|w| w.len() < 20),
            "{log}"
        );
    }

    /// No file under `home` contains these identifiers (raw bytes,
    /// hex or base32).
    fn assert_no_ids_in(home: &Path, ids: &[[u8; 16]]) {
        let mut stack = vec![home.to_path_buf()];
        while let Some(d) = stack.pop() {
            for e in fs::read_dir(&d).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    stack.push(p);
                    continue;
                }
                let bytes = fs::read(&p).unwrap();
                let text = String::from_utf8_lossy(&bytes).to_ascii_lowercase();
                for id in ids {
                    let forms = [
                        data_encoding::HEXLOWER.encode(id),
                        data_encoding::BASE32_NOPAD.encode(id).to_ascii_lowercase(),
                    ];
                    for f in &forms {
                        assert!(!text.contains(f.as_str()), "{} contains {f}", p.display());
                    }
                    assert!(
                        !bytes.windows(16).any(|w| w == id),
                        "{} contains a raw identifier",
                        p.display()
                    );
                }
            }
        }
    }

    /// Number of items received announced by the summary of `sync`.
    fn received(out: &str) -> usize {
        let line = out.lines().find(|l| l.starts_with("polled ")).unwrap();
        let after = &line[line.find("received ").unwrap() + "received ".len()..];
        after.split(' ').next().unwrap().parse().unwrap()
    }

    /// A flooded introduction mailbox (anyone can compute it) does not
    /// delay the sessions: the session message arrives in the same sync,
    /// the poll is recorded, and the introduction poll resumes where it
    /// had stopped.
    #[test]
    fn flooded_intro_mailbox_does_not_block_sessions() {
        use barking_core::packet::{DEFAULT_HOPS, Kind, Packet, PacketId, Tier};
        use barking_proto::client::Client;

        let node = TestNode::start_with(0, |c| {
            c.limits.requests_per_sec = 100_000;
            c.limits.bytes_per_sec = 1 << 30;
        });
        let ((da, a), (db, b)) = pair();
        node_add(&a, node.addr, &node.id);
        node_add(&b, node.addr, &node.id);

        // Session established through files; the first contact gives Bob's
        // introduction mailbox for today.
        let out_a = da.path().join("out");
        ok(&a, &["send", "bob", "ouverture", "--out", path_arg(&out_a)]);
        let first = packets(&out_a).remove(0);
        let intro = Packet::decode(&fs::read(&first).unwrap()).unwrap().mailbox;
        let out_b = db.path().join("out");
        ok(
            &b,
            &["receive", path_arg(&first), "--out", path_arg(&out_b)],
        );
        ok(&b, &["send", "alice", "retour", "--out", path_arg(&out_b)]);
        for p in packets(&out_b) {
            ok(&a, &["receive", path_arg(&p), "--out", path_arg(&out_a)]);
        }

        // Flood: 600 L packets (~9.4 MiB) in the introduction mailbox.
        const JUNK: u32 = 600;
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let id: NodeId = node.id.parse().unwrap();
            let mut s = Client::connect(node.addr, id).await.unwrap();
            let expires = u32::try_from(super::now_secs() + 86_400).unwrap();
            for n in 0..JUNK {
                let mut pid = [0xEE; 16];
                pid[..4].copy_from_slice(&n.to_le_bytes());
                let p = Packet {
                    kind: Kind::Message,
                    hops: DEFAULT_HOPS,
                    tier: Tier::L,
                    id: PacketId(pid),
                    expires_at: expires,
                    mailbox: intro,
                    payload: vec![n as u8; 16],
                };
                assert_eq!(s.deposit(&p.encode()).await.unwrap(), Ok(()));
            }
            s.close().await;
        });

        // Alice writes on the session, through the node.
        let out2 = da.path().join("out2");
        ok(
            &a,
            &[
                "send",
                "bob",
                "through the session",
                "--out",
                path_arg(&out2),
            ],
        );
        ok(&a, &["sync"]);

        let s1 = ok(&b, &["sync"]);
        assert!(s1.contains("[alice] through the session"), "{s1}");
        assert!(s1.contains("introductions: partial poll"), "{s1}");
        assert!(s1.contains("Poll recorded"), "{s1}");
        let r1 = received(&s1);
        assert!(r1 < JUNK as usize, "{r1}");
        // The sync state (positions, deposits) is in the encrypted database:
        // no mailbox or packet identifier in the clear.
        let sent = Packet::decode(&fs::read(packets(&out2).remove(0)).unwrap()).unwrap();
        let first_id = Packet::decode(&fs::read(&first).unwrap()).unwrap().id;
        let ids = [intro.0, sent.mailbox.0, sent.id.0, first_id.0];
        assert_no_ids_in(&a, &ids);
        assert_no_ids_in(&b, &ids);

        // The next sync resumes at the cursor: only the rest.
        let s2 = ok(&b, &["sync"]);
        assert!(!s2.contains("introductions: partial poll"), "{s2}");
        assert!(s2.contains("Poll recorded"), "{s2}");
        let r2 = received(&s2);
        assert!(r1 + r2 >= JUNK as usize, "{r1} + {r2}");
        assert!(r2 < JUNK as usize - r1 + 50, "{r1} + {r2}");
    }

    /// A long send queue (receipts and messages) does not block the poll:
    /// it happens first, the receipts go out first, and a `RateLimited` on
    /// the deposits stops the deposits without failing the sync; the
    /// following syncs finish without redepositing.
    #[test]
    fn outbox_backlog_does_not_block_fetch() {
        let node = TestNode::start(0);
        let ((da, a), (db, b)) = pair();
        node_add(&a, node.addr, &node.id);
        node_add(&b, node.addr, &node.id);
        // Session established through files: Bob's messages then arrive in
        // session mailboxes, fetched before the deposits.
        let out_a = da.path().join("out");
        let out_b = db.path().join("out");
        ok(&a, &["send", "bob", "ouverture", "--out", path_arg(&out_a)]);
        for p in packets(&out_a) {
            ok(&b, &["receive", path_arg(&p), "--out", path_arg(&out_b)]);
        }
        ok(&b, &["send", "alice", "retour", "--out", path_arg(&out_b)]);
        for p in packets(&out_b) {
            ok(&a, &["receive", path_arg(&p), "--out", path_arg(&out_a)]);
        }
        let acks_before = node.stats().acks;
        let out_b = db.path().join("out-node");
        for i in 0..3 {
            ok(
                &b,
                &[
                    "send",
                    "alice",
                    &format!("de Bob {i}"),
                    "--out",
                    path_arg(&out_b),
                ],
            );
        }
        ok(&b, &["sync"]);
        const N: usize = 100;
        let out_a = da.path().join("out-node");
        for i in 0..N {
            ok(
                &a,
                &["send", "bob", &format!("m{i}"), "--out", path_arg(&out_a)],
            );
        }
        // Bucket of the 127.0.0.1 group refilled.
        std::thread::sleep(std::time::Duration::from_secs(3));
        let s1 = ok(&a, &["sync"]);
        for i in 0..3 {
            assert!(s1.contains(&format!("[bob] de Bob {i}")), "{s1}");
        }
        assert!(s1.contains("Poll recorded"), "{s1}");
        // Rate limited: not everything went out in one sync.
        assert!(node.stats().packets < N as u64);
        // The three receipts went out before the messages.
        assert!(node.stats().acks >= acks_before + 3);
        let mut done = false;
        for _ in 0..8 {
            std::thread::sleep(std::time::Duration::from_secs(3));
            let s = ok(&a, &["sync"]);
            assert!(s.contains("Poll recorded"), "{s}");
            if node.stats().packets == N as u64 {
                done = true;
                break;
            }
        }
        assert!(done);
        // Everything is already deposited: nothing is redeposited.
        std::thread::sleep(std::time::Duration::from_secs(3));
        let s = ok(&a, &["sync"]);
        assert!(s.contains("deposited 0 "), "{s}");
    }

    /// Proof budget exhausted: the receipts (without proof) still go out.
    #[test]
    fn pow_budget_exhausted_still_sends_acks() {
        let node = TestNode::start(0);
        let ((da, a), (db, b)) = pair();
        node_add(&a, node.addr, &node.id);
        node_add(&b, node.addr, &node.id);
        let out_a = da.path().join("out");
        ok(&a, &["send", "bob", "bonjour", "--out", path_arg(&out_a)]);
        ok(&a, &["sync"]);
        let out_b = db.path().join("out");
        ok(
            &b,
            &["send", "alice", "en attente", "--out", path_arg(&out_b)],
        );
        let sync_b = || {
            let got = barking(&b)
                .env("BARKING_TEST_POW_BUDGET", "0")
                .arg("sync")
                .assert()
                .success()
                .get_output()
                .clone();
            String::from_utf8(got.stdout).unwrap()
        };
        let s = sync_b();
        assert!(s.contains("[alice] bonjour"), "{s}");
        assert!(s.contains("proof-of-work budget exhausted"), "{s}");
        // The receipt of a first contact (introduction mailbox, fetched
        // after the deposits) goes out at the next sync.
        let s = sync_b();
        assert!(s.contains("proof-of-work budget exhausted"), "{s}");
        // The receipt is deposited (it erased the message), not Bob's message.
        let st = node.stats();
        assert_eq!((st.packets, st.acks), (0, 1));
        assert!(ok(&a, &["sync"]).contains("delivered"));
    }

    /// An old plaintext state file is migrated into the database then erased.
    #[test]
    fn legacy_plaintext_state_is_migrated_and_removed() {
        let node = TestNode::start(0);
        let (_d, home) = party("tel");
        node_add(&home, node.addr, &node.id);
        let legacy = format!(
            "[[node]]\nid = \"{}\"\n[[node.deposited]]\nid = \"{}\"\nat = 1\n",
            node.id,
            "ab".repeat(16)
        );
        fs::write(home.join("sync_state.toml"), &legacy).unwrap();
        fs::write(home.join("fetch_cursors.toml"), "[[node]]\nid = \"x\"\n").unwrap();
        assert!(ok(&home, &["sync"]).contains("Poll recorded"));
        assert!(!home.join("sync_state.toml").exists());
        assert!(!home.join("fetch_cursors.toml").exists());
        assert_no_ids_in(&home, &[[0xab; 16]]);
    }

    /// The introduction poll has its own share of the deadline: when exceeded,
    /// it is partial, without preventing sessions, deposits or `mark_polled`.
    #[test]
    fn intro_fetch_overrun_is_partial_not_failure() {
        let node = TestNode::start(0);
        let ((da, a), (db, b)) = pair();
        node_add(&a, node.addr, &node.id);
        node_add(&b, node.addr, &node.id);
        // Session established through files.
        let out_a = da.path().join("out");
        ok(&a, &["send", "bob", "ouverture", "--out", path_arg(&out_a)]);
        let first = packets(&out_a).remove(0);
        let out_b = db.path().join("out");
        ok(
            &b,
            &["receive", path_arg(&first), "--out", path_arg(&out_b)],
        );
        ok(&b, &["send", "alice", "retour", "--out", path_arg(&out_b)]);
        for p in packets(&out_b) {
            ok(&a, &["receive", path_arg(&p), "--out", path_arg(&out_a)]);
        }
        let out2 = da.path().join("out2");
        ok(
            &a,
            &[
                "send",
                "bob",
                "through the session",
                "--out",
                path_arg(&out2),
            ],
        );
        ok(&a, &["sync"]);
        let got = barking(&b)
            .env("BARKING_TEST_INTRO_SLICE_MS", "0")
            .arg("sync")
            .assert()
            .success()
            .get_output()
            .clone();
        let s = String::from_utf8(got.stdout).unwrap();
        assert!(s.contains("[alice] through the session"), "{s}");
        assert!(s.contains("introductions: partial poll"), "{s}");
        assert!(s.contains("Poll recorded"), "{s}");
        // Bob's receipt is deposited (Alice's for "retour" awaits its
        // packet: deferred, not kept by the node).
        assert_eq!(node.stats().acks, 1);
    }

    /// A node that went down does not prevent receiving nor recording the
    /// poll: its mailboxes go to the next responsible.
    #[test]
    fn sync_with_one_dead_node() {
        let live = TestNode::start(0);
        let dead = TestNode::start(1);
        let dead_id = dead.id.clone();
        let ((da, a), (_db, b)) = pair();
        // Alice only has the live node; only Bob also has the dead node.
        node_add(&a, live.addr, &live.id);
        node_add(&b, dead.addr, &dead_id);
        node_add(&b, live.addr, &live.id);
        drop(dead);
        let out = da.path().join("out");
        ok(&a, &["send", "bob", "live", "--out", path_arg(&out)]);
        ok(&a, &["sync"]);
        assert_eq!(live.stats().packets, 1);

        let s = ok(&b, &["sync"]);
        assert!(s.contains("[alice] live"), "{s}");
        assert!(s.contains("Poll recorded"), "{s}");

        ok(&b, &["node", "remove", &dead_id]);
        assert!(!list_line(&b, &dead_id).contains("manual"));
        assert!(ok(&b, &["sync"]).contains("Poll recorded"));
    }

    /// The line of `node list` for the node whose id starts with `short`.
    fn list_line(home: &Path, id: &str) -> String {
        ok(home, &["node", "list"])
            .lines()
            .find(|l| l.starts_with(&id[..8]))
            .unwrap_or_else(|| panic!("{} not listed", &id[..8]))
            .to_owned()
    }

    #[test]
    fn node_add_list_remove() {
        let node = TestNode::start(0);
        let (_d, home) = party("tel");
        // Whitespace and lowercase tolerated.
        ok(
            &home,
            &[
                "node",
                "add",
                &node.addr.to_string(),
                &format!(" {} ", node.id.to_lowercase()),
            ],
        );
        // Pinged at addition: confirmed, added by hand, with its address.
        let line = list_line(&home, &node.id);
        assert_eq!(
            line,
            format!(
                "{}  confirmed  score 0.50  manual {}",
                &node.id[..8],
                node.addr
            )
        );
        // The list lives in the encrypted database: no plaintext file.
        assert!(!home.join("nodes.toml").exists());
        barking(&home)
            .args(["node", "add", &node.addr.to_string(), &node.id])
            .assert()
            .failure()
            .stderr(predicate::str::contains("already"));
        // Identifier that fails the puzzle.
        let bad = data_encoding::BASE32_NOPAD.encode(&[7u8; 32]);
        barking(&home)
            .args(["node", "add", "127.0.0.1:1", &bad])
            .assert()
            .failure()
            .stderr(predicate::str::contains("puzzle"));
        barking(&home)
            .args(["node", "add", "127.0.0.1:1", "not-base32"])
            .assert()
            .failure();
        // No longer added by hand: its address is gone, the node stays in
        // the view like any node learned from the network.
        ok(&home, &["node", "remove", &node.id]);
        let line = list_line(&home, &node.id);
        assert!(
            !line.contains("manual") && !line.contains("127.0.0.1"),
            "{line}"
        );
        barking(&home)
            .args(["node", "remove", &node.id])
            .assert()
            .failure();
    }

    /// `node add` proves the node's identity first: another node at that
    /// address, or no node at all, and nothing is added. The error names
    /// neither the address nor a path.
    #[test]
    fn node_add_refuses_unproven_node() {
        let node = TestNode::start(0);
        let other_id = NodeId::from_public_key(&key(1).verifying_key()).to_string();
        let (_d, home) = party("tel");
        let wrong = barking(&home)
            .args(["node", "add", &node.addr.to_string(), &other_id])
            .assert()
            .failure()
            .get_output()
            .clone();
        let err = String::from_utf8(wrong.stderr).unwrap();
        assert!(err.contains("nothing was added"), "{err}");
        assert!(!err.contains("127.0.0.1"), "{err}");
        assert!(!err.contains(home.to_str().unwrap()), "{err}");
        drop(node);
        let dead = UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        barking(&home)
            .args(["node", "add", &dead.to_string(), &other_id])
            .assert()
            .failure()
            .stderr(predicate::str::contains("nothing was added"));
        assert!(ok(&home, &["node", "list"]).contains("No known node"));
    }

    /// Nodes learned from the network are listed without their address:
    /// only those added by hand show one.
    #[test]
    fn node_list_shows_addresses_only_for_manual() {
        let a = TestNode::start_with(0, |c| c.dht_tick = Some(Duration::from_millis(200)));
        let a_entry = a.entry();
        let b = TestNode::start_with(1, move |c| {
            c.dht_tick = Some(Duration::from_millis(200));
            c.dht.as_mut().unwrap().bootstrap = vec![a_entry];
        });
        wait_known(&a, &b);
        let (_d, home) = party("tel");
        node_add(&home, a.addr, &a.id);
        ok(&home, &["sync"]);
        let list = ok(&home, &["node", "list"]);
        assert!(list.contains(&b.id[..8]), "{list}");
        let mut learned = 0;
        for line in list.lines() {
            if line.contains("manual") {
                assert!(line.ends_with(&format!("manual {}", a.addr)), "{line}");
                continue;
            }
            learned += 1;
            for word in line.split_whitespace() {
                assert!(word.parse::<std::net::IpAddr>().is_err(), "{line}");
                assert!(word.parse::<SocketAddr>().is_err(), "{line}");
            }
        }
        assert!(learned >= 1, "{list}");
    }

    /// Waits until `b` is in the table of `a`.
    fn wait_known(a: &TestNode, b: &TestNode) {
        use barking_proto::client::Client;
        use barking_proto::{RecordPolicy, Request, Response};
        let rt = tokio::runtime::Runtime::new().unwrap();
        let a_id: NodeId = a.id.parse().unwrap();
        let b_id: NodeId = b.id.parse().unwrap();
        rt.block_on(async {
            for _ in 0..100 {
                let s = Client::connect(a.addr, a_id).await.unwrap();
                let resp = s
                    .request(&Request::FindNode {
                        target: b_id.0,
                        from: None,
                    })
                    .await;
                s.close().await;
                if let Ok(Response::Nodes { records }) = resp
                    && records
                        .iter()
                        .any(|r| r.verify(now_secs(), &RecordPolicy::network(true)) == Ok(b_id))
                {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            panic!("b never entered the table of a");
        });
    }

    /// No node at all, not even after bootstrap: exit code 1 and a hint.
    #[test]
    fn sync_without_any_node_says_add_contact() {
        let (_d, home) = party("tel");
        barking(&home)
            .arg("sync")
            .assert()
            .failure()
            .stderr(predicate::str::contains(
                "no known node: add a contact or a node",
            ));
    }

    /// Known nodes, none reachable: success, and the queue waits.
    #[test]
    fn sync_with_unreachable_nodes_says_nothing_lost() {
        let node = TestNode::start(0);
        let ((da, a), _b) = pair();
        node_add(&a, node.addr, &node.id);
        drop(node);
        let out = da.path().join("out");
        ok(&a, &["send", "bob", "later", "--out", path_arg(&out)]);
        let s = ok(&a, &["sync"]);
        assert!(s.contains("network unreachable, nothing is lost"), "{s}");
        assert!(!s.contains("Poll recorded"), "{s}");
        let pending = ok(&a, &["outbox", "--out", path_arg(&da.path().join("again"))]);
        assert!(pending.contains("1 packet pending"), "{pending}");
    }

    /// The old plaintext node list enters the view as nodes added by hand,
    /// then the file is removed.
    #[test]
    fn nodes_toml_migrated_then_removed() {
        let node = TestNode::start(0);
        let (_d, home) = party("tel");
        fs::write(
            home.join("nodes.toml"),
            format!("[[node]]\naddr = \"{}\"\nid = \"{}\"\n", node.addr, node.id),
        )
        .unwrap();
        let line = list_line(&home, &node.id);
        assert!(line.contains("candidate"), "{line}");
        assert!(line.ends_with(&format!("manual {}", node.addr)), "{line}");
        assert!(!home.join("nodes.toml").exists());
        // The sync reaches it and confirms it.
        assert!(ok(&home, &["sync"]).contains("Poll recorded"));
        assert!(list_line(&home, &node.id).contains("confirmed"));
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
