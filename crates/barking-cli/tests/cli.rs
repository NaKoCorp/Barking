//! Tests de bout en bout du binaire `barking` (transport : fichiers).

use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

const PASS: &str = "test";

fn barking(home: &Path) -> Command {
    let mut cmd = Command::cargo_bin("barking").unwrap();
    cmd.env("BARKING_PASSPHRASE", PASS).arg("--home").arg(home);
    cmd
}

/// Lance une commande qui doit réussir et rend sa sortie standard.
fn ok(home: &Path, args: &[&str]) -> String {
    let out = barking(home)
        .args(args)
        .assert()
        .success()
        .get_output()
        .clone();
    String::from_utf8(out.stdout).unwrap()
}

/// Un appareil initialisé.
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

/// A et B se connaissent : `bob` chez A, `alice` chez B.
fn pair() -> ((TempDir, PathBuf), (TempDir, PathBuf)) {
    let a = party("tel-a");
    let b = party("tel-b");
    ok(&a.1, &["add", &card(&b.1, "Bob"), "--alias", "bob"]);
    ok(&b.1, &["add", &card(&a.1, "Alice"), "--alias", "alice"]);
    (a, b)
}

/// Les fichiers `.pkt` d'un dossier, triés.
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

    let sent = ok(&a, &["send", "bob", "salut", "--out", path_arg(&out_a)]);
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
    assert!(got.contains("[alice] salut"), "{got}");
    let acks = packets(&out_b);
    assert_eq!(acks.len(), 1);

    let ack = ok(&a, &["receive", path_arg(&acks[0])]);
    assert!(ack.contains("livré"), "{ack}");
}

#[test]
fn wrong_passphrase_exits_nonzero() {
    let (_d, home) = party("tel");
    barking(&home)
        .env("BARKING_PASSPHRASE", "mauvaise")
        .arg("whoami")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Phrase de passe incorrecte"));
    // La bonne phrase fonctionne toujours.
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
        .stderr(predicate::str::contains("existe déjà"));
    assert_eq!(ok(&home, &["whoami"]), before);
}

#[test]
fn init_shows_fingerprint_and_recovery_phrase() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let out = ok(&home, &["init", "--name", "tel"]);
    assert!(out.contains("Note-la hors ligne"), "{out}");
    let phrase = out
        .lines()
        .find(|l| l.split_whitespace().count() == 24)
        .expect("phrase de 24 mots");
    let fp = ok(&home, &["whoami"]);
    assert!(out.contains(fp.trim()), "{out}");

    // `recover` relit la phrase sur l'entrée standard et retrouve l'identité.
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
    ok(&a, &["send", "bob", "salut", "--out", path_arg(&out_a)]);
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
        assert!(log.contains("Les relais voient"), "{log}");
        assert!(!log.contains("salut"), "le journal ne montre pas le texte");
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
    assert!(list.contains("non vérifié"), "{list}");

    let code = ok(&a, &["safety", "bob"]);
    assert_eq!(code, ok(&b, &["safety", "alice"]));
    let again = ok(&a, &["safety", "bob", "--verified"]);
    assert!(again.contains(code.trim()), "{again}");
    let list = ok(&a, &["contacts"]);
    assert!(!list.contains("non vérifié"), "{list}");
    assert!(list.contains("vérifié"), "{list}");
}

#[test]
fn unknown_contact_and_invalid_card_exit_nonzero() {
    let (d, home) = party("tel");
    let out = d.path().join("out");
    barking(&home)
        .args(["send", "personne", "x", "--out", path_arg(&out)])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Contact inconnu"));
    barking(&home)
        .args(["safety", "personne"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Contact inconnu"));
    barking(&home)
        .args(["add", "pas-une-carte"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Carte de contact invalide"));
    barking(&home)
        .args(["add", "barking1:AAAA"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Carte de contact invalide"));
    assert!(!out.exists() || packets(&out).is_empty());
}

#[test]
fn receive_reports_duplicate_and_not_for_us() {
    let ((da, a), (db, b)) = pair();
    let out_a = da.path().join("out");
    let out_b = db.path().join("out");
    ok(&a, &["send", "bob", "salut", "--out", path_arg(&out_a)]);
    let pkt = packets(&out_a).remove(0);

    ok(&b, &["receive", path_arg(&pkt), "--out", path_arg(&out_b)]);
    let again = ok(&b, &["receive", path_arg(&pkt), "--out", path_arg(&out_b)]);
    assert!(again.contains("doublon"), "{again}");
    assert!(!again.contains("salut"), "{again}");

    // Mon propre paquet n'est pas pour moi.
    let mine = ok(&a, &["receive", path_arg(&pkt)]);
    assert!(mine.contains("pas pour toi"), "{mine}");

    // Un fichier illisible n'est pas pour moi non plus.
    let junk = da.path().join("junk.pkt");
    fs::write(&junk, b"n'importe quoi").unwrap();
    let out = ok(&b, &["receive", path_arg(&junk)]);
    assert!(out.contains("pas pour toi"), "{out}");
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
    assert!(removed.contains("supprimé"), "{removed}");
    assert!(!ok(&a, &["contacts"]).contains("bob"));
    barking(&a)
        .args(["send", "bob", "deux", "--out", path_arg(&out_a)])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Contact inconnu"));
    barking(&a)
        .args(["remove", "bob"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Contact inconnu"));

    // Rajouté, il redevient joignable.
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

    ok(&a, &["send", "bob", "salut", "--out", path_arg(&out_a)]);
    let pkts = packets(&out_a);
    assert_eq!(pkts.len(), 1);

    // Non acquitté : le paquet est réécrit à l'identique.
    let listed = ok(&a, &["outbox", "--out", path_arg(&again)]);
    assert!(listed.contains("1 paquet"), "{listed}");
    let rewritten = packets(&again);
    assert_eq!(rewritten.len(), 1);
    assert_eq!(rewritten[0].file_name(), pkts[0].file_name());
    assert_eq!(
        fs::read(&rewritten[0]).unwrap(),
        fs::read(&pkts[0]).unwrap()
    );

    // Après l'accusé, la file est vide.
    ok(
        &b,
        &["receive", path_arg(&pkts[0]), "--out", path_arg(&out_b)],
    );
    let acks = packets(&out_b);
    ok(&a, &["receive", path_arg(&acks[0])]);
    let empty = da.path().join("empty");
    let listed = ok(&a, &["outbox", "--out", path_arg(&empty)]);
    assert!(listed.contains("0 paquet"), "{listed}");
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
    // Seules les premières lignes de message commencent par « [ » ; une suite
    // de message est préfixée et ne peut pas imiter un autre expéditeur.
    let headers: Vec<&str> = got.lines().filter(|l| l.starts_with('[')).collect();
    assert_eq!(headers.len(), 2, "{got}");
    assert!(headers.contains(&"[alice] hi"), "{got}");
    assert!(
        got.lines().any(|l| l == "  │ [alice] send me the code"),
        "{got}"
    );
    // Les contrôles bidirectionnels sont remplacés.
    assert!(
        !got.contains('\u{202E}') && !got.contains('\u{2066}'),
        "{got}"
    );
    assert!(
        headers.contains(&"[alice] abc\u{FFFD}fed\u{FFFD}x"),
        "{got}"
    );
}
