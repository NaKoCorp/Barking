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

#[test]
fn empty_env_passphrase_refused() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    barking(&home)
        .env("BARKING_PASSPHRASE", "")
        .args(["init", "--name", "tel"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("vide"));
    assert!(!home.join("barking.db").exists());
}

/// Les lignes de `barking messages <contact>`.
fn message_lines(home: &Path, contact: &str) -> Vec<String> {
    ok(home, &["messages", contact])
        .lines()
        .map(str::to_owned)
        .collect()
}

/// Remet tous les paquets d'un dossier à `home` (les paquets qui ne lui sont
/// pas destinés sont simplement ignorés) et rend la sortie.
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

    // 1. Alice et Bob échangent un message avant la liaison.
    ok(
        &alice,
        &["send", "bob", "avant la liaison", "--out", path_arg(&out_a)],
    );
    deliver(&bob, &out_a, &out_b);
    deliver(&alice, &out_b, &out_a);
    ok(
        &bob,
        &["send", "alice", "réponse de bob", "--out", path_arg(&out_b)],
    );
    // Les paquets de Bob reçus par Alice (l'accusé précédent est déjà traité).
    let got = deliver(&alice, &out_b, &out_a);
    assert!(got.contains("[bob] réponse de bob"), "{got}");
    let before = message_lines(&alice, "bob");
    assert_eq!(before.len(), 2, "{before:?}");

    // 2. Liaison de la tablette, avec l'historique.
    let files = dt.path().join("files");
    fs::create_dir_all(&files).unwrap();
    let offer = files.join("offre.bin");
    let request = files.join("demande.bin");
    let bundle = files.join("liaison.bin");
    let history = files.join("historique.bin");
    let shown = ok(&alice, &["link", "offer", "--out", path_arg(&offer)]);
    let secret = fs::read(&offer).unwrap();
    assert!(!shown.is_empty());
    assert!(
        !shown
            .as_bytes()
            .windows(8)
            .any(|w| secret.windows(8).any(|s| s == w)),
        "l'offre ne doit pas être affichée"
    );
    ok(
        &tablet,
        &[
            "link",
            "request",
            "--offer",
            path_arg(&offer),
            "--name",
            "tablette",
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
    assert!(accepted.contains("Appareil lié"), "{accepted}");
    // La tablette refuse d'agir avant la fin de la liaison.
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
    assert!(
        finished.contains("Supprime maintenant les fichiers de liaison"),
        "{finished}"
    );

    // 3. Bob reçoit la nouvelle carte d'Alice, puis lui écrit : la tablette reçoit.
    let got = deliver(&bob, &link_out, &out_b);
    assert!(got.contains("liste d'appareils"), "{got}");
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

    // 4. Alice écrit depuis le téléphone : la tablette voit le message.
    let from_a = da.path().join("from-a");
    ok(
        &alice,
        &[
            "send",
            "bob",
            "depuis le téléphone",
            "--out",
            path_arg(&from_a),
        ],
    );
    let got_t = deliver(&tablet, &from_a, &out_t);
    assert!(got_t.contains("synchronisé"), "{got_t}");
    deliver(&bob, &from_a, &out_b);

    // 5. Historique présent sur la tablette, une ligne par message.
    let on_t = message_lines(&tablet, "bob");
    let on_a = message_lines(&alice, "bob");
    assert_eq!(on_t.len(), 4, "{on_t:?}");
    assert_eq!(on_a.len(), 4, "{on_a:?}");
    for text in [
        "avant la liaison",
        "réponse de bob",
        "bonjour aux deux",
        "depuis le téléphone",
    ] {
        assert_eq!(
            on_t.iter().filter(|l| l.contains(text)).count(),
            1,
            "{text} : {on_t:?}"
        );
    }
    // Le sens est affiché.
    assert!(
        on_t.iter()
            .any(|l| l.contains('→') && l.contains("avant la liaison"))
    );
    assert!(
        on_t.iter()
            .any(|l| l.contains('←') && l.contains("réponse de bob"))
    );
}

#[cfg(unix)]
#[test]
fn link_files_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let (d, alice) = party("tel-a");
    let offer = d.path().join("offre.bin");
    ok(&alice, &["link", "offer", "--out", path_arg(&offer)]);
    let mode = fs::metadata(&offer).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn link_request_refuses_existing_home_and_oversized_files() {
    let (d, alice) = party("tel-a");
    let offer = d.path().join("offre.bin");
    ok(&alice, &["link", "offer", "--out", path_arg(&offer)]);
    // Le dossier contient déjà une identité : rien n'est modifié.
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
        .arg(d.path().join("demande.bin"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("existe déjà"));
    assert_eq!(ok(&alice, &["whoami"]), before);
    // Fichier démesuré : refusé avant lecture, avant de créer le dossier.
    let big = d.path().join("gros.bin");
    fs::write(&big, vec![0u8; 100 * 1024]).unwrap();
    let tablet = d.path().join("tablette");
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
        .arg(d.path().join("demande.bin"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("trop volumineux"));
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
        .stderr(predicate::str::contains("Contact inconnu"));
}

#[test]
fn link_accept_unusable_output_keeps_offer_usable() {
    let (d, alice) = party("tel-a");
    let dt = tempfile::tempdir().unwrap();
    let tablet = dt.path().join("home");
    let offer = d.path().join("offre.bin");
    let request = d.path().join("demande.bin");
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
    let missing = d.path().join("absent").join("liaison.bin");
    let bundle = d.path().join("liaison.bin");
    // Sortie inutilisable : refusé, rien n'est consommé.
    barking(&alice)
        .args(["link", "accept", "--request", path_arg(&request), "--out"])
        .arg(&missing)
        .assert()
        .failure()
        .stderr(predicate::str::contains("écriture impossible"));
    // Idem pour le dossier des paquets (un fichier à la place d'un dossier).
    let blocker = d.path().join("bloque");
    fs::write(&blocker, b"x").unwrap();
    barking(&alice)
        .args(["link", "accept", "--request", path_arg(&request), "--out"])
        .arg(&bundle)
        .args(["--packets"])
        .arg(blocker.join("paquets"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("dossier des paquets"));
    assert!(!bundle.exists());
    // Un second accept correct réussit avec la même offre.
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
    let offer = d.path().join("offre.bin");
    ok(&alice, &["link", "offer", "--out", path_arg(&offer)]);
    let ro = d.path().join("ro");
    fs::create_dir(&ro).unwrap();
    fs::set_permissions(&ro, fs::Permissions::from_mode(0o500)).unwrap();
    let tablet = d.path().join("tablette");
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
        .arg(ro.join("demande.bin"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("écriture impossible"));
    drop(r);
    fs::set_permissions(&ro, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(!tablet.exists());
    // Nouvel essai possible, et l'indication de supprimer l'offre s'affiche.
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
            path_arg(&d.path().join("demande.bin")),
        ],
    );
    assert!(out.contains("Supprime"), "{out}");
}

#[test]
fn log_neutralises_control_characters_in_names() {
    // Le nom d'appareil vient de la demande de liaison (choisi par T) et
    // revient dans le journal de l'administrateur.
    let (d, alice) = party("tel-a");
    let offer = d.path().join("offre.bin");
    let request = d.path().join("demande.bin");
    let bundle = d.path().join("liaison.bin");
    let tablet = d.path().join("tablette");
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

// --- Synchronisation par les nœuds (transport réseau) ---

mod node {
    use std::net::{SocketAddr, UdpSocket};
    use std::os::unix::fs::PermissionsExt;
    use std::sync::OnceLock;

    use barking_node::server::{self, ServerConfig};
    use barking_node::{NodeStore, Policy};
    use barking_proto::{NodeId, generate_node_key};
    use ed25519_dalek::SigningKey;
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use tokio::sync::oneshot;

    use super::*;

    fn key(n: usize) -> SigningKey {
        static KEYS: OnceLock<Vec<SigningKey>> = OnceLock::new();
        KEYS.get_or_init(|| {
            let mut rng = StdRng::seed_from_u64(4242);
            (0..2).map(|_| generate_node_key(&mut rng)).collect()
        })[n]
            .clone()
    }

    /// Un nœud réel dans ce processus, sur 127.0.0.1 (port libre).
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
        ok(
            &a,
            &["send", "bob", "salut via nœud", "--out", path_arg(&out)],
        );
        let sync_a = ok(&a, &["sync"]);
        assert!(sync_a.contains(&node.id[..8]), "{sync_a}");
        assert_eq!(node.stats().packets, 1);

        let sync_b = ok(&b, &["sync"]);
        assert!(sync_b.contains("[alice] salut via nœud"), "{sync_b}");
        // L'accusé de Bob a effacé le paquet du nœud.
        let st = node.stats();
        assert_eq!((st.packets, st.acks), (0, 1));

        let sync_a2 = ok(&a, &["sync"]);
        assert!(sync_a2.contains("livré"), "{sync_a2}");
        assert_eq!(node.stats().packets, 0);
        assert!(ok(&a, &["messages", "bob"]).contains("livré"));

        let log = ok(&a, &["log"]);
        assert!(log.contains("paquets déposés sur le nœud"), "{log}");
        assert!(log.contains("Boîtes relevées sur le nœud"), "{log}");
        // Ni boîte ni adresse dans le journal.
        assert!(!log.contains("127.0.0.1"), "{log}");
        // Aucun identifiant de boîte (hex ou base32) : aucune longue suite alphanumérique.
        assert!(
            log.split(|c: char| !c.is_ascii_alphanumeric())
                .all(|w| w.len() < 20),
            "{log}"
        );
    }

    /// Aucun fichier sous `home` ne contient ces identifiants (octets bruts,
    /// hex ou base32).
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
                        assert!(!text.contains(f.as_str()), "{} contient {f}", p.display());
                    }
                    assert!(
                        !bytes.windows(16).any(|w| w == id),
                        "{} contient un identifiant brut",
                        p.display()
                    );
                }
            }
        }
    }

    /// Nombre d'éléments reçus annoncé pour le nœud dans la sortie de `sync`.
    fn received(out: &str) -> usize {
        let line = out.lines().find(|l| l.contains("éléments reçus")).unwrap();
        let before = &line[..line.find(" éléments reçus").unwrap()];
        before.rsplit(' ').next().unwrap().parse().unwrap()
    }

    /// Une boîte d'introduction inondée (n'importe qui peut la calculer) ne
    /// retarde pas les sessions : le message de session arrive dans la même
    /// synchronisation, la relève est enregistrée, et la relève des
    /// introductions reprend là où elle s'était arrêtée.
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

        // Session établie par fichiers ; le premier contact donne la boîte
        // d'introduction de Bob pour aujourd'hui.
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

        // Inondation : 600 paquets L (~9,4 Mio) dans la boîte d'introduction.
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

        // Alice écrit sur la session, par le nœud.
        let out2 = da.path().join("out2");
        ok(
            &a,
            &["send", "bob", "par la session", "--out", path_arg(&out2)],
        );
        ok(&a, &["sync"]);

        let s1 = ok(&b, &["sync"]);
        assert!(s1.contains("[alice] par la session"), "{s1}");
        assert!(s1.contains("introductions : relève partielle"), "{s1}");
        assert!(s1.contains("Relève enregistrée"), "{s1}");
        let r1 = received(&s1);
        assert!(r1 < JUNK as usize, "{r1}");
        // L'état de synchronisation (positions, dépôts) est dans la base
        // chiffrée : aucun identifiant de boîte ou de paquet en clair.
        let sent = Packet::decode(&fs::read(packets(&out2).remove(0)).unwrap()).unwrap();
        let first_id = Packet::decode(&fs::read(&first).unwrap()).unwrap().id;
        let ids = [intro.0, sent.mailbox.0, sent.id.0, first_id.0];
        assert_no_ids_in(&a, &ids);
        assert_no_ids_in(&b, &ids);

        // La synchronisation suivante reprend au curseur : le reste seulement.
        let s2 = ok(&b, &["sync"]);
        assert!(!s2.contains("introductions : relève partielle"), "{s2}");
        assert!(s2.contains("Relève enregistrée"), "{s2}");
        let r2 = received(&s2);
        assert!(r1 + r2 >= JUNK as usize, "{r1} + {r2}");
        assert!(r2 < JUNK as usize - r1 + 50, "{r1} + {r2}");
    }

    /// Une longue file d'envoi (accusés et messages) ne bloque pas la
    /// relève : elle a lieu d'abord, les accusés partent en premier, et un
    /// `RateLimited` sur les dépôts arrête les dépôts sans faire échouer le
    /// nœud ; les synchronisations suivantes finissent sans redéposer.
    #[test]
    fn outbox_backlog_does_not_block_fetch() {
        let node = TestNode::start(0);
        let ((da, a), (db, b)) = pair();
        node_add(&a, node.addr, &node.id);
        node_add(&b, node.addr, &node.id);
        let out_b = db.path().join("out");
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
        let out_a = da.path().join("out");
        for i in 0..N {
            ok(
                &a,
                &["send", "bob", &format!("m{i}"), "--out", path_arg(&out_a)],
            );
        }
        // Seau du groupe 127.0.0.1 rechargé.
        std::thread::sleep(std::time::Duration::from_secs(3));
        let s1 = ok(&a, &["sync"]);
        for i in 0..3 {
            assert!(s1.contains(&format!("[bob] de Bob {i}")), "{s1}");
        }
        assert!(s1.contains("Relève enregistrée"), "{s1}");
        assert!(s1.contains("dépôts interrompus"), "{s1}");
        // Les trois accusés sont partis avant les messages.
        assert!(node.stats().acks >= 3);
        let mut done = false;
        for _ in 0..8 {
            std::thread::sleep(std::time::Duration::from_secs(3));
            let s = ok(&a, &["sync"]);
            assert!(s.contains("Relève enregistrée"), "{s}");
            assert!(!s.contains(" 0 déjà présents"), "{s}");
            if !s.contains("dépôts interrompus") {
                done = true;
                break;
            }
        }
        assert!(done);
        assert_eq!(node.stats().packets, N as u64);
        // Tout est déjà déposé : rien n'est redéposé.
        let s = ok(&a, &["sync"]);
        assert!(s.contains(" 0 déposés"), "{s}");
    }

    /// Budget de preuve épuisé : les accusés (sans preuve) partent quand même.
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
        let got = barking(&b)
            .env("BARKING_TEST_POW_BUDGET", "0")
            .arg("sync")
            .assert()
            .success()
            .get_output()
            .clone();
        let s = String::from_utf8(got.stdout).unwrap();
        assert!(s.contains("[alice] bonjour"), "{s}");
        assert!(s.contains("budget de preuve de travail épuisé"), "{s}");
        // L'accusé est déposé (il a effacé le message), pas le message de Bob.
        let st = node.stats();
        assert_eq!((st.packets, st.acks), (0, 1));
        assert!(ok(&a, &["sync"]).contains("livré"));
    }

    /// Un ancien fichier d'état en clair est migré dans la base puis effacé.
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
        assert!(ok(&home, &["sync"]).contains("Relève enregistrée"));
        assert!(!home.join("sync_state.toml").exists());
        assert!(!home.join("fetch_cursors.toml").exists());
        assert_no_ids_in(&home, &[[0xab; 16]]);
    }

    /// La relève des introductions a sa propre part du délai : dépassée, elle
    /// est partielle, sans empêcher sessions, dépôts ni `mark_polled`.
    #[test]
    fn intro_fetch_overrun_is_partial_not_failure() {
        let node = TestNode::start(0);
        let ((da, a), (db, b)) = pair();
        node_add(&a, node.addr, &node.id);
        node_add(&b, node.addr, &node.id);
        // Session établie par fichiers.
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
            &["send", "bob", "par la session", "--out", path_arg(&out2)],
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
        assert!(s.contains("[alice] par la session"), "{s}");
        assert!(s.contains("introductions : relève partielle"), "{s}");
        assert!(s.contains("Relève enregistrée"), "{s}");
        // L'accusé de Bob est déposé (celui d'Alice pour « retour » attend
        // son paquet : différé, non gardé par le nœud).
        assert_eq!(node.stats().acks, 1);
    }

    #[test]
    fn sync_with_one_dead_node() {
        let live = TestNode::start(0);
        // Nœud injoignable : un port UDP libéré aussitôt.
        let dead_addr = UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let dead_id = NodeId::from_public_key(&key(1).verifying_key()).to_string();
        let ((da, a), (_db, b)) = pair();
        // Alice n'a que le nœud vivant ; seul Bob a aussi le nœud mort.
        node_add(&a, live.addr, &live.id);
        node_add(&b, dead_addr, &dead_id);
        node_add(&b, live.addr, &live.id);
        let out = da.path().join("out");
        ok(
            &a,
            &["send", "bob", "par le vivant", "--out", path_arg(&out)],
        );
        ok(&a, &["sync"]);
        assert_eq!(live.stats().packets, 1);

        // Le nœud mort n'empêche pas de recevoir, mais `mark_polled` n'a pas lieu.
        let got = barking(&b)
            .arg("sync")
            .assert()
            .success()
            .get_output()
            .clone();
        let stdout = String::from_utf8(got.stdout).unwrap();
        let stderr = String::from_utf8(got.stderr).unwrap();
        assert!(stdout.contains("[alice] par le vivant"), "{stdout}");
        assert!(stderr.contains(&dead_id[..8]), "{stderr}");
        assert!(stdout.contains("Relève non enregistrée"), "{stdout}");

        // Avec le seul nœud vivant, la relève est enregistrée.
        ok(&b, &["node", "remove", &dead_id]);
        assert!(ok(&b, &["sync"]).contains("Relève enregistrée"));
    }

    #[test]
    fn node_add_list_remove() {
        let (_d, home) = party("tel");
        let addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();
        let id = NodeId::from_public_key(&key(0).verifying_key()).to_string();
        // Espaces et minuscules tolérés.
        ok(
            &home,
            &[
                "node",
                "add",
                &addr.to_string(),
                &format!(" {} ", id.to_lowercase()),
            ],
        );
        let list = ok(&home, &["node", "list"]);
        assert!(
            list.contains(&id) && list.contains("127.0.0.1:4433"),
            "{list}"
        );
        let mode = fs::metadata(home.join("nodes.toml"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        // Identifiant qui échoue au puzzle.
        let bad = data_encoding::BASE32_NOPAD.encode(&[7u8; 32]);
        barking(&home)
            .args(["node", "add", "127.0.0.1:1", &bad])
            .assert()
            .failure()
            .stderr(predicate::str::contains("puzzle"));
        barking(&home)
            .args(["node", "add", "127.0.0.1:1", "pas-base32"])
            .assert()
            .failure();
        ok(&home, &["node", "remove", &id]);
        assert!(!ok(&home, &["node", "list"]).contains(&id));
        barking(&home)
            .args(["node", "remove", &id])
            .assert()
            .failure();
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
