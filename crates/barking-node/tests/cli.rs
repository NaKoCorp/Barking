//! Le binaire `barking-node` lancé comme sous-processus : `init`, `run`,
//! `status`, configuration et journaux.

use std::fs;
use std::net::{SocketAddr, UdpSocket};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use barking_packet::{DEFAULT_HOPS, Kind, MailboxId, Packet, PacketId, Tier};
use barking_proto::NodeId;
use barking_proto::client::Client;

const BIN: &str = env!("CARGO_BIN_EXE_barking-node");

fn node(args: &[&str]) -> Output {
    Command::new(BIN).args(args).output().unwrap()
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// Valeur de la ligne `<clé> : <valeur>` de la sortie.
fn field(out: &str, key: &str) -> String {
    out.lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            (k.trim() == key).then(|| v.trim().to_string())
        })
        .unwrap_or_else(|| panic!("champ {key} absent de : {out}"))
}

fn init(dir: &Path) -> Output {
    node(&["init", "--data-dir", dir.to_str().unwrap()])
}

#[test]
fn init_creates_private_key_and_prints_id() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("data");
    let out = init(&dir);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);

    let id: NodeId = field(&stdout, "identifiant").parse().unwrap();
    assert!(id.puzzle_ok(), "l'identifiant doit résoudre le puzzle");
    assert!(!field(&stdout, "adresse").is_empty());

    let key = dir.join("node.key");
    assert_eq!(
        fs::metadata(&key).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert!(dir.join("node.db").exists());
    assert_eq!(
        fs::metadata(dir.join("node.db"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert!(!dir.join("node.key.tmp").exists());
    // La clé écrite redonne bien cet identifiant (status le relit).
    let st = node(&["status", "--data-dir", dir.to_str().unwrap()]);
    assert!(st.status.success(), "{}", text(&st.stderr));
    assert_eq!(field(&text(&st.stdout), "identifiant"), id.to_string());
}

#[test]
fn init_refuses_existing_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("data");
    assert!(init(&dir).status.success());
    let key_before = fs::read(dir.join("node.key")).unwrap();
    let again = init(&dir);
    assert!(!again.status.success());
    assert!(text(&again.stderr).contains("déjà initialisé"));
    assert_eq!(fs::read(dir.join("node.key")).unwrap(), key_before);
}

#[test]
fn config_rejects_unknown_key() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = tmp.path().join("node.toml");
    fs::write(&cfg, "pow_bits = 18\ncle_inconnue = 1\n").unwrap();
    let out = node(&["run", "--config", cfg.to_str().unwrap()]);
    assert!(!out.status.success());
    assert!(
        text(&out.stderr).contains("cle_inconnue"),
        "{}",
        text(&out.stderr)
    );
    // Valeurs hors bornes : refusées aussi.
    fs::write(&cfg, "pow_bits = 25\n").unwrap();
    let out = node(&["run", "--config", cfg.to_str().unwrap()]);
    assert!(!out.status.success());
}

fn free_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Running {
    child: Option<Child>,
}

impl Running {
    fn start(cfg: &Path) -> Running {
        let child = Command::new(BIN)
            .args(["run", "--config", cfg.to_str().unwrap()])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        Running { child: Some(child) }
    }

    /// Arrêt propre (SIGTERM) puis sortie capturée.
    fn stop(mut self) -> Output {
        let child = self.child.take().unwrap();
        let pid = child.id().to_string();
        assert!(
            Command::new("kill")
                .args(["-TERM", &pid])
                .status()
                .unwrap()
                .success()
        );
        child.wait_with_output().unwrap()
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if let Some(c) = self.child.as_mut() {
            let _ = c.kill();
        }
    }
}

fn write_config(dir: &Path, data: &Path, listen: &[SocketAddr]) -> std::path::PathBuf {
    let listen: Vec<String> = listen.iter().map(|a| format!("\"{a}\"")).collect();
    let cfg = dir.join("node.toml");
    fs::write(
        &cfg,
        format!(
            "listen = [{}]\ndata_dir = \"{}\"\npow_bits = 8\nlog_interval_secs = 1\n",
            listen.join(", "),
            data.display()
        ),
    )
    .unwrap();
    cfg
}

async fn connect_when_ready(addr: SocketAddr, id: NodeId) -> barking_proto::client::Session {
    let end = Instant::now() + Duration::from_secs(20);
    loop {
        match Client::connect(addr, id).await {
            Ok(s) => return s,
            Err(e) if Instant::now() > end => panic!("le nœud ne répond pas : {e}"),
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
}

fn status_of(data: &Path) -> String {
    let st = node(&["status", "--data-dir", data.to_str().unwrap()]);
    assert!(st.status.success(), "{}", text(&st.stderr));
    text(&st.stdout)
}

#[tokio::test]
async fn run_and_status() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("data");
    let out = init(&data);
    assert!(out.status.success());
    let id: NodeId = field(&text(&out.stdout), "identifiant").parse().unwrap();

    let addr: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
    let cfg = write_config(tmp.path(), &data, &[addr]);
    let running = Running::start(&cfg);
    let session = connect_when_ready(addr, id).await;
    assert_eq!(session.node_id(), id);
    assert_eq!(session.pow_bits(), 8);
    session.close().await;

    let s = status_of(&data);
    assert_eq!(field(&s, "paquets"), "0");
    assert_eq!(field(&s, "accusés"), "0");

    let out = running.stop();
    assert!(out.status.success(), "arrêt propre : {:?}", out.status);
}

fn message(n: u8, mailbox: [u8; 16]) -> Vec<u8> {
    let expires = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 86_400;
    Packet {
        kind: Kind::Message,
        hops: DEFAULT_HOPS,
        tier: Tier::S,
        id: PacketId([n; 16]),
        expires_at: u32::try_from(expires).unwrap(),
        mailbox: MailboxId(mailbox),
        payload: vec![n; 16],
    }
    .encode()
}

/// Cherche `needle` dans tous les fichiers du dossier (base, WAL…).
fn files_contain(dir: &Path, needle: &[u8]) -> bool {
    fs::read_dir(dir).unwrap().any(|e| {
        let bytes = fs::read(e.unwrap().path()).unwrap();
        bytes.windows(needle.len()).any(|w| w == needle)
    })
}

#[tokio::test]
async fn logs_and_db_contain_no_ip() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("data");
    let out = init(&data);
    assert!(out.status.success());
    let id: NodeId = field(&text(&out.stdout), "identifiant").parse().unwrap();

    // IPv4 et, si la machine l'a, IPv6 sur le même port.
    let port = free_port();
    let v4: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let v6: SocketAddr = format!("[::1]:{port}").parse().unwrap();
    let have_v6 = UdpSocket::bind(v6).is_ok();
    let mut listen = vec![v4];
    if have_v6 {
        listen.push(v6);
    }
    let cfg = write_config(tmp.path(), &data, &listen);
    let running = Running::start(&cfg);

    let mailbox = [0xA7u8; 16];
    let mut targets = vec![v4];
    if have_v6 {
        targets.push(v6);
    }
    for (i, addr) in targets.iter().enumerate() {
        let mut s = connect_when_ready(*addr, id).await;
        assert_eq!(
            s.deposit(&message(i as u8 + 1, mailbox)).await.unwrap(),
            Ok(())
        );
        // Un refus (expiré) alimente aussi les compteurs de refus.
        let mut old = Packet::decode(&message(9, mailbox)).unwrap();
        old.expires_at = 1;
        assert!(s.deposit(&old.encode()).await.unwrap().is_err());
        s.close().await;
    }

    // Cas d'erreur : poignée de main ratée (mauvais identifiant attendu),
    // octets UDP quelconques, flux tronqué.
    let wrong = NodeId([7; 32]);
    assert!(Client::connect(v4, wrong).await.is_err());
    let junk = UdpSocket::bind("127.0.0.1:0").unwrap();
    for n in [1usize, 40, 1200, 1500] {
        junk.send_to(&vec![0xC3; n], v4).unwrap();
    }
    let sess = connect_when_ready(v4, id).await;
    if let Ok((mut send, _recv)) = sess.connection().open_bi().await {
        let _ = send.write_all(&[0, 0, 0xFF, 0xFF, 1, 2, 3]).await;
        let _ = send.finish();
    }
    // Laisse passer au moins un rapport agrégé (intervalle de 1 s).
    tokio::time::sleep(Duration::from_millis(2500)).await;
    sess.close().await;

    let s = status_of(&data);
    assert_eq!(field(&s, "paquets"), targets.len().to_string());

    let out = running.stop();
    assert!(out.status.success());
    let logs = text(&out.stderr) + &text(&out.stdout);
    assert!(
        logs.contains("dépôts"),
        "le rapport agrégé doit apparaître dans les journaux : {logs:?}"
    );
    assert!(!logs.contains("quinn_udp"), "journaux : {logs:?}");
    let b32 = data_encoding::BASE32_NOPAD.encode(&mailbox);
    let b32_lower = b32.to_lowercase();
    for needle in [
        "127.0.0.1",
        "::1",
        "[::",
        &"a7".repeat(16),
        &b32,
        &b32_lower,
    ] {
        assert!(
            !logs.contains(needle),
            "journaux : {needle} trouvé dans {logs:?}"
        );
    }
    // Aucune adresse ni boîte lisible dans la base (et son WAL).
    for needle in ["127.0.0.1", "::1", &"a7".repeat(16), &b32, &b32_lower] {
        assert!(!files_contain(&data, needle.as_bytes()), "base : {needle}");
    }
}

#[test]
fn key_symlink_is_refused_and_init_recovers() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("data");
    assert!(init(&dir).status.success());
    let real = tmp.path().join("real.key");
    fs::rename(dir.join("node.key"), &real).unwrap();
    std::os::unix::fs::symlink(&real, dir.join("node.key")).unwrap();
    let st = node(&["status", "--data-dir", dir.to_str().unwrap()]);
    assert!(!st.status.success());
    assert!(
        text(&st.stderr).contains("fichier ordinaire"),
        "{}",
        text(&st.stderr)
    );

    // Dossier ouvert au groupe : avertissement en français.
    let open = tmp.path().join("open");
    fs::create_dir(&open).unwrap();
    fs::set_permissions(&open, fs::Permissions::from_mode(0o755)).unwrap();
    let out = init(&open);
    assert!(out.status.success());
    assert!(
        text(&out.stderr).contains("avertissement"),
        "{}",
        text(&out.stderr)
    );
}
