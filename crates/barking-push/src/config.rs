//! TOML configuration and key files of the relay.
//!
//! Key files follow the conventions of `barking-node`: a regular file (no
//! symbolic link, no other type) with no permission for group or others.
//! The node key is the Ed25519 secret, in the node's text format (unpadded
//! base32 of the 32 bytes, one line).
//! Seal keys are raw 32-byte X25519 secrets.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use serde::Deserialize;
use x25519_dalek::StaticSecret;
use zeroize::Zeroizing;

pub const DEFAULT_APNS_PRODUCTION_URL: &str = "https://api.push.apple.com";
pub const DEFAULT_APNS_SANDBOX_URL: &str = "https://api.sandbox.push.apple.com";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("configuration: {0}")]
    Config(String),
    #[error("{0}")]
    Key(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayConfig {
    /// QUIC listen addresses (`host:port`).
    #[serde(default = "default_listen")]
    pub listen: Vec<String>,
    /// Ed25519 identity of the relay (satisfies the node puzzle).
    pub node_key_file: PathBuf,
    /// X25519 keys clients seal tokens to; several allow rotation.
    pub seal_keys: Vec<SealKeyFile>,
    pub apns: ApnsConfig,
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    #[serde(default = "default_max_connections_per_ip")]
    pub max_connections_per_ip: u32,
    #[serde(default = "default_log_interval_secs")]
    pub log_interval_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealKeyFile {
    pub id: u8,
    pub file: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApnsConfig {
    pub team_id: String,
    pub key_id: String,
    /// Bundle identifier (`apns-topic`).
    pub topic: String,
    /// APNs authentication key (`.p8`).
    pub key_file: PathBuf,
    #[serde(default = "default_production_url")]
    pub production_url: String,
    #[serde(default = "default_sandbox_url")]
    pub sandbox_url: String,
}

fn default_listen() -> Vec<String> {
    vec!["[::]:4433".to_string()]
}
fn default_max_connections() -> u32 {
    10_000
}
fn default_max_connections_per_ip() -> u32 {
    16
}
fn default_log_interval_secs() -> u64 {
    60
}
fn default_production_url() -> String {
    DEFAULT_APNS_PRODUCTION_URL.to_string()
}
fn default_sandbox_url() -> String {
    DEFAULT_APNS_SANDBOX_URL.to_string()
}

impl RelayConfig {
    pub fn parse(text: &str) -> Result<RelayConfig> {
        let cfg: RelayConfig = toml::from_str(text).map_err(|e| Error::Config(e.to_string()))?;
        if cfg.listen.is_empty() {
            return Err(Error::Config("listen is empty".into()));
        }
        // Current key plus, during a rotation, the previous one.
        if cfg.seal_keys.is_empty() || cfg.seal_keys.len() > 2 {
            return Err(Error::Config("seal_keys must hold 1 or 2 keys".into()));
        }
        if cfg.seal_keys.len() == 2 && cfg.seal_keys[0].id == cfg.seal_keys[1].id {
            return Err(Error::Config("duplicate seal key id".into()));
        }
        if cfg.max_connections == 0 || cfg.max_connections_per_ip == 0 {
            return Err(Error::Config("connection limits must be positive".into()));
        }
        if cfg.log_interval_secs == 0 {
            return Err(Error::Config("log_interval_secs must be positive".into()));
        }
        Ok(cfg)
    }

    pub fn load(path: &Path) -> Result<RelayConfig> {
        let text = fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("{}: {e}", path.display())))?;
        Self::parse(&text)
    }
}

/// Reads a secret file after the checks of the node: regular file, mode
/// without group or other bits.
fn read_secret(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let meta =
        fs::symlink_metadata(path).map_err(|e| Error::Key(format!("{}: {e}", path.display())))?;
    if !meta.file_type().is_file() {
        return Err(Error::Key(format!(
            "{} must be a regular file (neither a symbolic link nor another type)",
            path.display()
        )));
    }
    if meta.permissions().mode() & 0o077 != 0 {
        return Err(Error::Key(format!(
            "{} must have mode 0600 (readable by other users)",
            path.display()
        )));
    }
    Ok(Zeroizing::new(fs::read(path)?))
}

/// Loads the node identity key.
pub fn load_node_key(path: &Path) -> Result<SigningKey> {
    let bytes = read_secret(path)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| Error::Key("node key unreadable".into()))?;
    let decoded = Zeroizing::new(
        data_encoding::BASE32_NOPAD
            .decode(text.trim().as_bytes())
            .map_err(|_| Error::Key("node key unreadable".into()))?,
    );
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(
        decoded
            .as_slice()
            .try_into()
            .map_err(|_| Error::Key("node key has the wrong size".into()))?,
    );
    Ok(SigningKey::from_bytes(&seed))
}

/// Loads the APNs authentication key (`.p8`, PKCS#8 PEM, ES256).
pub fn load_apns_key(path: &Path) -> Result<p256::ecdsa::SigningKey> {
    use p256::pkcs8::DecodePrivateKey;
    let bytes = read_secret(path)?;
    let pem = std::str::from_utf8(&bytes).map_err(|_| Error::Key("APNs key unreadable".into()))?;
    p256::ecdsa::SigningKey::from_pkcs8_pem(pem)
        .map_err(|_| Error::Key("APNs key unreadable".into()))
}

/// Loads the seal keys; ids must be distinct.
pub fn load_seal_keys(files: &[SealKeyFile]) -> Result<Vec<(u8, StaticSecret)>> {
    let mut out: Vec<(u8, StaticSecret)> = Vec::with_capacity(files.len());
    for f in files {
        if out.iter().any(|(id, _)| *id == f.id) {
            return Err(Error::Config(format!("duplicate seal key id {}", f.id)));
        }
        let bytes = read_secret(&f.file)?;
        let raw: Zeroizing<[u8; 32]> = Zeroizing::new(
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| Error::Key("seal key must be 32 raw bytes".into()))?,
        );
        out.push((f.id, StaticSecret::from(*raw)));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{OpenOptionsExt, symlink};

    use super::*;

    const MINIMAL: &str = r#"
node_key_file = "/etc/barking-push/node.key"
seal_keys = [{ id = 1, file = "/etc/barking-push/seal1.key" }]

[apns]
team_id = "TEAM"
key_id = "KEY"
topic = "fr.example.barking"
key_file = "/etc/barking-push/apns.p8"
"#;

    #[test]
    fn config_parses_and_rejects_unknown_fields() {
        let cfg = RelayConfig::parse(MINIMAL).unwrap();
        assert_eq!(cfg.listen, vec!["[::]:4433".to_string()]);
        assert_eq!(cfg.max_connections, 10_000);
        assert_eq!(cfg.max_connections_per_ip, 16);
        assert_eq!(cfg.log_interval_secs, 60);
        assert_eq!(
            cfg.seal_keys,
            vec![SealKeyFile {
                id: 1,
                file: "/etc/barking-push/seal1.key".into()
            }]
        );
        assert_eq!(cfg.apns.production_url, "https://api.push.apple.com");
        assert_eq!(cfg.apns.sandbox_url, "https://api.sandbox.push.apple.com");

        assert!(RelayConfig::parse(&format!("bogus = 1\n{MINIMAL}")).is_err());
        let nested = MINIMAL.replace("topic =", "extra = 1\ntopic =");
        assert!(RelayConfig::parse(&nested).is_err());
        let seal = MINIMAL.replace("id = 1,", "id = 1, mode = 2,");
        assert!(RelayConfig::parse(&seal).is_err());
        assert!(RelayConfig::parse("listen = []\n").is_err());
        let none = MINIMAL.replace(
            "seal_keys = [{ id = 1, file = \"/etc/barking-push/seal1.key\" }]",
            "seal_keys = []",
        );
        assert!(RelayConfig::parse(&none).is_err());
        let two = MINIMAL.replace("}]", "}, { id = 2, file = \"/b\" }]");
        assert!(RelayConfig::parse(&two).is_ok());
        let dup = MINIMAL.replace("}]", "}, { id = 1, file = \"/b\" }]");
        assert!(RelayConfig::parse(&dup).is_err());
        let three = MINIMAL.replace(
            "}]",
            "}, { id = 2, file = \"/b\" }, { id = 3, file = \"/c\" }]",
        );
        assert!(RelayConfig::parse(&three).is_err());
    }

    fn write(path: &Path, bytes: &[u8], mode: u32) {
        use std::io::Write;
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(path)
            .unwrap();
        f.write_all(bytes).unwrap();
    }

    #[test]
    fn key_files_are_checked() {
        let dir = tempfile::tempdir().unwrap();
        let seed = [9u8; 32];
        let expected = SigningKey::from_bytes(&seed).to_bytes();

        let b32 = dir.path().join("b32.key");
        write(
            &b32,
            format!("{}\n", data_encoding::BASE32_NOPAD.encode(&seed)).as_bytes(),
            0o600,
        );
        assert_eq!(load_node_key(&b32).unwrap().to_bytes(), expected);

        // Raw bytes are not the node format.
        let raw = dir.path().join("raw.key");
        write(&raw, &seed, 0o600);
        assert!(load_node_key(&raw).is_err());

        let open = dir.path().join("open.key");
        write(&open, &seed, 0o644);
        assert!(load_node_key(&open).is_err());

        let link = dir.path().join("link.key");
        symlink(&raw, &link).unwrap();
        assert!(load_node_key(&link).is_err());

        let short = dir.path().join("short.key");
        write(&short, &[1u8; 5], 0o600);
        assert!(load_node_key(&short).is_err());
        assert!(load_seal_keys(&[SealKeyFile { id: 1, file: short }]).is_err());

        let files = [
            SealKeyFile {
                id: 1,
                file: raw.clone(),
            },
            SealKeyFile {
                id: 1,
                file: raw.clone(),
            },
        ];
        assert!(load_seal_keys(&files).is_err());
        let keys = load_seal_keys(&files[..1]).unwrap();
        assert_eq!(keys[0].0, 1);
    }
}
