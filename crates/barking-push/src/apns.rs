//! APNs HTTP/2 client: one alert push per wake token, authenticated with a
//! cached ES256 provider token.
//!
//! Nothing here logs a device token, a collapse label or an APNs reason.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use barking_proto::push::{ApnsEnv, WakeToken};
use data_encoding::HEXLOWER;
use p256::ecdsa::SigningKey;

use crate::config::{ApnsConfig, Error, Result};
use crate::jwt::apns_jwt;
use crate::server::{PushOutcome, Pusher};

/// Exact notification payload (also what the client's extension expects).
const BODY: &str =
    r#"{"aps":{"alert":{"loc-key":"NEW_MESSAGE"},"mutable-content":1,"sound":"default"}}"#;
/// Apple asks for a provider token refresh at most every 60 min and at
/// least every 60 min before expiry: renew after 50 min.
const JWT_LIFETIME_SECS: u64 = 50 * 60;
/// APNs drops the notification if the device stays offline this long.
const EXPIRATION_SECS: u64 = 3600;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

struct CachedJwt {
    jwt: String,
    iat: u64,
}

pub struct ApnsPusher {
    client: reqwest::Client,
    team_id: String,
    key_id: String,
    topic: String,
    key: SigningKey,
    production_url: String,
    sandbox_url: String,
    clock: Clock,
    jwt: Mutex<Option<CachedJwt>>,
}

fn system_clock() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl ApnsPusher {
    /// Production constructor: HTTPS only, system clock.
    pub fn new(cfg: &ApnsConfig, key: SigningKey) -> Result<ApnsPusher> {
        Self::new_with_clock(cfg, key, system_clock)
    }

    /// Like [`new`](Self::new) with an injectable seconds-since-epoch clock
    /// (JWT `iat`, token age and notification expiry).
    pub fn new_with_clock(
        cfg: &ApnsConfig,
        key: SigningKey,
        clock: impl Fn() -> u64 + Send + Sync + 'static,
    ) -> Result<ApnsPusher> {
        for url in [&cfg.production_url, &cfg.sandbox_url] {
            if !url.starts_with("https://") {
                return Err(Error::Config("APNs URLs must use https".into()));
            }
        }
        let client = base_client()
            .https_only(true)
            .build()
            .map_err(|_| Error::Config("cannot build the APNs HTTP client".into()))?;
        Ok(Self::assemble(cfg, key, client, Arc::new(clock)))
    }

    /// Test constructor: cleartext HTTP/2 with prior knowledge (a fake APNs
    /// on localhost). Not reachable from the binary.
    #[cfg(any(test, feature = "test-apns"))]
    pub fn new_insecure_for_tests(
        cfg: &ApnsConfig,
        key: SigningKey,
        clock: impl Fn() -> u64 + Send + Sync + 'static,
    ) -> Result<ApnsPusher> {
        let client = base_client()
            .http2_prior_knowledge()
            .build()
            .map_err(|_| Error::Config("cannot build the APNs HTTP client".into()))?;
        Ok(Self::assemble(cfg, key, client, Arc::new(clock)))
    }

    fn assemble(cfg: &ApnsConfig, key: SigningKey, client: reqwest::Client, clock: Clock) -> Self {
        ApnsPusher {
            client,
            team_id: cfg.team_id.clone(),
            key_id: cfg.key_id.clone(),
            topic: cfg.topic.clone(),
            key,
            production_url: cfg.production_url.trim_end_matches('/').to_string(),
            sandbox_url: cfg.sandbox_url.trim_end_matches('/').to_string(),
            clock,
            jwt: Mutex::new(None),
        }
    }

    /// Cached provider token with its `iat`, renewed after 50 min, or when
    /// it is the one APNs just rejected (`rejected_iat`). A token already
    /// replaced by a concurrent push is reused: one renewal per rejection.
    fn bearer(&self, rejected_iat: Option<u64>) -> (String, u64) {
        let now = (self.clock)();
        let mut slot = self.jwt.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(c) = slot.as_ref()
            && rejected_iat != Some(c.iat)
            && now.saturating_sub(c.iat) < JWT_LIFETIME_SECS
        {
            return (c.jwt.clone(), c.iat);
        }
        let jwt = apns_jwt(&self.team_id, &self.key_id, &self.key, now);
        *slot = Some(CachedJwt {
            jwt: jwt.clone(),
            iat: now,
        });
        (jwt, now)
    }

    /// One request; the second value is the `iat` of the provider token if
    /// APNs rejected it as expired.
    async fn send(
        &self,
        token: &WakeToken,
        rejected_iat: Option<u64>,
    ) -> (PushOutcome, Option<u64>) {
        let base = match token.env {
            ApnsEnv::Production => &self.production_url,
            ApnsEnv::Sandbox => &self.sandbox_url,
        };
        let url = format!("{base}/3/device/{}", HEXLOWER.encode(&token.apns_token));
        let (jwt, iat) = self.bearer(rejected_iat);
        let resp = self
            .client
            .post(url)
            .header("authorization", format!("bearer {jwt}"))
            .header("apns-topic", &self.topic)
            .header("apns-push-type", "alert")
            .header("apns-priority", "10")
            .header(
                "apns-expiration",
                ((self.clock)() + EXPIRATION_SECS).to_string(),
            )
            .header("apns-collapse-id", HEXLOWER.encode(&token.collapse))
            .header("content-type", "application/json")
            .body(BODY)
            .send()
            .await;
        let resp = match resp {
            Ok(r) => r,
            Err(_) => return (PushOutcome::Failed(0), None),
        };
        let code = resp.status().as_u16();
        match code {
            200 => (PushOutcome::Sent, None),
            410 => (PushOutcome::Unregistered, None),
            403 => {
                let expired = resp
                    .bytes()
                    .await
                    .is_ok_and(|b| b.len() < 4096 && contains(&b, b"ExpiredProviderToken"));
                (PushOutcome::Failed(403), expired.then_some(iat))
            }
            other => (PushOutcome::Failed(other), None),
        }
    }
}

/// Fails if the host trust store holds no root certificate: reqwest verifies
/// Apple's certificate through it, and every push would fail otherwise.
pub fn verify_trust_store() -> Result<()> {
    check_root_count(rustls_native_certs::load_native_certs().certs.len())
}

fn check_root_count(count: usize) -> Result<()> {
    if count == 0 {
        return Err(Error::Config(
            "the host trust store has no root certificates, APNs TLS cannot be verified \
             (install ca-certificates, or set SSL_CERT_FILE / SSL_CERT_DIR)"
                .into(),
        ));
    }
    Ok(())
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Installs the `ring` rustls provider as the process default (reqwest is
/// built without a provider so that aws-lc never enters the build). Safe to
/// call more than once.
pub fn install_crypto_provider() {
    // Err means a provider is already installed: nothing to do.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn base_client() -> reqwest::ClientBuilder {
    install_crypto_provider();
    reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .connect_timeout(CONNECT_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
}

impl Pusher for ApnsPusher {
    async fn push(&self, token: WakeToken) -> PushOutcome {
        let (outcome, rejected) = self.send(&token, None).await;
        if rejected.is_some() {
            // Renew the provider token and retry once.
            return self.send(&token, rejected).await.0;
        }
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_trust_store_is_refused() {
        assert!(check_root_count(0).is_err());
        assert!(check_root_count(1).is_ok());
    }
}
