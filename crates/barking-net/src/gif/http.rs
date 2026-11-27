//! HTTPS for the GIF providers: the transport trait, the reqwest
//! implementation and the mapping of HTTP replies to [`GifError`].

use std::sync::Arc;
use std::time::Duration;

use url::Url;

use super::{GifError, providers, url_allowed};

/// `User-Agent` of every GIF request: the same for every install, no
/// version, no identifier.
pub const USER_AGENT: &str = "Barking";
/// Whole-request delay.
pub const TIMEOUT: Duration = Duration::from_secs(15);
/// Wait before retrying after a `429` that gives no usable `Retry-After`.
pub const DEFAULT_RETRY_AFTER_SECS: u32 = 60;
/// Longest wait taken from a `Retry-After`.
pub const MAX_RETRY_AFTER_SECS: u32 = 3600;

/// Fetches a URL for a GIF provider. Used through generics
/// (`t: &impl GifTransport`).
pub trait GifTransport: Send + Sync {
    /// `GET url`, body of at most `max_bytes` bytes.
    fn get(
        &self,
        url: &Url,
        max_bytes: usize,
    ) -> impl Future<Output = Result<Vec<u8>, GifError>> + Send;
}

/// What the transport keeps of an HTTP response.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HttpReply {
    pub status: u16,
    /// Raw `Retry-After` header, if any.
    pub retry_after: Option<String>,
    pub body: Vec<u8>,
}

/// Maps a reply to its body or to the error the interface shows.
///
/// Beyond `404`, `429` and `5xx`: `401`/`403` mean the app's key is refused
/// (`NotConfigured`, retrying will not help), another `4xx` or a `2xx` other
/// than `200` a request or reply this client does not understand
/// (`Malformed`), a `3xx` (redirects are never followed) or `1xx`
/// `Unreachable`. These are the API host's meanings: on a media host,
/// [`super::data`] reads `401`, `403` and `404` alike as `NotFound` (the
/// file is gone or refused, the key is not in that request).
pub fn map_reply(reply: HttpReply) -> Result<Vec<u8>, GifError> {
    match reply.status {
        200 => Ok(reply.body),
        404 => Err(GifError::NotFound),
        429 => Err(GifError::RateLimited {
            retry_after_secs: reply
                .retry_after
                .as_deref()
                .map_or(DEFAULT_RETRY_AFTER_SECS, retry_after_secs),
        }),
        401 | 403 => Err(GifError::NotConfigured),
        201..=299 | 400..=499 => Err(GifError::Malformed),
        _ => Err(GifError::Unreachable),
    }
}

/// Seconds to wait from a `Retry-After` value: delay-seconds clamped to
/// [`MAX_RETRY_AFTER_SECS`], an all-digit value too large for any integer
/// included; a date or anything else gives [`DEFAULT_RETRY_AFTER_SECS`].
fn retry_after_secs(value: &str) -> u32 {
    let v = value.trim();
    if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
        return DEFAULT_RETRY_AFTER_SECS;
    }
    v.parse::<u64>()
        .ok()
        .and_then(|s| u32::try_from(s).ok())
        .map_or(MAX_RETRY_AFTER_SECS, |s| s.min(MAX_RETRY_AFTER_SECS))
}

/// Whether the transport may contact `url`: HTTPS on port 443 to a host of
/// a known provider. Checked before any connection.
pub(crate) fn transport_allows(url: &Url) -> bool {
    providers().iter().any(|p| url_allowed(*p, url))
}

/// Body accumulator refusing more than `max` bytes.
pub(crate) struct CappedBody {
    buf: Vec<u8>,
    max: usize,
}

impl CappedBody {
    pub(crate) fn new(max: usize) -> Self {
        Self {
            buf: Vec::new(),
            max,
        }
    }

    pub(crate) fn push(&mut self, chunk: &[u8]) -> Result<(), GifError> {
        if chunk.len() > self.max - self.buf.len() {
            return Err(GifError::TooLarge);
        }
        self.buf.extend_from_slice(chunk);
        Ok(())
    }

    pub(crate) fn into_inner(self) -> Vec<u8> {
        self.buf
    }
}

/// reqwest over rustls (`ring`, webpki roots), HTTP/1.1, no cookie, no
/// redirect, no proxy.
pub struct HttpsTransport {
    client: reqwest::Client,
}

impl HttpsTransport {
    /// # Errors
    /// `Unreachable` if the HTTP client cannot be built.
    pub fn new() -> Result<Self, GifError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let mut tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| GifError::Unreachable)?
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        let client = reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .http1_only()
            .https_only(true)
            .user_agent(USER_AGENT)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(TIMEOUT)
            .build()
            .map_err(|_| GifError::Unreachable)?;
        Ok(Self { client })
    }
}

impl GifTransport for HttpsTransport {
    // Neither the URL (it holds the key) nor a reqwest error (its text
    // holds the URL) is ever logged or returned.
    async fn get(&self, url: &Url, max_bytes: usize) -> Result<Vec<u8>, GifError> {
        if !transport_allows(url) {
            return Err(GifError::Malformed);
        }
        let mut resp = self
            .client
            .get(url.clone())
            .send()
            .await
            .map_err(|e| classify_error(&e))?;
        let status = resp.status().as_u16();
        if status != 200 {
            let retry_after = resp
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .map(String::from);
            return map_reply(HttpReply {
                status,
                retry_after,
                body: Vec::new(),
            });
        }
        if resp.content_length().is_some_and(|n| n > max_bytes as u64) {
            return Err(GifError::TooLarge);
        }
        let mut body = CappedBody::new(max_bytes);
        while let Some(chunk) = resp.chunk().await.map_err(|e| classify_error(&e))? {
            body.push(&chunk)?;
        }
        map_reply(HttpReply {
            status,
            retry_after: None,
            body: body.into_inner(),
        })
    }
}

/// Classifies a failed request: no network at all is `Offline`, anything
/// else (DNS, refused, TLS, timeout) `Unreachable`.
pub(crate) fn classify_error(err: &(dyn std::error::Error + 'static)) -> GifError {
    use std::io::ErrorKind;
    let mut cur = Some(err);
    while let Some(e) = cur {
        if let Some(io) = e.downcast_ref::<std::io::Error>()
            && matches!(
                io.kind(),
                ErrorKind::NetworkUnreachable | ErrorKind::NetworkDown
            )
        {
            return GifError::Offline;
        }
        cur = e.source();
    }
    GifError::Unreachable
}

#[cfg(test)]
pub(crate) mod fake {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use super::*;

    /// Transport serving queued replies and counting calls.
    #[derive(Default)]
    pub(crate) struct FakeTransport {
        replies: Mutex<VecDeque<HttpReply>>,
        urls: Mutex<Vec<Url>>,
    }

    impl FakeTransport {
        pub(crate) fn new(replies: impl IntoIterator<Item = HttpReply>) -> Self {
            Self {
                replies: Mutex::new(replies.into_iter().collect()),
                urls: Mutex::default(),
            }
        }

        pub(crate) fn calls(&self) -> usize {
            self.urls.lock().unwrap().len()
        }

        pub(crate) fn urls(&self) -> Vec<Url> {
            self.urls.lock().unwrap().clone()
        }
    }

    impl HttpReply {
        pub(crate) fn ok(body: impl Into<Vec<u8>>) -> Self {
            Self {
                status: 200,
                retry_after: None,
                body: body.into(),
            }
        }

        pub(crate) fn status(status: u16) -> Self {
            Self {
                status,
                retry_after: None,
                body: Vec::new(),
            }
        }
    }

    impl GifTransport for FakeTransport {
        async fn get(&self, url: &Url, max_bytes: usize) -> Result<Vec<u8>, GifError> {
            self.urls.lock().unwrap().push(url.clone());
            if !transport_allows(url) {
                return Err(GifError::Malformed);
            }
            let reply = self
                .replies
                .lock()
                .unwrap()
                .pop_front()
                .ok_or(GifError::Unreachable)?;
            if reply.body.len() > max_bytes {
                return Err(GifError::TooLarge);
            }
            map_reply(reply)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::FakeTransport;
    use super::*;
    use crate::gif::{MAX_GIF_BYTES, klipy};

    fn rate_limited(retry_after: Option<&str>) -> HttpReply {
        HttpReply {
            status: 429,
            retry_after: retry_after.map(String::from),
            body: Vec::new(),
        }
    }

    #[tokio::test]
    async fn klipy_429_maps_to_rate_limited() {
        let t = FakeTransport::new([
            rate_limited(Some("30")),
            rate_limited(None),
            rate_limited(Some("Wed, 21 Oct 2026 07:28:00 GMT")),
            rate_limited(Some("999999")),
            rate_limited(Some("99999999999999999999")),
            rate_limited(Some("3600")),
        ]);
        let url = klipy().search_url("KEY", "hello", 1);
        let expect = |secs| {
            Err(GifError::RateLimited {
                retry_after_secs: secs,
            })
        };
        assert_eq!(t.get(&url, MAX_GIF_BYTES).await, expect(30));
        assert_eq!(t.get(&url, MAX_GIF_BYTES).await, expect(60));
        assert_eq!(t.get(&url, MAX_GIF_BYTES).await, expect(60));
        // Clamped to an hour, however large, beyond any integer included.
        assert_eq!(t.get(&url, MAX_GIF_BYTES).await, expect(3600));
        assert_eq!(t.get(&url, MAX_GIF_BYTES).await, expect(3600));
        assert_eq!(t.get(&url, MAX_GIF_BYTES).await, expect(3600));
        assert_eq!(t.calls(), 6);
        assert_eq!(t.urls()[0], url);
    }

    #[test]
    fn status_mapping() {
        assert_eq!(map_reply(HttpReply::ok("body")), Ok(b"body".to_vec()));
        for (status, err) in [
            (404, GifError::NotFound),
            (500, GifError::Unreachable),
            (502, GifError::Unreachable),
            (503, GifError::Unreachable),
            (401, GifError::NotConfigured),
            (403, GifError::NotConfigured),
            (400, GifError::Malformed),
            (410, GifError::Malformed),
            (301, GifError::Unreachable),
            (302, GifError::Unreachable),
            (204, GifError::Malformed),
        ] {
            assert_eq!(map_reply(HttpReply::status(status)), Err(err), "{status}");
        }
    }

    #[tokio::test]
    async fn https_transport_refuses_non_443_and_http() {
        let t = HttpsTransport::new().expect("client builds without network");
        for url in [
            "http://api.klipy.com/api/v1/KEY/gifs/search",
            "https://api.klipy.com:8443/api/v1/KEY/gifs/search",
            "https://api.klipy.com:80/api/v1/KEY/gifs/search",
            "https://user:pw@api.klipy.com/api/v1/KEY/gifs/search",
            "https://example.com/",
            "https://api.klipy.com.example.com/",
            "https://93.184.216.34/",
            "ftp://api.klipy.com/",
        ] {
            let url = Url::parse(url).unwrap();
            // Refused before any connection: no network needed, instant.
            assert_eq!(
                t.get(&url, MAX_GIF_BYTES).await,
                Err(GifError::Malformed),
                "{url}"
            );
        }
    }

    #[test]
    fn capped_body_refuses_more_than_max() {
        let chunk = vec![0u8; 1024 * 1024];
        let mut body = CappedBody::new(MAX_GIF_BYTES);
        for _ in 0..8 {
            body.push(&chunk).unwrap();
        }
        // 9 MiB in all: refused, and nothing beyond the cap is kept.
        assert_eq!(body.push(&chunk), Err(GifError::TooLarge));
        assert!(body.into_inner().len() <= MAX_GIF_BYTES);
        let mut exact = CappedBody::new(MAX_GIF_BYTES);
        exact.push(&vec![0u8; MAX_GIF_BYTES]).unwrap();
        assert_eq!(exact.push(&[0]), Err(GifError::TooLarge));
    }

    #[derive(Debug)]
    struct Wrapped(std::io::Error);

    impl std::fmt::Display for Wrapped {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("connect")
        }
    }

    impl std::error::Error for Wrapped {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.0)
        }
    }

    #[test]
    fn no_network_is_offline() {
        use std::io::{Error, ErrorKind};
        for kind in [ErrorKind::NetworkUnreachable, ErrorKind::NetworkDown] {
            assert_eq!(
                classify_error(&Wrapped(Error::from(kind))),
                GifError::Offline
            );
        }
        for kind in [ErrorKind::ConnectionRefused, ErrorKind::TimedOut] {
            assert_eq!(
                classify_error(&Wrapped(Error::from(kind))),
                GifError::Unreachable
            );
        }
    }

    #[tokio::test]
    async fn fake_transport_without_reply_is_unreachable() {
        let t = FakeTransport::default();
        let url = klipy().trending_url("KEY", 1);
        assert_eq!(t.get(&url, MAX_GIF_BYTES).await, Err(GifError::Unreachable));
        assert_eq!(t.calls(), 1);
    }
}
