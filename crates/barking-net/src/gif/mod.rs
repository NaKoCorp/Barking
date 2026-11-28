//! GIF providers: search, trending and resolution of a received GIF.
//!
//! Everything specific to a provider sits behind [`GifProvider`]; the HTTPS
//! requests go through [`GifTransport`]. Nothing here is cached: responses,
//! URLs and media only live for the call that fetched them.

pub mod http;
pub mod klipy;
pub mod provider;

pub use barking_core::core::GifUse;
use barking_core::gif::GifProviderId;
use url::Url;

pub use http::{GifTransport, HttpsTransport};
pub use klipy::klipy;
pub use provider::GifProvider;

/// Largest response or media accepted, in bytes.
pub const MAX_GIF_BYTES: usize = 8 * 1024 * 1024;

/// One page of search or trending results.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct GifPage {
    pub results: Vec<GifResult>,
    /// Number of the next page, if the provider has one.
    pub next: Option<u32>,
}

/// One result in a page.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct GifResult {
    /// Provider number (`GifProviderId::as_u8`).
    pub provider: u8,
    /// Identifier at the provider, the only part sent in a message with
    /// the provider and the size.
    pub id: String,
    /// Size of the rendition a received GIF is resolved to.
    pub width: u16,
    pub height: u16,
    pub title: String,
    /// Small rendition for the picker grid only, never kept.
    pub preview_mp4: Url,
}

/// A GIF resolved from its identifier.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct GifItem {
    /// Identifier of the entry the provider answered with.
    pub id: String,
    pub mp4: Url,
    pub width: u16,
    pub height: u16,
    pub title: String,
    /// Name of the author, when the provider gives one (attribution).
    pub author: Option<String>,
}

/// Why a GIF call failed, distinct so the interface can say the right thing.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum GifError {
    #[error("GIFs are not enabled for this provider")]
    NotEnabled,
    #[error("no key for this GIF provider")]
    NotConfigured,
    #[error("offline")]
    Offline,
    #[error("GIF provider unreachable")]
    Unreachable,
    #[error("GIF provider rate limit, retry in {retry_after_secs} s")]
    RateLimited { retry_after_secs: u32 },
    #[error("GIF not found")]
    NotFound,
    #[error("GIF response too large")]
    TooLarge,
    #[error("malformed GIF response")]
    Malformed,
}

/// Every provider this client knows.
#[must_use]
pub fn providers() -> [&'static dyn GifProvider; 1] {
    [klipy()]
}

/// Whether `url` may be fetched for `provider`: HTTPS on port 443, no
/// credentials, host exactly one of the provider's hosts.
#[must_use]
pub fn url_allowed(provider: &dyn GifProvider, url: &Url) -> bool {
    url.scheme() == "https"
        && url.port_or_known_default() == Some(443)
        && url.username().is_empty()
        && url.password().is_none()
        && matches!(url.host(), Some(url::Host::Domain(h)) if provider.hosts().contains(&h))
}

/// Whether `url` may be fetched as a picker preview: as [`url_allowed`],
/// with the host one of the provider's media hosts, never its API host.
#[must_use]
pub fn media_url_allowed(provider: &dyn GifProvider, url: &Url) -> bool {
    url_allowed(provider, url)
        && matches!(url.host(), Some(url::Host::Domain(h)) if provider.media_hosts().contains(&h))
}

/// The provider used for search and trending.
pub const ACTIVE_GIF_PROVIDER: GifProviderId = GifProviderId::Klipy;

/// The app's key for each provider, handed to the core at startup.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct GifKeys {
    pub klipy: Option<String>,
}

// Never prints a key.
impl std::fmt::Debug for GifKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GifKeys")
            .field("klipy", &self.klipy.as_ref().map(|_| "<set>"))
            .finish()
    }
}

/// A received GIF, fetched for display and kept nowhere.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct GifMedia {
    pub mp4: Vec<u8>,
    pub author: Option<String>,
    pub title: String,
}

/// Consent and usage counters, as the caller keeps them. Asked for each
/// check and each count, never held across a request: the FFI answers each
/// by opening the core briefly, so a request (up to [`http::TIMEOUT`]) never
/// keeps the core from other calls.
pub trait GifGate {
    /// Whether this client may contact `provider` now. A caller that cannot
    /// tell answers `false`.
    fn allowed(&self, provider: u8) -> bool;
    /// Counts one use, once the call succeeded. A count that cannot be
    /// written never fails the call.
    fn record(&self, use_: GifUse);
}

fn provider_of(id: GifProviderId) -> &'static dyn GifProvider {
    match id {
        GifProviderId::Klipy => klipy(),
    }
}

/// Consent, then key: the provider's key if this client may contact it
/// now. Asked again before every request.
fn gate(g: &impl GifGate, keys: &GifKeys, id: GifProviderId) -> Result<String, GifError> {
    if !g.allowed(id.as_u8()) {
        return Err(GifError::NotEnabled);
    }
    let key = match id {
        GifProviderId::Klipy => keys.klipy.as_ref(),
    };
    key.filter(|k| !k.is_empty())
        .cloned()
        .ok_or(GifError::NotConfigured)
}

/// One page of search results. Counts a search once it succeeded.
///
/// # Errors
/// `NotEnabled` without consent (nothing is sent), `NotConfigured` without
/// a key, otherwise what the transport or the provider's reply gives.
pub async fn search(
    g: &impl GifGate,
    keys: &GifKeys,
    t: &impl GifTransport,
    query: &str,
    page: u32,
) -> Result<GifPage, GifError> {
    let provider = provider_of(ACTIVE_GIF_PROVIDER);
    let key = gate(g, keys, ACTIVE_GIF_PROVIDER)?;
    let body = t
        .get(&provider.search_url(&key, query, page), MAX_GIF_BYTES)
        .await?;
    let page = provider.parse_page(&body)?;
    g.record(GifUse::Search);
    Ok(page)
}

/// One page of trending GIFs. Counted as a search once it succeeded, so
/// Transparency's count of calls to the provider is exact.
///
/// # Errors
/// As [`search`].
pub async fn trending(
    g: &impl GifGate,
    keys: &GifKeys,
    t: &impl GifTransport,
    page: u32,
) -> Result<GifPage, GifError> {
    let provider = provider_of(ACTIVE_GIF_PROVIDER);
    let key = gate(g, keys, ACTIVE_GIF_PROVIDER)?;
    let body = t
        .get(&provider.trending_url(&key, page), MAX_GIF_BYTES)
        .await?;
    let page = provider.parse_page(&body)?;
    g.record(GifUse::Search);
    Ok(page)
}

/// Resolves the GIF `id` of `provider` and downloads its MP4. Consent is
/// checked again before the download. Counts a GIF shown on success.
///
/// # Errors
/// `NotFound` for an unknown provider or a malformed identifier (nothing
/// is sent), and for a media host that refuses or no longer serves the GIF
/// (`401`, `403`, `404`: on a media host this means the file is gone, not
/// that the app's key is wrong); `Malformed` if the provider answers with
/// another entry; `NotEnabled` if consent was withdrawn during the
/// resolution (the MP4 is then never requested); else as [`search`].
pub async fn data(
    g: &impl GifGate,
    keys: &GifKeys,
    t: &impl GifTransport,
    provider: u8,
    id: &str,
) -> Result<GifMedia, GifError> {
    let pid = GifProviderId::from_u8(provider).ok_or(GifError::NotFound)?;
    let p = provider_of(pid);
    if !p.validate_id(id) {
        return Err(GifError::NotFound);
    }
    let key = gate(g, keys, pid)?;
    let body = t.get(&p.resolve_url(&key, id), MAX_GIF_BYTES).await?;
    let item = p.parse_item(&body)?;
    if item.id != id {
        return Err(GifError::Malformed);
    }
    // Consent may have been withdrawn while the first request was running.
    gate(g, keys, pid)?;
    let mp4 = t.get(&item.mp4, MAX_GIF_BYTES).await.map_err(|e| match e {
        // `401`/`403` from the media host: the file is refused, not the key.
        GifError::NotConfigured => GifError::NotFound,
        e => e,
    })?;
    g.record(GifUse::Shown);
    Ok(GifMedia {
        mp4,
        author: item.author,
        title: item.title,
    })
}

/// Fetches a picker preview (`GifResult::preview_mp4`, given back as a
/// string by the app) from the active provider. Consent is checked right
/// before the request; the URL must be on one of the provider's media
/// hosts, HTTPS on 443 ([`media_url_allowed`]), and is used as given. Counts a preview on
/// success. No key is needed: media hosts are public.
///
/// # Errors
/// `NotEnabled` without consent and `Malformed` for a URL this client may
/// not fetch (nothing is sent in either case); `NotFound` for a preview
/// the media host refuses or no longer serves; else what the transport
/// gives.
pub async fn preview(
    g: &impl GifGate,
    t: &impl GifTransport,
    url: &str,
) -> Result<Vec<u8>, GifError> {
    let provider = provider_of(ACTIVE_GIF_PROVIDER);
    let url = Url::parse(url).map_err(|_| GifError::Malformed)?;
    if !media_url_allowed(provider, &url) {
        return Err(GifError::Malformed);
    }
    if !g.allowed(ACTIVE_GIF_PROVIDER.as_u8()) {
        return Err(GifError::NotEnabled);
    }
    let mp4 = t.get(&url, MAX_GIF_BYTES).await.map_err(|e| match e {
        GifError::NotConfigured => GifError::NotFound,
        e => e,
    })?;
    g.record(GifUse::Preview);
    Ok(mp4)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::http::HttpReply;
    use super::http::fake::FakeTransport;
    use super::*;

    const SEARCH: &[u8] = include_bytes!("../../tests/fixtures/klipy/search.json");
    const TRENDING: &[u8] = include_bytes!("../../tests/fixtures/klipy/trending.json");
    const ITEMS: &[u8] = include_bytes!("../../tests/fixtures/klipy/items.json");
    const SLUG: &str = "hello-hi-662";

    /// Consent answered by a script: `true` for the first `allow` checks,
    /// then `false` (`usize::MAX`: always). Records the checks and uses.
    struct FakeGate {
        allow: usize,
        checks: AtomicUsize,
        uses: Mutex<Vec<GifUse>>,
    }

    impl FakeGate {
        fn new(allow: usize) -> Self {
            Self {
                allow,
                checks: AtomicUsize::new(0),
                uses: Mutex::default(),
            }
        }

        fn on() -> Self {
            Self::new(usize::MAX)
        }

        fn off() -> Self {
            Self::new(0)
        }

        fn uses(&self) -> Vec<GifUse> {
            self.uses.lock().unwrap().clone()
        }

        fn checks(&self) -> usize {
            self.checks.load(Ordering::SeqCst)
        }
    }

    impl GifGate for FakeGate {
        fn allowed(&self, provider: u8) -> bool {
            assert_eq!(provider, 1);
            self.checks.fetch_add(1, Ordering::SeqCst) < self.allow
        }

        fn record(&self, use_: GifUse) {
            self.uses.lock().unwrap().push(use_);
        }
    }

    fn keys() -> GifKeys {
        GifKeys {
            klipy: Some("KEY".into()),
        }
    }

    #[tokio::test]
    async fn gif_calls_refused_without_consent() {
        let g = FakeGate::off();
        let t = FakeTransport::new([HttpReply::ok(SEARCH), HttpReply::ok(ITEMS)]);
        assert_eq!(
            search(&g, &keys(), &t, "hi", 1).await.err(),
            Some(GifError::NotEnabled)
        );
        assert_eq!(
            trending(&g, &keys(), &t, 1).await.err(),
            Some(GifError::NotEnabled)
        );
        assert_eq!(
            data(&g, &keys(), &t, 1, SLUG).await.err(),
            Some(GifError::NotEnabled)
        );
        assert_eq!(t.calls(), 0);
        assert!(g.uses().is_empty());
    }

    /// The gate is asked again for every call: an answer that turns to no
    /// stops the next call before any request.
    #[tokio::test]
    async fn gif_disable_between_calls_blocks_next_call() {
        let g = FakeGate::new(1);
        let t = FakeTransport::new([HttpReply::ok(SEARCH), HttpReply::ok(SEARCH)]);
        search(&g, &keys(), &t, "hi", 1).await.unwrap();
        assert_eq!(
            search(&g, &keys(), &t, "hi", 1).await.err(),
            Some(GifError::NotEnabled)
        );
        assert_eq!(t.calls(), 1);
        assert_eq!(g.checks(), 2);
    }

    /// Consent withdrawn while the resolution was running: the MP4 is never
    /// requested, nothing is counted.
    #[tokio::test]
    async fn gif_data_consent_withdrawn_before_download_is_not_enabled() {
        let g = FakeGate::new(1);
        let t = FakeTransport::new([HttpReply::ok(ITEMS), HttpReply::ok("MP4")]);
        assert_eq!(
            data(&g, &keys(), &t, 1, SLUG).await.err(),
            Some(GifError::NotEnabled)
        );
        assert_eq!(t.calls(), 1);
        assert_eq!(g.checks(), 2);
        assert!(g.uses().is_empty());
    }

    #[tokio::test]
    async fn gif_missing_key_is_not_configured() {
        let g = FakeGate::on();
        let t = FakeTransport::new([HttpReply::ok(SEARCH)]);
        let none = GifKeys::default();
        let empty = GifKeys {
            klipy: Some(String::new()),
        };
        for k in [&none, &empty] {
            assert_eq!(
                search(&g, k, &t, "hi", 1).await.err(),
                Some(GifError::NotConfigured)
            );
            assert_eq!(
                trending(&g, k, &t, 1).await.err(),
                Some(GifError::NotConfigured)
            );
            assert_eq!(
                data(&g, k, &t, 1, SLUG).await.err(),
                Some(GifError::NotConfigured)
            );
        }
        assert_eq!(t.calls(), 0);
    }

    #[tokio::test]
    async fn gif_unknown_provider_data_is_not_found_without_call() {
        let g = FakeGate::on();
        let t = FakeTransport::new([HttpReply::ok(ITEMS)]);
        for provider in [0, 2] {
            assert_eq!(
                data(&g, &keys(), &t, provider, SLUG).await.err(),
                Some(GifError::NotFound)
            );
        }
        assert_eq!(
            data(&g, &keys(), &t, 1, "Bad Id!").await.err(),
            Some(GifError::NotFound)
        );
        assert_eq!(t.calls(), 0);
        assert_eq!(g.checks(), 0);
    }

    #[tokio::test]
    async fn gif_data_resolves_then_downloads() {
        let g = FakeGate::on();
        let mp4 = b"MP4-BYTES".to_vec();
        let t = FakeTransport::new([HttpReply::ok(ITEMS), HttpReply::ok(mp4.clone())]);
        let media = data(&g, &keys(), &t, 1, SLUG).await.unwrap();
        assert_eq!(media.mp4, mp4);
        assert_eq!(t.calls(), 2);
        // Consent checked before each of the two requests.
        assert_eq!(g.checks(), 2);
        let urls = t.urls();
        assert_eq!(urls[0].path(), "/api/v1/KEY/gifs/items");
        assert!(urls[1].host_str().unwrap().ends_with("klipy.com"));
        assert_ne!(urls[1].host_str(), Some("api.klipy.com"));
        assert_eq!(g.uses(), vec![GifUse::Shown]);
    }

    #[tokio::test]
    async fn gif_data_refuses_another_entry_without_download() {
        let g = FakeGate::on();
        let t = FakeTransport::new([HttpReply::ok(ITEMS), HttpReply::ok("x")]);
        assert_eq!(
            data(&g, &keys(), &t, 1, "other-slug-1").await.err(),
            Some(GifError::Malformed)
        );
        assert_eq!(t.calls(), 1);
        assert!(g.uses().is_empty());
    }

    #[tokio::test]
    async fn gif_data_media_refusal_is_not_found_api_refusal_is_not_configured() {
        let g = FakeGate::on();
        for media in [401, 403, 404] {
            let t = FakeTransport::new([HttpReply::ok(ITEMS), HttpReply::status(media)]);
            assert_eq!(
                data(&g, &keys(), &t, 1, SLUG).await.err(),
                Some(GifError::NotFound),
                "{media}"
            );
            assert_eq!(t.calls(), 2);
        }
        for api in [401, 403] {
            let t = FakeTransport::new([HttpReply::status(api)]);
            assert_eq!(
                data(&g, &keys(), &t, 1, SLUG).await.err(),
                Some(GifError::NotConfigured),
                "{api}"
            );
            assert_eq!(t.calls(), 1);
        }
        assert!(g.uses().is_empty());
    }

    #[tokio::test]
    async fn gif_search_counts_usage() {
        let g = FakeGate::on();
        let t = FakeTransport::new([
            HttpReply::ok(SEARCH),
            HttpReply::ok(TRENDING),
            HttpReply::status(500),
        ]);
        let page = search(&g, &keys(), &t, "hi", 1).await.unwrap();
        assert!(!page.results.is_empty());
        assert_eq!(g.uses(), vec![GifUse::Search]);
        // Trending is a call to the provider too, counted as a search, so
        // Transparency's total is exact; a failed search is not counted.
        trending(&g, &keys(), &t, 1).await.unwrap();
        assert_eq!(g.uses(), vec![GifUse::Search, GifUse::Search]);
        assert_eq!(
            search(&g, &keys(), &t, "hi", 1).await.err(),
            Some(GifError::Unreachable)
        );
        assert_eq!(g.uses(), vec![GifUse::Search, GifUse::Search]);
    }

    const PREVIEW: &str = "https://static.klipy.com/ii/abc/preview.mp4";

    #[tokio::test]
    async fn gif_preview_fetches_and_counts() {
        let g = FakeGate::on();
        let t = FakeTransport::new([HttpReply::ok("MP4")]);
        assert_eq!(preview(&g, &t, PREVIEW).await.unwrap(), b"MP4".to_vec());
        assert_eq!(t.urls()[0].as_str(), PREVIEW);
        assert_eq!(g.checks(), 1);
        assert_eq!(g.uses(), vec![GifUse::Preview]);
    }

    /// GIFs turned off (by sync, in Settings) while the picker is open:
    /// the next preview sends nothing.
    #[tokio::test]
    async fn gif_preview_refused_without_consent() {
        let g = FakeGate::new(1);
        let t = FakeTransport::new([HttpReply::ok("MP4"), HttpReply::ok("MP4")]);
        preview(&g, &t, PREVIEW).await.unwrap();
        assert_eq!(
            preview(&g, &t, PREVIEW).await.err(),
            Some(GifError::NotEnabled)
        );
        assert_eq!(t.calls(), 1);
        assert_eq!(g.uses(), vec![GifUse::Preview]);
    }

    #[tokio::test]
    async fn gif_preview_refuses_other_urls_without_call() {
        let g = FakeGate::on();
        let t = FakeTransport::new([HttpReply::ok("MP4")]);
        for bad in [
            "",
            "not a url",
            "http://static.klipy.com/a.mp4",
            "https://static.klipy.com:8443/a.mp4",
            "https://user@static.klipy.com/a.mp4",
            "https://static.klipy.com.evil.net/a.mp4",
            "https://cdn.example.com/a.mp4",
            // The API host is the provider's, but never a preview's.
            "https://api.klipy.com/a.mp4",
            "https://api.klipy.com/api/v1/KEY/gifs/trending",
        ] {
            assert_eq!(
                preview(&g, &t, bad).await.err(),
                Some(GifError::Malformed),
                "{bad}"
            );
        }
        assert_eq!(t.calls(), 0);
        assert_eq!(g.checks(), 0);
    }

    #[tokio::test]
    async fn gif_preview_failure_is_not_counted() {
        let g = FakeGate::on();
        for (status, want) in [
            (403, GifError::NotFound),
            (404, GifError::NotFound),
            (500, GifError::Unreachable),
        ] {
            let t = FakeTransport::new([HttpReply::status(status)]);
            assert_eq!(preview(&g, &t, PREVIEW).await.err(), Some(want), "{status}");
        }
        assert!(g.uses().is_empty());
    }

    #[test]
    fn every_provider_id_has_its_provider() {
        let id = GifProviderId::Klipy;
        assert_eq!(provider_of(id).id(), id);
    }

    #[test]
    fn gif_keys_debug_hides_the_key() {
        assert!(!format!("{:?}", keys()).contains("KEY"));
    }
}
