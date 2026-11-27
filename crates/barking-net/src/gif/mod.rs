//! GIF providers: search, trending and resolution of a received GIF.
//!
//! Everything specific to a provider sits behind [`GifProvider`]; the HTTPS
//! requests go through [`GifTransport`]. Nothing here is cached: responses,
//! URLs and media only live for the call that fetched them.

pub mod http;
pub mod klipy;
pub mod provider;

use barking_core::Core;
use barking_core::core::GifUse;
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

fn provider_of(id: GifProviderId) -> &'static dyn GifProvider {
    providers()
        .into_iter()
        .find(|p| p.id() == id)
        .expect("every GifProviderId has a provider")
}

/// Consent, then key: the provider's key if this client may contact it
/// now. A core that cannot answer counts as no consent.
fn gate(core: &Core, keys: &GifKeys, id: GifProviderId) -> Result<String, GifError> {
    if !core.gif_allowed(id.as_u8()).unwrap_or(false) {
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
    core: &mut Core,
    keys: &GifKeys,
    t: &impl GifTransport,
    query: &str,
    page: u32,
    now: u64,
) -> Result<GifPage, GifError> {
    let provider = provider_of(ACTIVE_GIF_PROVIDER);
    let key = gate(core, keys, ACTIVE_GIF_PROVIDER)?;
    let body = t
        .get(&provider.search_url(&key, query, page), MAX_GIF_BYTES)
        .await?;
    let page = provider.parse_page(&body)?;
    // A counter that cannot be written never fails the search.
    let _ = core.record_gif_use(GifUse::Search, now);
    Ok(page)
}

/// One page of trending GIFs. Not counted as a search.
///
/// # Errors
/// As [`search`].
pub async fn trending(
    core: &mut Core,
    keys: &GifKeys,
    t: &impl GifTransport,
    page: u32,
    _now: u64,
) -> Result<GifPage, GifError> {
    let provider = provider_of(ACTIVE_GIF_PROVIDER);
    let key = gate(core, keys, ACTIVE_GIF_PROVIDER)?;
    let body = t
        .get(&provider.trending_url(&key, page), MAX_GIF_BYTES)
        .await?;
    provider.parse_page(&body)
}

/// Resolves the GIF `id` of `provider` and downloads its MP4. Consent is
/// checked again before the download. Counts a GIF shown on success.
///
/// # Errors
/// `NotFound` for an unknown provider or a malformed identifier (nothing
/// is sent) and for a media host that no longer serves the GIF (`403`,
/// `404`); `Malformed` if the provider answers with another entry; else as
/// [`search`].
pub async fn data(
    core: &mut Core,
    keys: &GifKeys,
    t: &impl GifTransport,
    provider: u8,
    id: &str,
    now: u64,
) -> Result<GifMedia, GifError> {
    let pid = GifProviderId::from_u8(provider).ok_or(GifError::NotFound)?;
    let p = provider_of(pid);
    if !p.validate_id(id) {
        return Err(GifError::NotFound);
    }
    let key = gate(core, keys, pid)?;
    let body = t.get(&p.resolve_url(&key, id), MAX_GIF_BYTES).await?;
    let item = p.parse_item(&body)?;
    if item.id != id {
        return Err(GifError::Malformed);
    }
    // Consent may have been withdrawn while the first call was running.
    gate(core, keys, pid)?;
    let mp4 = t.get(&item.mp4, MAX_GIF_BYTES).await.map_err(|e| match e {
        // On the media host a refusal means the file is gone, not that the
        // app's key is wrong.
        GifError::NotConfigured => GifError::NotFound,
        e => e,
    })?;
    let _ = core.record_gif_use(GifUse::Shown, now);
    Ok(GifMedia {
        mp4,
        author: item.author,
        title: item.title,
    })
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    use super::http::HttpReply;
    use super::http::fake::FakeTransport;
    use super::*;

    const SEARCH: &[u8] = include_bytes!("../../tests/fixtures/klipy/search.json");
    const TRENDING: &[u8] = include_bytes!("../../tests/fixtures/klipy/trending.json");
    const ITEMS: &[u8] = include_bytes!("../../tests/fixtures/klipy/items.json");
    const SLUG: &str = "hello-hi-662";
    const NOW: u64 = 1_800_000_000;

    fn core(enabled: bool) -> (tempfile::TempDir, Core, StdRng) {
        let dir = tempfile::tempdir().unwrap();
        let mut rng = StdRng::seed_from_u64(3);
        let (mut core, _) =
            Core::create(&dir.path().join("a.db"), &[1; 32], "a", NOW, &mut rng).unwrap();
        if enabled {
            core.enable_gif_provider(1, 1, NOW, &mut rng).unwrap();
        }
        (dir, core, rng)
    }

    fn keys() -> GifKeys {
        GifKeys {
            klipy: Some("KEY".into()),
        }
    }

    fn usage(core: &Core) -> (u32, u32) {
        core.gif_usage(1)
            .unwrap()
            .first()
            .map_or((0, 0), |d| (d.searches, d.shown))
    }

    #[tokio::test]
    async fn gif_calls_refused_without_consent() {
        let (_d, mut core, _) = core(false);
        let t = FakeTransport::new([HttpReply::ok(SEARCH), HttpReply::ok(ITEMS)]);
        assert_eq!(
            search(&mut core, &keys(), &t, "hi", 1, NOW).await.err(),
            Some(GifError::NotEnabled)
        );
        assert_eq!(
            trending(&mut core, &keys(), &t, 1, NOW).await.err(),
            Some(GifError::NotEnabled)
        );
        assert_eq!(
            data(&mut core, &keys(), &t, 1, SLUG, NOW).await.err(),
            Some(GifError::NotEnabled)
        );
        assert_eq!(t.calls(), 0);
        assert_eq!(usage(&core), (0, 0));
    }

    #[tokio::test]
    async fn gif_disable_between_calls_blocks_next_call() {
        let (_d, mut core, mut rng) = core(true);
        let t = FakeTransport::new([HttpReply::ok(SEARCH), HttpReply::ok(SEARCH)]);
        search(&mut core, &keys(), &t, "hi", 1, NOW).await.unwrap();
        core.disable_gif_provider(1, NOW + 1, &mut rng).unwrap();
        assert_eq!(
            search(&mut core, &keys(), &t, "hi", 1, NOW).await.err(),
            Some(GifError::NotEnabled)
        );
        assert_eq!(t.calls(), 1);
    }

    #[tokio::test]
    async fn gif_missing_key_is_not_configured() {
        let (_d, mut core, _) = core(true);
        let t = FakeTransport::new([HttpReply::ok(SEARCH)]);
        let none = GifKeys::default();
        assert_eq!(
            search(&mut core, &none, &t, "hi", 1, NOW).await.err(),
            Some(GifError::NotConfigured)
        );
        assert_eq!(
            trending(&mut core, &none, &t, 1, NOW).await.err(),
            Some(GifError::NotConfigured)
        );
        assert_eq!(
            data(&mut core, &none, &t, 1, SLUG, NOW).await.err(),
            Some(GifError::NotConfigured)
        );
        assert_eq!(t.calls(), 0);
    }

    #[tokio::test]
    async fn gif_unknown_provider_data_is_not_found_without_call() {
        let (_d, mut core, _) = core(true);
        let t = FakeTransport::new([HttpReply::ok(ITEMS)]);
        for provider in [0, 2] {
            assert_eq!(
                data(&mut core, &keys(), &t, provider, SLUG, NOW)
                    .await
                    .err(),
                Some(GifError::NotFound)
            );
        }
        assert_eq!(
            data(&mut core, &keys(), &t, 1, "Bad Id!", NOW).await.err(),
            Some(GifError::NotFound)
        );
        assert_eq!(t.calls(), 0);
    }

    #[tokio::test]
    async fn gif_data_resolves_then_downloads() {
        let (_d, mut core, _) = core(true);
        let mp4 = b"MP4-BYTES".to_vec();
        let t = FakeTransport::new([HttpReply::ok(ITEMS), HttpReply::ok(mp4.clone())]);
        let media = data(&mut core, &keys(), &t, 1, SLUG, NOW).await.unwrap();
        assert_eq!(media.mp4, mp4);
        assert_eq!(t.calls(), 2);
        let urls = t.urls();
        assert_eq!(urls[0].path(), "/api/v1/KEY/gifs/items");
        assert!(urls[1].host_str().unwrap().ends_with("klipy.com"));
        assert_ne!(urls[1].host_str(), Some("api.klipy.com"));
        assert_eq!(usage(&core), (0, 1));
    }

    #[tokio::test]
    async fn gif_data_refuses_another_entry_without_download() {
        let (_d, mut core, _) = core(true);
        let t = FakeTransport::new([HttpReply::ok(ITEMS), HttpReply::ok("x")]);
        assert_eq!(
            data(&mut core, &keys(), &t, 1, "other-slug-1", NOW)
                .await
                .err(),
            Some(GifError::Malformed)
        );
        assert_eq!(t.calls(), 1);
        assert_eq!(usage(&core), (0, 0));
    }

    #[tokio::test]
    async fn gif_data_media_403_is_not_found_api_403_is_not_configured() {
        let (_d, mut core, _) = core(true);
        for media in [403, 404] {
            let t = FakeTransport::new([HttpReply::ok(ITEMS), HttpReply::status(media)]);
            assert_eq!(
                data(&mut core, &keys(), &t, 1, SLUG, NOW).await.err(),
                Some(GifError::NotFound),
                "{media}"
            );
            assert_eq!(t.calls(), 2);
        }
        let t = FakeTransport::new([HttpReply::status(403)]);
        assert_eq!(
            data(&mut core, &keys(), &t, 1, SLUG, NOW).await.err(),
            Some(GifError::NotConfigured)
        );
        assert_eq!(t.calls(), 1);
        assert_eq!(usage(&core), (0, 0));
    }

    #[tokio::test]
    async fn gif_search_counts_usage() {
        let (_d, mut core, _) = core(true);
        let t = FakeTransport::new([
            HttpReply::ok(SEARCH),
            HttpReply::ok(TRENDING),
            HttpReply::status(500),
        ]);
        let page = search(&mut core, &keys(), &t, "hi", 1, NOW).await.unwrap();
        assert!(!page.results.is_empty());
        assert_eq!(usage(&core), (1, 0));
        // Trending is not a search; a failed search is not counted.
        trending(&mut core, &keys(), &t, 1, NOW).await.unwrap();
        assert_eq!(
            search(&mut core, &keys(), &t, "hi", 1, NOW).await.err(),
            Some(GifError::Unreachable)
        );
        assert_eq!(usage(&core), (1, 0));
    }

    #[test]
    fn gif_keys_debug_hides_the_key() {
        assert!(!format!("{:?}", keys()).contains("KEY"));
    }
}
