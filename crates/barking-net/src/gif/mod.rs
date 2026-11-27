//! GIF providers: search, trending and resolution of a received GIF.
//!
//! Everything specific to a provider sits behind [`GifProvider`]; the HTTPS
//! requests go through [`GifTransport`]. Nothing here is cached: responses,
//! URLs and media only live for the call that fetched them.

pub mod http;
pub mod klipy;
pub mod provider;

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
