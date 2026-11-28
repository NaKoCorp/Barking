//! What a GIF provider must offer. Settings, sync, message contents and the
//! interface only go through this trait.

use barking_core::gif::GifProviderId;
use url::Url;

use super::{GifError, GifItem, GifPage};

pub trait GifProvider: Send + Sync {
    fn id(&self) -> GifProviderId;
    /// Name shown in the interface.
    fn name(&self) -> &'static str;
    /// Version of this provider's warning the interface shows now; at
    /// least `MIN_GIF_WARNING_VERSION`, raised when its text changes in a
    /// way that matters.
    fn warning_version(&self) -> u16;
    /// The provider's privacy policy, linked from the warning.
    fn privacy_url(&self) -> &'static str;
    /// The only hosts ever contacted for this provider, API and media.
    fn hosts(&self) -> &'static [&'static str];
    /// The hosts serving media only (a subset of [`Self::hosts`]): the
    /// only ones a picker preview may be fetched from.
    fn media_hosts(&self) -> &'static [&'static str];
    /// Whether `id` has the format of an identifier of this provider.
    fn validate_id(&self, id: &str) -> bool;
    /// Search request. `key` is the app's key for this provider.
    fn search_url(&self, key: &str, query: &str, page: u32) -> Url;
    fn trending_url(&self, key: &str, page: u32) -> Url;
    /// Request resolving a received GIF from its identifier.
    fn resolve_url(&self, key: &str, id: &str) -> Url;
    /// Reads a search or trending response.
    fn parse_page(&self, body: &[u8]) -> Result<GifPage, GifError>;
    /// Reads a resolution response.
    fn parse_item(&self, body: &[u8]) -> Result<GifItem, GifError>;
}
