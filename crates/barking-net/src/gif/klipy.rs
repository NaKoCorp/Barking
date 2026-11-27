//! Klipy (<https://docs.klipy.com>), the active GIF provider.
//!
//! JSON fields read (documentation of 2026-11-27, "GIF - Search API",
//! "GIF - Trending API", "GIF - Items API"):
//! - envelope: `result` (must not be `false`), `data.data[]` (entries),
//!   `data.current_page` and `data.has_next` (pages only);
//! - entry: `slug` (identifier), `title`, `type` (only `gif` is kept),
//!   `file.<size>.mp4.{url,width,height}` with size `md` (else `hd`, `sm`,
//!   `xs`) for the GIF itself and `sm` (else `xs`, `md`, `hd`) for the
//!   picker preview;
//! - author: none documented, so `GifItem::author` stays `None` until a
//!   live response shows one.

use std::collections::BTreeMap;

use barking_core::gif::{GifProviderId, MAX_GIF_ID_LEN};
use serde::Deserialize;
use url::Url;

use super::{GifError, GifItem, GifPage, GifProvider, GifResult, url_allowed};

/// API root; the key is the next path segment.
const API_BASE: &str = "https://api.klipy.com/api/v1/";
const HOSTS: &[&str] = &[
    "api.klipy.com",
    "static.klipy.com",
    "static1.klipy.com",
    "static2.klipy.com",
];
/// Results per page (Klipy accepts 8 to 50).
const PER_PAGE: &str = "24";
const FORMAT_FILTER: &str = "mp4";
const CONTENT_FILTER: &str = "medium";
/// Rendition sent and shown, by preference.
const MAIN_SIZES: [&str; 4] = ["md", "hd", "sm", "xs"];
/// Rendition for the picker grid, by preference.
const PREVIEW_SIZES: [&str; 4] = ["sm", "xs", "md", "hd"];

struct Klipy;

static KLIPY: Klipy = Klipy;

/// The Klipy provider.
#[must_use]
pub fn klipy() -> &'static dyn GifProvider {
    &KLIPY
}

#[derive(Deserialize)]
struct Envelope {
    result: Option<bool>,
    data: Option<Data>,
}

#[derive(Deserialize)]
struct Data {
    data: Option<Vec<serde_json::Value>>,
    current_page: Option<u32>,
    has_next: Option<bool>,
}

#[derive(Deserialize)]
struct Entry {
    slug: String,
    #[serde(default)]
    title: Option<String>,
    #[serde(rename = "type", default)]
    kind: Option<String>,
    file: BTreeMap<String, BTreeMap<String, serde_json::Value>>,
}

#[derive(Deserialize)]
struct Rendition {
    url: String,
    width: u64,
    height: u64,
}

/// An entry reduced to what the client keeps.
struct Parsed {
    id: String,
    title: String,
    mp4: Url,
    width: u16,
    height: u16,
    preview: Url,
}

impl Klipy {
    fn api_url(key: &str, endpoint: &str) -> Url {
        let mut url = Url::parse(API_BASE).expect("static URL");
        url.path_segments_mut()
            .expect("https URL has a path")
            .pop_if_empty()
            .push(key)
            .push("gifs")
            .push(endpoint);
        url
    }

    fn list_url(key: &str, endpoint: &str, query: Option<&str>, page: u32) -> Url {
        let mut url = Self::api_url(key, endpoint);
        {
            let mut pairs = url.query_pairs_mut();
            if let Some(q) = query {
                pairs.append_pair("q", q);
            }
            pairs
                .append_pair("page", &page.max(1).to_string())
                .append_pair("per_page", PER_PAGE)
                .append_pair("format_filter", FORMAT_FILTER)
                .append_pair("content_filter", CONTENT_FILTER);
        }
        url
    }

    /// Entries of a response; `Malformed` for anything but a successful
    /// envelope with an entry list.
    fn envelope(body: &[u8]) -> Result<Data, GifError> {
        let env: Envelope = serde_json::from_slice(body).map_err(|_| GifError::Malformed)?;
        if env.result == Some(false) {
            return Err(GifError::Malformed);
        }
        let data = env.data.ok_or(GifError::Malformed)?;
        if data.data.is_none() {
            return Err(GifError::Malformed);
        }
        Ok(data)
    }

    /// `Ok(None)` for an entry the client does not use (not a GIF, no MP4,
    /// bad identifier or size); `Malformed` for a media URL outside the
    /// provider's hosts, which is never skipped silently.
    fn entry(&self, value: serde_json::Value) -> Result<Option<Parsed>, GifError> {
        let Ok(entry) = serde_json::from_value::<Entry>(value) else {
            return Ok(None);
        };
        if entry.kind.as_deref().is_some_and(|k| k != "gif") || !self.validate_id(&entry.slug) {
            return Ok(None);
        }
        let (Some(main), Some(preview)) = (
            Self::rendition(&entry, &MAIN_SIZES),
            Self::rendition(&entry, &PREVIEW_SIZES),
        ) else {
            return Ok(None);
        };
        let mp4 = self.media_url(&main.url)?;
        let preview = self.media_url(&preview.url)?;
        let (Some(width), Some(height)) = (dimension(main.width), dimension(main.height)) else {
            return Ok(None);
        };
        Ok(Some(Parsed {
            id: entry.slug,
            title: entry.title.unwrap_or_default(),
            mp4,
            width,
            height,
            preview,
        }))
    }

    /// The MP4 of the first size present; a broken one makes the entry
    /// unusable rather than falling back to another size.
    fn rendition(entry: &Entry, sizes: &[&str]) -> Option<Rendition> {
        let mp4 = sizes
            .iter()
            .find_map(|size| entry.file.get(*size)?.get("mp4"))?;
        serde_json::from_value(mp4.clone()).ok()
    }

    fn media_url(&self, raw: &str) -> Result<Url, GifError> {
        let url = Url::parse(raw).map_err(|_| GifError::Malformed)?;
        if url_allowed(self, &url) {
            Ok(url)
        } else {
            Err(GifError::Malformed)
        }
    }
}

/// A usable dimension: 1 to `u16::MAX`.
fn dimension(value: u64) -> Option<u16> {
    u16::try_from(value).ok().filter(|v| *v > 0)
}

impl GifProvider for Klipy {
    fn id(&self) -> GifProviderId {
        GifProviderId::Klipy
    }

    fn name(&self) -> &'static str {
        GifProviderId::Klipy.name()
    }

    fn hosts(&self) -> &'static [&'static str] {
        HOSTS
    }

    /// A Klipy slug: `[a-z0-9-]{1,64}`.
    fn validate_id(&self, id: &str) -> bool {
        (1..=MAX_GIF_ID_LEN).contains(&id.len())
            && id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    }

    fn search_url(&self, key: &str, query: &str, page: u32) -> Url {
        Self::list_url(key, "search", Some(query), page)
    }

    fn trending_url(&self, key: &str, page: u32) -> Url {
        Self::list_url(key, "trending", None, page)
    }

    fn resolve_url(&self, key: &str, id: &str) -> Url {
        let mut url = Self::api_url(key, "items");
        url.query_pairs_mut().append_pair("slugs", id);
        url
    }

    fn parse_page(&self, body: &[u8]) -> Result<GifPage, GifError> {
        let data = Self::envelope(body)?;
        let mut results = Vec::new();
        for value in data.data.unwrap_or_default() {
            if let Some(p) = self.entry(value)? {
                results.push(GifResult {
                    provider: GifProviderId::Klipy.as_u8(),
                    id: p.id,
                    width: p.width,
                    height: p.height,
                    title: p.title,
                    preview_mp4: p.preview,
                });
            }
        }
        let next = match (data.has_next, data.current_page) {
            (Some(true), Some(page)) => page.checked_add(1),
            _ => None,
        };
        Ok(GifPage { results, next })
    }

    fn parse_item(&self, body: &[u8]) -> Result<GifItem, GifError> {
        let data = Self::envelope(body)?;
        let first = data
            .data
            .unwrap_or_default()
            .into_iter()
            .next()
            .ok_or(GifError::NotFound)?;
        let p = self.entry(first)?.ok_or(GifError::Malformed)?;
        Ok(GifItem {
            id: p.id,
            mp4: p.mp4,
            width: p.width,
            height: p.height,
            title: p.title,
            author: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::gif::{GifTransport, HttpsTransport, MAX_GIF_BYTES, url_allowed};

    const SEARCH: &[u8] = include_bytes!("../../tests/fixtures/klipy/search.json");
    const TRENDING: &[u8] = include_bytes!("../../tests/fixtures/klipy/trending.json");
    const ITEMS: &[u8] = include_bytes!("../../tests/fixtures/klipy/items.json");
    const ITEMS_EMPTY: &[u8] = include_bytes!("../../tests/fixtures/klipy/items_empty.json");

    fn keys(u: &Url) -> BTreeSet<String> {
        u.query_pairs().map(|(k, _)| k.into_owned()).collect()
    }

    fn pair(u: &Url, key: &str) -> Option<String> {
        u.query_pairs()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.into_owned())
    }

    fn replace(body: &[u8], from: &str, to: &str) -> Vec<u8> {
        String::from_utf8(body.to_vec())
            .unwrap()
            .replace(from, to)
            .into_bytes()
    }

    #[test]
    fn klipy_search_url_has_only_allowed_params() {
        let u = klipy().search_url("KEY", "happy dance", 2);
        assert_eq!(u.scheme(), "https");
        assert_eq!(u.host_str(), Some("api.klipy.com"));
        assert_eq!(u.port(), None);
        assert_eq!(u.path(), "/api/v1/KEY/gifs/search");
        let expected: BTreeSet<String> =
            ["content_filter", "format_filter", "page", "per_page", "q"]
                .map(String::from)
                .into();
        assert_eq!(keys(&u), expected);
        assert_eq!(pair(&u, "q").as_deref(), Some("happy dance"));
        assert_eq!(pair(&u, "page").as_deref(), Some("2"));
        assert_eq!(pair(&u, "per_page").as_deref(), Some("24"));
        assert_eq!(pair(&u, "format_filter").as_deref(), Some("mp4"));
        assert_eq!(pair(&u, "content_filter").as_deref(), Some("medium"));
        assert!(url_allowed(klipy(), &u));
    }

    #[test]
    fn klipy_trending_url_has_only_allowed_params() {
        let u = klipy().trending_url("KEY", 1);
        assert_eq!(u.host_str(), Some("api.klipy.com"));
        assert_eq!(u.path(), "/api/v1/KEY/gifs/trending");
        let expected: BTreeSet<String> = ["content_filter", "format_filter", "page", "per_page"]
            .map(String::from)
            .into();
        assert_eq!(keys(&u), expected);
        assert!(url_allowed(klipy(), &u));
    }

    #[test]
    fn klipy_resolve_url_sends_only_slugs() {
        let u = klipy().resolve_url("KEY", "hello-hi-662");
        assert_eq!(u.host_str(), Some("api.klipy.com"));
        assert_eq!(u.path(), "/api/v1/KEY/gifs/items");
        assert_eq!(keys(&u), BTreeSet::from(["slugs".to_string()]));
        assert_eq!(pair(&u, "slugs").as_deref(), Some("hello-hi-662"));
    }

    #[test]
    fn klipy_page_zero_is_page_one() {
        let u = klipy().trending_url("KEY", 0);
        assert_eq!(pair(&u, "page").as_deref(), Some("1"));
    }

    #[test]
    fn klipy_key_stays_one_path_segment() {
        let u = klipy().search_url("a/b?c#d", "x", 1);
        assert_eq!(u.path_segments().unwrap().count(), 5);
        assert!(u.path().ends_with("/gifs/search"));
        assert_eq!(u.fragment(), None);
        assert_eq!(keys(&u).len(), 5);
    }

    #[test]
    fn klipy_validate_id() {
        let p = klipy();
        assert!(p.validate_id("hello-hi-662"));
        assert!(p.validate_id(&"a".repeat(64)));
        for bad in ["", "Hello", "a b", "a/b", "a_b", "é", &"a".repeat(65)] {
            assert!(!p.validate_id(bad), "{bad:?}");
        }
    }

    #[test]
    fn klipy_hosts() {
        assert_eq!(
            klipy().hosts(),
            &[
                "api.klipy.com",
                "static.klipy.com",
                "static1.klipy.com",
                "static2.klipy.com"
            ]
        );
        assert_eq!(klipy().id(), GifProviderId::Klipy);
        assert_eq!(klipy().name(), "Klipy");
    }

    #[test]
    fn klipy_parses_search_fixture() {
        let page = klipy().parse_page(SEARCH).unwrap();
        assert_eq!(page.next, Some(2));
        assert_eq!(page.results.len(), 2);
        for r in &page.results {
            assert_eq!(r.provider, GifProviderId::Klipy.as_u8());
            assert!(klipy().validate_id(&r.id));
            assert!(r.width > 0 && r.height > 0);
            assert!(url_allowed(klipy(), &r.preview_mp4));
        }
        let first = &page.results[0];
        assert_eq!(first.id, "hello-hi-662");
        assert_eq!(first.title, "Hello");
        // Size of the rendition `parse_item` resolves to (md), preview from sm.
        assert_eq!((first.width, first.height), (498, 498));
        assert!(first.preview_mp4.path().ends_with("/3c2Tqd1S.mp4"));
        assert_eq!(page.results[1].id, "happy-dance-cat-1k8");
        assert_eq!((page.results[1].width, page.results[1].height), (480, 270));
    }

    #[test]
    fn klipy_parses_trending_fixture() {
        let page = klipy().parse_page(TRENDING).unwrap();
        assert_eq!(page.results.len(), 2);
        assert_eq!(page.results[0].id, "happy-dance-cat-1k8");
        assert_eq!(page.next, Some(2));
    }

    #[test]
    fn klipy_last_page_has_no_next() {
        let body = replace(SEARCH, "\"has_next\": true", "\"has_next\": false");
        assert_eq!(klipy().parse_page(&body).unwrap().next, None);
    }

    #[test]
    fn klipy_empty_page_is_empty() {
        let body = br#"{"result":true,"data":{"data":[],"current_page":1,"per_page":24,"has_next":false}}"#;
        let page = klipy().parse_page(body).unwrap();
        assert!(page.results.is_empty());
        assert_eq!(page.next, None);
    }

    #[test]
    fn klipy_parses_item_fixture() {
        let item = klipy().parse_item(ITEMS).unwrap();
        assert!(url_allowed(klipy(), &item.mp4));
        assert!(item.mp4.path().ends_with("/V6da8Awi.mp4"));
        assert_eq!((item.width, item.height), (498, 498));
        assert_eq!(item.title, "Hello");
        // The documented response has no author field.
        assert_eq!(item.author, None);
    }

    #[test]
    fn klipy_item_and_result_sizes_agree() {
        let page = klipy().parse_page(SEARCH).unwrap();
        let item = klipy().parse_item(ITEMS).unwrap();
        assert_eq!(
            (page.results[0].width, page.results[0].height),
            (item.width, item.height)
        );
    }

    #[test]
    fn klipy_empty_item_is_not_found() {
        assert_eq!(klipy().parse_item(ITEMS_EMPTY), Err(GifError::NotFound));
    }

    #[test]
    fn klipy_empty_200_is_malformed() {
        for body in [
            &b""[..],
            b"{}",
            b"null",
            b"[]",
            b"not json",
            br#"{"result":false}"#,
            br#"{"result":false,"data":{"data":[]}}"#,
            br#"{"result":true}"#,
            br#"{"result":true,"data":{}}"#,
        ] {
            assert_eq!(
                klipy().parse_page(body),
                Err(GifError::Malformed),
                "{body:?}"
            );
            assert_eq!(
                klipy().parse_item(body),
                Err(GifError::Malformed),
                "{body:?}"
            );
        }
    }

    #[test]
    fn klipy_media_url_off_host_is_refused() {
        for (from, to) in [
            ("https://static.klipy.com/", "https://cdn.example.com/"),
            ("https://static.klipy.com/", "http://static.klipy.com/"),
            (
                "https://static.klipy.com/",
                "https://static.klipy.com:8443/",
            ),
            (
                "https://static.klipy.com/",
                "https://user@static.klipy.com/",
            ),
            (
                "https://static.klipy.com/",
                "https://static.klipy.com.evil.net/",
            ),
        ] {
            let items = replace(ITEMS, from, to);
            assert_eq!(klipy().parse_item(&items), Err(GifError::Malformed), "{to}");
            let search = replace(SEARCH, from, to);
            assert_eq!(
                klipy().parse_page(&search),
                Err(GifError::Malformed),
                "{to}"
            );
        }
    }

    #[test]
    fn klipy_other_static_hosts_are_accepted() {
        let items = replace(
            ITEMS,
            "https://static.klipy.com/",
            "https://static2.klipy.com/",
        );
        let item = klipy().parse_item(&items).unwrap();
        assert_eq!(item.mp4.host_str(), Some("static2.klipy.com"));
    }

    #[test]
    fn klipy_bad_item_fields_are_malformed() {
        for (from, to) in [
            ("\"hello-hi-662\"", "\"Hello Hi\""),
            ("\"width\": 498", "\"width\": 0"),
            ("\"height\": 498", "\"height\": 70000"),
            ("\"width\": 498", "\"width\": -1"),
        ] {
            let items = replace(ITEMS, from, to);
            assert_eq!(klipy().parse_item(&items), Err(GifError::Malformed), "{to}");
        }
    }

    #[test]
    fn klipy_bad_page_entries_are_skipped() {
        let bad_slug = replace(SEARCH, "\"hello-hi-662\"", "\"Hello Hi\"");
        let page = klipy().parse_page(&bad_slug).unwrap();
        assert_eq!(page.results.len(), 1);
        assert_eq!(page.results[0].id, "happy-dance-cat-1k8");
        let not_gif = replace(SEARCH, "\"type\": \"gif\"", "\"type\": \"ad\"");
        assert!(klipy().parse_page(&not_gif).unwrap().results.is_empty());
    }

    /// Calls Klipy for real with the key in `BARKING_KLIPY_KEY`:
    /// `BARKING_KLIPY_KEY=... cargo test -p barking-net klipy_live_smoke -- --ignored`.
    /// Never prints the key nor a URL holding it.
    #[tokio::test]
    #[ignore = "network; needs BARKING_KLIPY_KEY"]
    async fn klipy_live_smoke() {
        let Some(key) = std::env::var("BARKING_KLIPY_KEY")
            .ok()
            .filter(|k| !k.is_empty())
        else {
            eprintln!("BARKING_KLIPY_KEY not set, skipped");
            return;
        };
        let t = HttpsTransport::new().expect("client");
        let p = klipy();
        let body = t
            .get(&p.search_url(&key, "hello", 1), MAX_GIF_BYTES)
            .await
            .map_err(|e| format!("search: {e:?}"))
            .unwrap();
        let page = p
            .parse_page(&body)
            .map_err(|e| format!("search parse: {e:?}"))
            .unwrap();
        assert!(!page.results.is_empty(), "search returned no result");
        let first = &page.results[0];
        let body = t
            .get(&p.resolve_url(&key, &first.id), MAX_GIF_BYTES)
            .await
            .map_err(|e| format!("items: {e:?}"))
            .unwrap();
        let item = p
            .parse_item(&body)
            .map_err(|e| format!("items parse: {e:?}"))
            .unwrap();
        assert_eq!((item.width, item.height), (first.width, first.height));
        let mp4 = t
            .get(&item.mp4, MAX_GIF_BYTES)
            .await
            .map_err(|e| format!("mp4: {e:?}"))
            .unwrap();
        assert!(!mp4.is_empty());
        eprintln!(
            "klipy live: {} results, item author present: {}, mp4 {} bytes",
            page.results.len(),
            item.author.is_some(),
            mp4.len()
        );
    }
}
