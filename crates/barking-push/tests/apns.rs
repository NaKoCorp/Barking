//! APNs client tests against a fake APNs: cleartext HTTP/2 (h2c) on
//! 127.0.0.1.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use barking_proto::push::{ApnsEnv, WakeReason, WakeToken};
use barking_push::apns::ApnsPusher;
use barking_push::{ApnsConfig, PushOutcome, Pusher};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use p256::ecdsa::SigningKey;
use tokio::net::TcpListener;

const BODY: &str =
    r#"{"aps":{"alert":{"loc-key":"NEW_MESSAGE"},"mutable-content":1,"sound":"default"}}"#;
const RECEIPT_BODY: &str = r#"{"aps":{"content-available":1}}"#;

#[derive(Clone, Debug)]
struct Seen {
    path: String,
    headers: Vec<(String, String)>,
    body: String,
}

impl Seen {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

struct Fake {
    url: String,
    seen: Arc<Mutex<Vec<Seen>>>,
    replies: Arc<Mutex<VecDeque<(u16, &'static str)>>>,
}

async fn fake() -> Fake {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
    let replies: Arc<Mutex<VecDeque<(u16, &'static str)>>> = Arc::default();
    let (s, r) = (seen.clone(), replies.clone());
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let (s, r) = (s.clone(), r.clone());
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let (s, r) = (s.clone(), r.clone());
                    async move {
                        let path = req.uri().path().to_string();
                        let headers = req
                            .headers()
                            .iter()
                            .map(|(k, v)| (k.to_string(), v.to_str().unwrap().to_string()))
                            .collect();
                        let body = req.into_body().collect().await.unwrap().to_bytes();
                        s.lock().unwrap().push(Seen {
                            path,
                            headers,
                            body: String::from_utf8(body.to_vec()).unwrap(),
                        });
                        let (code, text) = r.lock().unwrap().pop_front().unwrap_or((200, ""));
                        Ok::<_, std::convert::Infallible>(
                            Response::builder()
                                .status(code)
                                .body(Full::new(Bytes::from_static(text.as_bytes())))
                                .unwrap(),
                        )
                    }
                });
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    Fake { url, seen, replies }
}

fn key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32].into()).unwrap()
}

fn cfg(production: &str, sandbox: &str) -> ApnsConfig {
    ApnsConfig {
        team_id: "TEAM123456".into(),
        key_id: "KEY1234567".into(),
        topic: "fr.example.barking".into(),
        key_file: "unused.p8".into(),
        production_url: production.into(),
        sandbox_url: sandbox.into(),
    }
}

fn token(env: ApnsEnv) -> WakeToken {
    WakeToken {
        apns_token: vec![0xab; 32],
        env,
        collapse: [0x11; 16],
        expires_day: 0,
        reason: WakeReason::Message,
    }
}

/// Clock that advances by one second at every reading.
fn ticking_clock() -> impl Fn() -> u64 + Send + Sync + 'static {
    let t = AtomicU64::new(1_700_000_000);
    move || t.fetch_add(1, Ordering::SeqCst)
}

fn pusher(production: &str, sandbox: &str) -> ApnsPusher {
    ApnsPusher::new_insecure_for_tests(&cfg(production, sandbox), key(), ticking_clock()).unwrap()
}

fn iat_of(jwt: &str) -> u64 {
    let payload = jwt.split('.').nth(1).unwrap();
    let json = data_encoding::BASE64URL_NOPAD
        .decode(payload.as_bytes())
        .unwrap();
    let text = String::from_utf8(json).unwrap();
    text.split("\"iat\":")
        .nth(1)
        .unwrap()
        .trim_end_matches('}')
        .parse()
        .unwrap()
}

#[tokio::test]
async fn push_sends_exact_headers_and_body() {
    let f = fake().await;
    let p = pusher(&f.url, &f.url);
    assert_eq!(p.push(token(ApnsEnv::Production)).await, PushOutcome::Sent);
    let seen = f.seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    let s = &seen[0];
    assert_eq!(s.path, format!("/3/device/{}", "ab".repeat(32)));
    assert_eq!(s.body, BODY);
    let jwt = s
        .header("authorization")
        .unwrap()
        .strip_prefix("bearer ")
        .unwrap();
    let part = |i: usize| {
        let raw = data_encoding::BASE64URL_NOPAD
            .decode(jwt.split('.').nth(i).unwrap().as_bytes())
            .unwrap();
        String::from_utf8(raw).unwrap()
    };
    assert!(part(0).contains(r#""kid":"KEY1234567""#));
    assert!(part(1).contains(r#""iss":"TEAM123456""#));
    assert_eq!(s.header("apns-topic"), Some("fr.example.barking"));
    assert_eq!(s.header("apns-push-type"), Some("alert"));
    assert_eq!(s.header("apns-priority"), Some("10"));
    assert_eq!(s.header("apns-collapse-id"), Some("11".repeat(16).as_str()));
    let exp: u64 = s.header("apns-expiration").unwrap().parse().unwrap();
    assert!((1_700_000_000 + 3600..1_700_000_000 + 3700).contains(&exp));
}

#[tokio::test]
async fn receipt_push_is_background() {
    let f = fake().await;
    let p = pusher(&f.url, &f.url);
    let mut t = token(ApnsEnv::Production);
    t.reason = WakeReason::Receipt;
    assert_eq!(p.push(t).await, PushOutcome::Sent);
    let seen = f.seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    let s = &seen[0];
    assert_eq!(s.body, RECEIPT_BODY);
    assert_eq!(s.header("apns-topic"), Some("fr.example.barking"));
    assert_eq!(s.header("apns-push-type"), Some("background"));
    assert_eq!(s.header("apns-priority"), Some("5"));
    assert_eq!(s.header("apns-collapse-id"), Some("11".repeat(16).as_str()));
    let exp: u64 = s.header("apns-expiration").unwrap().parse().unwrap();
    assert!((1_700_000_000 + 3600..1_700_000_000 + 3700).contains(&exp));
}

#[tokio::test]
async fn status_mapping() {
    let f = fake().await;
    let p = pusher(&f.url, &f.url);
    {
        let mut r = f.replies.lock().unwrap();
        r.push_back((200, ""));
        r.push_back((410, r#"{"reason":"Unregistered"}"#));
        r.push_back((400, r#"{"reason":"BadDeviceToken"}"#));
    }
    assert_eq!(p.push(token(ApnsEnv::Production)).await, PushOutcome::Sent);
    assert_eq!(
        p.push(token(ApnsEnv::Production)).await,
        PushOutcome::Unregistered
    );
    assert_eq!(
        p.push(token(ApnsEnv::Production)).await,
        PushOutcome::Failed(400)
    );
}

#[tokio::test]
async fn expired_provider_token_refreshes_jwt() {
    let f = fake().await;
    let p = pusher(&f.url, &f.url);
    f.replies
        .lock()
        .unwrap()
        .push_back((403, r#"{"reason":"ExpiredProviderToken"}"#));
    assert_eq!(p.push(token(ApnsEnv::Production)).await, PushOutcome::Sent);
    let seen = f.seen.lock().unwrap();
    assert_eq!(seen.len(), 2, "one retry after ExpiredProviderToken");
    let bearer = |s: &Seen| {
        s.header("authorization")
            .unwrap()
            .strip_prefix("bearer ")
            .unwrap()
            .to_string()
    };
    assert!(iat_of(&bearer(&seen[1])) > iat_of(&bearer(&seen[0])));
}

#[tokio::test]
async fn other_403_is_not_retried() {
    let f = fake().await;
    let p = pusher(&f.url, &f.url);
    f.replies
        .lock()
        .unwrap()
        .push_back((403, r#"{"reason":"InvalidProviderToken"}"#));
    assert_eq!(
        p.push(token(ApnsEnv::Production)).await,
        PushOutcome::Failed(403)
    );
    assert_eq!(f.seen.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn jwt_is_cached_between_pushes() {
    let f = fake().await;
    let p = pusher(&f.url, &f.url);
    p.push(token(ApnsEnv::Production)).await;
    p.push(token(ApnsEnv::Production)).await;
    let seen = f.seen.lock().unwrap();
    assert_eq!(
        seen[0].header("authorization"),
        seen[1].header("authorization")
    );
}

#[tokio::test]
async fn sandbox_token_goes_to_sandbox_url() {
    let prod = fake().await;
    let sandbox = fake().await;
    let p = pusher(&prod.url, &sandbox.url);
    assert_eq!(p.push(token(ApnsEnv::Sandbox)).await, PushOutcome::Sent);
    assert_eq!(prod.seen.lock().unwrap().len(), 0);
    assert_eq!(sandbox.seen.lock().unwrap().len(), 1);
    assert_eq!(p.push(token(ApnsEnv::Production)).await, PushOutcome::Sent);
    assert_eq!(prod.seen.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn production_constructor_refuses_cleartext_urls() {
    let c = cfg("http://127.0.0.1:1", "https://api.sandbox.push.apple.com");
    assert!(ApnsPusher::new(&c, key()).is_err());
}

#[tokio::test]
async fn unreachable_apns_is_failed_zero() {
    let p = pusher("http://127.0.0.1:1", "http://127.0.0.1:1");
    assert_eq!(
        p.push(token(ApnsEnv::Production)).await,
        PushOutcome::Failed(0)
    );
}

#[tokio::test]
async fn jwt_renewed_at_exactly_fifty_minutes() {
    let f = fake().await;
    let now = Arc::new(AtomicU64::new(1_700_000_000));
    let c = now.clone();
    let p = ApnsPusher::new_insecure_for_tests(&cfg(&f.url, &f.url), key(), move || {
        c.load(Ordering::SeqCst)
    })
    .unwrap();
    p.push(token(ApnsEnv::Production)).await;
    now.store(1_700_000_000 + 2999, Ordering::SeqCst);
    p.push(token(ApnsEnv::Production)).await;
    now.store(1_700_000_000 + 3000, Ordering::SeqCst);
    p.push(token(ApnsEnv::Production)).await;
    let seen = f.seen.lock().unwrap();
    let auth = |i: usize| seen[i].header("authorization").unwrap().to_string();
    assert_eq!(auth(0), auth(1), "reused at +2999 s");
    assert_ne!(auth(1), auth(2), "renewed at +3000 s");
}

#[tokio::test]
async fn concurrent_expired_tokens_renew_once() {
    const N: usize = 8;
    let f = fake().await;
    let p = Arc::new(pusher(&f.url, &f.url));
    p.push(token(ApnsEnv::Production)).await; // caches the first token
    {
        let mut r = f.replies.lock().unwrap();
        for _ in 0..N {
            r.push_back((403, r#"{"reason":"ExpiredProviderToken"}"#));
        }
    }
    let mut tasks = Vec::new();
    for _ in 0..N {
        let p = p.clone();
        tasks.push(tokio::spawn(async move {
            p.push(token(ApnsEnv::Production)).await
        }));
    }
    for t in tasks {
        assert_eq!(t.await.unwrap(), PushOutcome::Sent);
    }
    let seen = f.seen.lock().unwrap();
    let mut bearers: Vec<&str> = seen
        .iter()
        .map(|s| s.header("authorization").unwrap())
        .collect();
    bearers.sort_unstable();
    bearers.dedup();
    assert_eq!(bearers.len(), 2, "the old token and a single renewal");
}
