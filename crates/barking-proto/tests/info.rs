//! `Info` request gating on the negotiated version and the session's round
//! trip samples, against a minimal quinn server.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use barking_proto::client::Client;
use barking_proto::frame::{self, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES};
use barking_proto::msg::{FillTier, Limits, NodeInfoReport, Request, Response};
use barking_proto::{ErrorReason, NodeId, NodeRecord, tls};
use ed25519_dalek::SigningKey;
use quinn::Endpoint;

/// Seed of a key solving the 20-bit puzzle (same as `peer_auth.rs`).
const SEED: [u8; 32] = [
    109, 33, 207, 142, 255, 118, 3, 197, 255, 37, 245, 98, 29, 38, 206, 73, 204, 227, 116, 134,
    207, 149, 45, 186, 178, 63, 22, 1, 91, 51, 3, 154,
];

fn report() -> NodeInfoReport {
    NodeInfoReport {
        software: "test".into(),
        protocol: 5,
        uptime_secs: 3,
        storage: FillTier::Low,
        wake: None,
        push_link: None,
        origin: None,
    }
}

/// Server speaking `version` in `Hello`; counts every request other than
/// `Hello`. `Info` gets the report, or `Unsupported` if `info_unsupported`.
fn spawn_server(
    key: &SigningKey,
    version: u16,
    info_unsupported: bool,
) -> (SocketAddr, Arc<AtomicUsize>, Endpoint) {
    let ep = Endpoint::server(
        tls::quinn_server_config(key),
        (Ipv4Addr::LOCALHOST, 0).into(),
    )
    .unwrap();
    let addr = ep.local_addr().unwrap();
    let node_id = NodeId::from_public_key(&key.verifying_key());
    let record = NodeRecord::sign(key, Some("1.2.3.4:4433".parse().unwrap()), None, 7_200);
    let others = Arc::new(AtomicUsize::new(0));
    let (ep2, others2) = (ep.clone(), others.clone());
    tokio::spawn(async move {
        while let Some(incoming) = ep2.accept().await {
            let (record, others) = (record.clone(), others2.clone());
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                    let Ok(req) = frame::read::<Request>(&mut recv, MAX_REQUEST_BYTES).await else {
                        return;
                    };
                    let resp = match req {
                        Request::Hello { .. } => Response::Hello {
                            version,
                            min_version: 2,
                            node_id,
                            pow_bits: 8,
                            limits: Limits {
                                max_mailboxes_per_fetch: 8,
                                max_request_bytes: MAX_REQUEST_BYTES as u32,
                                max_response_bytes: MAX_RESPONSE_BYTES as u32,
                                wake: false,
                            },
                        },
                        Request::Info { .. } => {
                            others.fetch_add(1, Ordering::SeqCst);
                            if info_unsupported {
                                Response::Error(ErrorReason::Unsupported)
                            } else {
                                Response::Info(report())
                            }
                        }
                        _ => {
                            others.fetch_add(1, Ordering::SeqCst);
                            Response::Pong {
                                record: record.clone(),
                            }
                        }
                    };
                    let _ = frame::write(&mut send, &resp, MAX_RESPONSE_BYTES).await;
                    let _ = send.finish();
                }
            });
        }
    });
    (addr, others, ep)
}

fn id_of(k: &SigningKey) -> NodeId {
    NodeId::from_public_key(&k.verifying_key())
}

#[tokio::test]
async fn info_not_sent_below_v5() {
    let key = SigningKey::from_bytes(&SEED);
    let (addr, requests, _ep) = spawn_server(&key, 4, false);
    let session = Client::connect(addr, id_of(&key)).await.unwrap();
    assert_eq!(session.peer_version(), 4);
    assert!(!session.info_supported());
    assert_eq!(session.info(None).await.unwrap(), None);
    assert_eq!(session.info(Some(NodeId([1; 32]))).await.unwrap(), None);
    assert_eq!(requests.load(Ordering::SeqCst), 0, "nothing was sent");
}

#[tokio::test]
async fn info_returns_the_report_from_v5() {
    let key = SigningKey::from_bytes(&SEED);
    let (addr, requests, _ep) = spawn_server(&key, 5, false);
    let session = Client::connect(addr, id_of(&key)).await.unwrap();
    assert_eq!(session.peer_version(), 5);
    assert!(session.info_supported());
    assert_eq!(session.info(None).await.unwrap(), Some(report()));
    assert_eq!(requests.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn info_error_response_is_none() {
    let key = SigningKey::from_bytes(&SEED);
    let (addr, _requests, _ep) = spawn_server(&key, 5, true);
    let session = Client::connect(addr, id_of(&key)).await.unwrap();
    assert_eq!(session.info(None).await.unwrap(), None);
}

#[tokio::test]
async fn rtt_samples_keep_last_eight() {
    let key = SigningKey::from_bytes(&SEED);
    let (addr, _requests, _ep) = spawn_server(&key, 5, false);
    let session = Client::connect(addr, id_of(&key)).await.unwrap();
    // `Hello` already gave one sample.
    assert_eq!(session.rtt_samples().len(), 1);
    for _ in 0..10 {
        session
            .request(&Request::Ping { from: None })
            .await
            .unwrap();
    }
    assert_eq!(session.rtt_samples().len(), 8);
}
