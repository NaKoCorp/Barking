//! Authentification optionnelle des nœuds appelants : un serveur quinn
//! minimal répond à `Hello` et publie ce que `peer_node_id` voit.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::OnceLock;

use barking_proto::client::{self, Client, ClientError};
use barking_proto::frame::{self, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES};
use barking_proto::msg::{Limits, Request, Response};
use barking_proto::{NodeId, PROTOCOL_VERSION, generate_node_key, tls};
use ed25519_dalek::SigningKey;
use quinn::Endpoint;
use rand::SeedableRng;
use rand::rngs::StdRng;
use tokio::sync::mpsc;

fn key(n: usize) -> SigningKey {
    static KEYS: OnceLock<Vec<SigningKey>> = OnceLock::new();
    KEYS.get_or_init(|| {
        let mut rng = StdRng::seed_from_u64(77);
        (0..2).map(|_| generate_node_key(&mut rng)).collect()
    })[n]
        .clone()
}

fn id_of(k: &SigningKey) -> NodeId {
    NodeId::from_public_key(&k.verifying_key())
}

/// Serveur minimal : chaque connexion acceptée publie `peer_node_id`, puis
/// une requête `Hello` reçoit sa réponse.
fn spawn_server(
    key: &SigningKey,
) -> (
    SocketAddr,
    mpsc::UnboundedReceiver<Option<NodeId>>,
    Endpoint,
) {
    spawn_server_with(key, None)
}

/// Comme `spawn_server`, mais `refuse` remplace la réponse à `Hello` : le
/// serveur l'envoie, attend l'accusé du client, puis ferme la connexion.
fn spawn_server_with(
    key: &SigningKey,
    refuse: Option<Response>,
) -> (
    SocketAddr,
    mpsc::UnboundedReceiver<Option<NodeId>>,
    Endpoint,
) {
    let cfg = tls::quinn_server_config(key);
    let ep = Endpoint::server(cfg, (Ipv4Addr::LOCALHOST, 0).into()).unwrap();
    let addr = ep.local_addr().unwrap();
    let (tx, rx) = mpsc::unbounded_channel();
    let node_id = id_of(key);
    let ep2 = ep.clone();
    tokio::spawn(async move {
        while let Some(incoming) = ep2.accept().await {
            let tx = tx.clone();
            let refuse = refuse.clone();
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                let _ = tx.send(tls::peer_node_id(&conn));
                while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                    let Ok(Request::Hello { .. }) =
                        frame::read::<Request>(&mut recv, MAX_REQUEST_BYTES).await
                    else {
                        return;
                    };
                    if let Some(r) = refuse {
                        let _ = frame::write(&mut send, &r, MAX_RESPONSE_BYTES).await;
                        let _ = send.finish();
                        let _ = send.stopped().await;
                        conn.close(0u32.into(), b"fin");
                        return;
                    }
                    let resp = Response::Hello {
                        version: PROTOCOL_VERSION,
                        min_version: 0,
                        node_id,
                        pow_bits: 8,
                        limits: Limits {
                            max_mailboxes_per_fetch: 8,
                            max_request_bytes: MAX_REQUEST_BYTES as u32,
                            max_response_bytes: MAX_RESPONSE_BYTES as u32,
                        },
                    };
                    let _ = frame::write(&mut send, &resp, MAX_RESPONSE_BYTES).await;
                    let _ = send.finish();
                }
            });
        }
    });
    (addr, rx, ep)
}

fn client_endpoint() -> Endpoint {
    Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).unwrap()
}

#[tokio::test]
async fn anonymous_client_has_no_peer_id() {
    let server = key(0);
    let (addr, mut seen, _ep) = spawn_server(&server);
    let _session = Client::connect(addr, id_of(&server)).await.unwrap();
    assert_eq!(seen.recv().await, Some(None));
}

#[tokio::test]
async fn node_client_is_identified() {
    let (server, caller) = (key(0), key(1));
    let (addr, mut seen, _ep) = spawn_server(&server);
    let ep = client_endpoint();
    let conn = client::connect_peer(&ep, addr, id_of(&server), &caller)
        .await
        .unwrap();
    assert_eq!(seen.recv().await, Some(Some(id_of(&caller))));
    // La connexion reste utilisable pour d'autres requêtes.
    let hello = Request::Hello {
        version: PROTOCOL_VERSION,
        min_version: 0,
    };
    assert!(matches!(
        client::request(&conn, &hello).await,
        Ok(Response::Hello { .. })
    ));
}

#[tokio::test]
async fn one_identity_serves_many_connections_and_reports_pow_bits() {
    let (server, caller) = (key(0), key(1));
    let (addr, mut seen, _ep) = spawn_server(&server);
    let ep = client_endpoint();
    let identity = tls::NodeIdentity::new(&caller);
    for _ in 0..2 {
        let (_conn, pow_bits) = client::connect_node(&ep, addr, id_of(&server), &identity)
            .await
            .unwrap();
        assert_eq!(pow_bits, 8);
        assert_eq!(seen.recv().await, Some(Some(id_of(&caller))));
    }
    // Identifiant épinglé différent : refusé avec la même identité.
    assert!(
        client::connect_node(&ep, addr, NodeId([3; 32]), &identity)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn node_client_with_bad_puzzle_is_refused() {
    let server = key(0);
    // Clé valide mais qui ne résout pas le puzzle de 20 bits.
    let weak = SigningKey::from_bytes(&[9; 32]);
    assert!(!id_of(&weak).puzzle_ok());
    let (addr, _seen, _ep) = spawn_server(&server);
    let ep = client_endpoint();
    let r = client::connect_peer(&ep, addr, id_of(&server), &weak).await;
    assert!(matches!(r, Err(ClientError::Connect(_))), "{:?}", r.err());
}

#[tokio::test]
async fn connect_peer_checks_server_identity() {
    let (server, caller) = (key(0), key(1));
    let (addr, _seen, _ep) = spawn_server(&server);
    let ep = client_endpoint();
    let r = client::connect_peer(&ep, addr, NodeId([3; 32]), &caller).await;
    assert!(matches!(r, Err(ClientError::Connect(_))), "{:?}", r.err());
}

#[tokio::test]
async fn connect_peer_reports_version_refusal_not_connect() {
    let (server, caller) = (key(0), key(1));
    let refuse = Response::Error(barking_proto::ErrorReason::VersionTooOld);
    let (addr, _seen, _ep) = spawn_server_with(&server, Some(refuse));
    let ep = client_endpoint();
    // Plusieurs essais : le résultat ne doit pas dépendre de la course entre
    // la réponse et la fermeture de la connexion.
    for _ in 0..5 {
        let r = client::connect_peer(&ep, addr, id_of(&server), &caller).await;
        assert!(matches!(r, Err(ClientError::Version)), "{:?}", r.err());
    }
}
