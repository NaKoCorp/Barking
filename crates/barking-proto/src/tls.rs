//! TLS 1.3 with pinned identity (spec §3.2).
//!
//! - The node presents a self-signed X.509 certificate carrying its Ed25519 key.
//! - The client uses no certificate authority: it accepts the
//!   certificate only if its key yields the expected identifier and that
//!   identifier solves the puzzle. The TLS handshake signature is
//!   verified with that same key: a certificate copied without the private key is
//!   rejected.
//! - The client sends no SNI. An anonymous client presents no
//!   certificate; a calling node presents its own (self-signed, Ed25519, key
//!   that solves the puzzle), which the server accepts without requiring it.
//!
//! Cryptographic provider: `ring` (no aws-lc: no cmake or NASM, simpler musl
//! and reproducible build). The same provider serves the client and
//! the node.

use std::sync::Arc;

use ed25519_dalek::{SigningKey, VerifyingKey};
use rustls::DistinguishedName;
use rustls::client::ResolvesClientCert;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::sign::CertifiedKey;
use rustls::{CertificateError, DigitallySignedStruct, SignatureScheme};
use zeroize::Zeroizing;

use crate::{ALPN, NodeId};

/// DER header of an Ed25519 PKCS#8 v1 private key (RFC 8410), followed by the seed.
const PKCS8_ED25519_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];
/// DER header of an Ed25519 `SubjectPublicKeyInfo` (RFC 8410), followed by the key.
const SPKI_ED25519_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
/// Internal name of the certificate (ignored by the verifier, never sent as SNI).
pub const CERT_NAME: &str = "barking-node";

/// Only Ed25519 algorithms are accepted for the TLS signature.
static ED25519_ONLY: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[webpki::ring::ED25519],
    mapping: &[(SignatureScheme::ED25519, &[webpki::ring::ED25519])],
};

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Node private key encoded as PKCS#8 v1 (DER).
pub fn pkcs8_der(key: &SigningKey) -> Zeroizing<Vec<u8>> {
    let mut der = Zeroizing::new(Vec::with_capacity(48));
    der.extend_from_slice(&PKCS8_ED25519_PREFIX);
    der.extend_from_slice(key.as_bytes());
    der
}

/// Self-signed certificate carrying the node's Ed25519 key.
pub fn self_signed_cert(key: &SigningKey) -> CertificateDer<'static> {
    let der = pkcs8_der(key);
    // Inputs built here (valid Ed25519 key, fixed name): these calls do not
    // depend on any byte coming from the network.
    let kp = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
        &PrivatePkcs8KeyDer::from(&der[..]),
        &rcgen::PKCS_ED25519,
    )
    .expect("valid Ed25519 PKCS#8 key");
    rcgen::CertificateParams::new(vec![CERT_NAME.to_string()])
        .expect("valid certificate name")
        .self_signed(&kp)
        .expect("certificate signature")
        .der()
        .clone()
}

/// TLS configuration of the node: TLS 1.3 only, ALPN `barking/0`, optional
/// client certificate (a calling node may identify itself, a client need not).
pub fn server_config(key: &SigningKey) -> rustls::ServerConfig {
    let cert = self_signed_cert(key);
    let der = pkcs8_der(key);
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 supported by ring")
        .with_client_cert_verifier(Arc::new(PeerNode))
        .with_single_cert(
            vec![cert],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der.to_vec())),
        )
        .expect("consistent certificate and key");
    cfg.alpn_protocols = vec![ALPN.to_vec()];
    cfg
}

/// QUIC configuration of the node (default transport; the server adjusts it).
pub fn quinn_server_config(key: &SigningKey) -> quinn::ServerConfig {
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(server_config(key))
        .expect("initial TLS 1.3 suite available");
    quinn::ServerConfig::with_crypto(Arc::new(crypto))
}

/// TLS configuration of the client, pinned on `expected`.
pub fn client_config(expected: NodeId) -> rustls::ClientConfig {
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 supported by ring")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedNode { expected }))
        .with_no_client_auth();
    cfg.alpn_protocols = vec![ALPN.to_vec()];
    cfg.enable_sni = false;
    cfg
}

/// TLS identity of a calling node: self-signed certificate and signing
/// key, built once and shared by all its outgoing
/// connections. The DER copy of the seed used to build it is erased
/// immediately.
#[derive(Clone, Debug)]
pub struct NodeIdentity {
    certified: Arc<CertifiedKey>,
}

impl NodeIdentity {
    pub fn new(key: &SigningKey) -> NodeIdentity {
        let der = pkcs8_der(key);
        // Input built here (valid Ed25519 key): no byte from the network.
        let signer =
            rustls::crypto::ring::sign::any_eddsa_type(&PrivatePkcs8KeyDer::from(&der[..]))
                .expect("valid Ed25519 PKCS#8 key");
        NodeIdentity {
            certified: Arc::new(CertifiedKey::new(vec![self_signed_cert(key)], signer)),
        }
    }
}

impl ResolvesClientCert for NodeIdentity {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.certified))
    }

    fn has_certs(&self) -> bool {
        true
    }
}

/// TLS configuration of a calling node: same pinning as `client_config`,
/// plus the self-signed certificate of `key` to identify itself to the server.
pub fn node_client_config(expected: NodeId, key: &SigningKey) -> rustls::ClientConfig {
    node_client_config_for(expected, &NodeIdentity::new(key))
}

/// Like `node_client_config`, with an already-built identity: only
/// the pinned identifier changes from one connection to the next.
pub fn node_client_config_for(expected: NodeId, identity: &NodeIdentity) -> rustls::ClientConfig {
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 supported by ring")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedNode { expected }))
        .with_client_cert_resolver(Arc::new(identity.clone()));
    cfg.alpn_protocols = vec![ALPN.to_vec()];
    cfg.enable_sni = false;
    cfg
}

/// Identifier of the calling node, if the connection carries a client certificate
/// (already validated by the handshake) whose key solves the puzzle.
pub fn peer_node_id(conn: &quinn::Connection) -> Option<NodeId> {
    let identity = conn.peer_identity()?;
    let certs = identity.downcast::<Vec<CertificateDer<'static>>>().ok()?;
    let [cert] = certs.as_slice() else {
        return None;
    };
    let id = NodeId::from_public_key(&node_key_from_cert(cert)?);
    id.puzzle_ok().then_some(id)
}

/// Ed25519 key carried by a certificate, if it is one.
pub fn node_key_from_cert(cert: &CertificateDer<'_>) -> Option<VerifyingKey> {
    let ee = webpki::EndEntityCert::try_from(cert).ok()?;
    let spki = ee.subject_public_key_info();
    let raw = spki.as_ref().strip_prefix(&SPKI_ED25519_PREFIX[..])?;
    let bytes: [u8; 32] = raw.try_into().ok()?;
    VerifyingKey::from_bytes(&bytes).ok()
}

/// Pinned verifier: expected identifier + puzzle + TLS signature.
#[derive(Debug)]
struct PinnedNode {
    expected: NodeId,
}

impl ServerCertVerifier for PinnedNode {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if !intermediates.is_empty() {
            return Err(CertificateError::ApplicationVerificationFailure.into());
        }
        let key = node_key_from_cert(end_entity).ok_or(CertificateError::BadEncoding)?;
        let id = NodeId::from_public_key(&key);
        if id != self.expected || !id.puzzle_ok() {
            return Err(CertificateError::ApplicationVerificationFailure.into());
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // Only TLS 1.3 is negotiated; TLS 1.2 is never accepted.
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // `cert` is the certificate already accepted by `verify_server_cert`:
        // the signature is verified with the pinned key.
        rustls::crypto::verify_tls13_signature(message, cert, dss, &ED25519_ONLY)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

/// Client certificate verifier: optional, but if presented,
/// Ed25519 only, key that solves the puzzle, TLS signature verified.
#[derive(Debug)]
struct PeerNode;

impl ClientCertVerifier for PeerNode {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        // No authority: no hint to send.
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        if !intermediates.is_empty() {
            return Err(CertificateError::ApplicationVerificationFailure.into());
        }
        let key = node_key_from_cert(end_entity).ok_or(CertificateError::BadEncoding)?;
        if !NodeId::from_public_key(&key).puzzle_ok() {
            return Err(CertificateError::ApplicationVerificationFailure.into());
        }
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &ED25519_ONLY)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cert_carries_node_key() {
        let k = SigningKey::from_bytes(&[5; 32]);
        let cert = self_signed_cert(&k);
        assert_eq!(node_key_from_cert(&cert), Some(k.verifying_key()));
        assert_eq!(
            node_key_from_cert(&CertificateDer::from(vec![1, 2, 3])),
            None
        );
    }

    #[test]
    fn verifier_checks_id_and_puzzle() {
        let k = SigningKey::from_bytes(&[5; 32]);
        let cert = self_signed_cert(&k);
        let id = NodeId::from_public_key(&k.verifying_key());
        let name = ServerName::try_from(CERT_NAME).unwrap();
        let check = |expected| {
            PinnedNode { expected }.verify_server_cert(&cert, &[], &name, &[], UnixTime::now())
        };
        // Right identifier but unsolved puzzle: rejected.
        assert!(!id.puzzle_ok());
        assert!(check(id).is_err());
        // Other identifier: rejected.
        assert!(check(NodeId([0; 32])).is_err());
    }

    /// Key whose identifier solves the puzzle (seed drawn once with
    /// `generate_node_key` in optimized mode).
    fn puzzle_key() -> SigningKey {
        SigningKey::from_bytes(&[
            2, 175, 79, 102, 56, 164, 4, 76, 174, 101, 223, 131, 29, 124, 100, 133, 164, 220, 15,
            194, 250, 40, 224, 152, 37, 232, 123, 107, 239, 175, 170, 96,
        ])
    }

    #[test]
    fn client_cert_with_intermediates_is_refused() {
        let cert = self_signed_cert(&puzzle_key());
        let check = |chain: &[CertificateDer<'_>]| {
            PeerNode.verify_client_cert(&cert, chain, UnixTime::now())
        };
        assert!(check(&[]).is_ok());
        let other = self_signed_cert(&SigningKey::from_bytes(&[7; 32]));
        assert!(check(&[other]).is_err());
        assert!(check(std::slice::from_ref(&cert)).is_err());
    }

    #[test]
    fn non_ed25519_client_cert_is_refused() {
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = rcgen::CertificateParams::new(vec![CERT_NAME.to_string()])
            .unwrap()
            .self_signed(&kp)
            .unwrap()
            .der()
            .clone();
        assert_eq!(node_key_from_cert(&cert), None);
        assert!(
            PeerNode
                .verify_client_cert(&cert, &[], UnixTime::now())
                .is_err()
        );
    }

    #[test]
    fn configs_build() {
        let k = SigningKey::from_bytes(&[6; 32]);
        let s = server_config(&k);
        assert_eq!(s.alpn_protocols, vec![ALPN.to_vec()]);
        let c = client_config(NodeId([1; 32]));
        assert!(!c.enable_sni);
        assert_eq!(c.alpn_protocols, vec![ALPN.to_vec()]);
        let _ = quinn_server_config(&k);
    }
}
