//! TLS 1.3 à identité épinglée (spec §3.2).
//!
//! - Le nœud présente un certificat X.509 autosigné qui porte sa clé Ed25519.
//! - Le client n'utilise aucune autorité de certification : il accepte le
//!   certificat seulement si sa clé donne l'identifiant attendu et que cet
//!   identifiant résout le puzzle. La signature de la poignée de main TLS est
//!   vérifiée avec cette même clé : un certificat copié sans la clé privée est
//!   refusé.
//! - Le client n'envoie pas de SNI. Un client anonyme ne présente aucun
//!   certificat ; un nœud appelant présente le sien (autosigné, Ed25519, clé
//!   qui résout le puzzle), que le serveur accepte sans l'exiger.
//!
//! Fournisseur cryptographique : `ring` (pas d'aws-lc : ni cmake ni NASM, build
//! musl et reproductible plus simple). Le même fournisseur sert au client et
//! au nœud.

use std::sync::Arc;

use ed25519_dalek::{SigningKey, VerifyingKey};
use rustls::DistinguishedName;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{CertificateError, DigitallySignedStruct, SignatureScheme};
use zeroize::Zeroizing;

use crate::{ALPN, NodeId};

/// En-tête DER d'une clé privée Ed25519 PKCS#8 v1 (RFC 8410), suivi de la graine.
const PKCS8_ED25519_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];
/// En-tête DER d'une `SubjectPublicKeyInfo` Ed25519 (RFC 8410), suivi de la clé.
const SPKI_ED25519_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
/// Nom interne du certificat (ignoré par le vérificateur, jamais envoyé en SNI).
pub const CERT_NAME: &str = "barking-node";

/// Seuls les algorithmes Ed25519 sont acceptés pour la signature TLS.
static ED25519_ONLY: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[webpki::ring::ED25519],
    mapping: &[(SignatureScheme::ED25519, &[webpki::ring::ED25519])],
};

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Clé privée du nœud encodée en PKCS#8 v1 (DER).
pub fn pkcs8_der(key: &SigningKey) -> Zeroizing<Vec<u8>> {
    let mut der = Zeroizing::new(Vec::with_capacity(48));
    der.extend_from_slice(&PKCS8_ED25519_PREFIX);
    der.extend_from_slice(key.as_bytes());
    der
}

/// Certificat autosigné portant la clé Ed25519 du nœud.
pub fn self_signed_cert(key: &SigningKey) -> CertificateDer<'static> {
    let der = pkcs8_der(key);
    // Entrées construites ici (clé Ed25519 valide, nom fixe) : ces appels ne
    // dépendent d'aucun octet venu du réseau.
    let kp = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
        &PrivatePkcs8KeyDer::from(&der[..]),
        &rcgen::PKCS_ED25519,
    )
    .expect("clé Ed25519 PKCS#8 valide");
    rcgen::CertificateParams::new(vec![CERT_NAME.to_string()])
        .expect("nom de certificat valide")
        .self_signed(&kp)
        .expect("signature du certificat")
        .der()
        .clone()
}

/// Configuration TLS du nœud : TLS 1.3 seul, ALPN `barking/0`, certificat
/// client optionnel (un nœud appelant peut s'identifier, un client non).
pub fn server_config(key: &SigningKey) -> rustls::ServerConfig {
    let cert = self_signed_cert(key);
    let der = pkcs8_der(key);
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 pris en charge par ring")
        .with_client_cert_verifier(Arc::new(PeerNode))
        .with_single_cert(
            vec![cert],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der.to_vec())),
        )
        .expect("certificat et clé cohérents");
    cfg.alpn_protocols = vec![ALPN.to_vec()];
    cfg
}

/// Configuration QUIC du nœud (transport par défaut ; le serveur l'ajuste).
pub fn quinn_server_config(key: &SigningKey) -> quinn::ServerConfig {
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(server_config(key))
        .expect("suite TLS 1.3 initiale disponible");
    quinn::ServerConfig::with_crypto(Arc::new(crypto))
}

/// Configuration TLS du client, épinglée sur `expected`.
pub fn client_config(expected: NodeId) -> rustls::ClientConfig {
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 pris en charge par ring")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedNode { expected }))
        .with_no_client_auth();
    cfg.alpn_protocols = vec![ALPN.to_vec()];
    cfg.enable_sni = false;
    cfg
}

/// Configuration TLS d'un nœud appelant : même épinglage que `client_config`,
/// plus le certificat autosigné de `key` pour s'identifier auprès du serveur.
pub fn node_client_config(expected: NodeId, key: &SigningKey) -> rustls::ClientConfig {
    let der = pkcs8_der(key);
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 pris en charge par ring")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedNode { expected }))
        .with_client_auth_cert(
            vec![self_signed_cert(key)],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der.to_vec())),
        )
        .expect("certificat et clé cohérents");
    cfg.alpn_protocols = vec![ALPN.to_vec()];
    cfg.enable_sni = false;
    cfg
}

/// Identifiant du nœud appelant, si la connexion porte un certificat client
/// (déjà validé par la poignée de main) dont la clé résout le puzzle.
pub fn peer_node_id(conn: &quinn::Connection) -> Option<NodeId> {
    let identity = conn.peer_identity()?;
    let certs = identity.downcast::<Vec<CertificateDer<'static>>>().ok()?;
    let [cert] = certs.as_slice() else {
        return None;
    };
    let id = NodeId::from_public_key(&node_key_from_cert(cert)?);
    id.puzzle_ok().then_some(id)
}

/// Clé Ed25519 portée par un certificat, si c'en est une.
pub fn node_key_from_cert(cert: &CertificateDer<'_>) -> Option<VerifyingKey> {
    let ee = webpki::EndEntityCert::try_from(cert).ok()?;
    let spki = ee.subject_public_key_info();
    let raw = spki.as_ref().strip_prefix(&SPKI_ED25519_PREFIX[..])?;
    let bytes: [u8; 32] = raw.try_into().ok()?;
    VerifyingKey::from_bytes(&bytes).ok()
}

/// Vérificateur épinglé : identifiant attendu + puzzle + signature TLS.
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
        // Seul TLS 1.3 est négocié ; TLS 1.2 n'est jamais accepté.
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
        // `cert` est le certificat déjà accepté par `verify_server_cert` :
        // la signature est vérifiée avec la clé épinglée.
        rustls::crypto::verify_tls13_signature(message, cert, dss, &ED25519_ONLY)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

/// Vérificateur de certificat client : optionnel, mais s'il est présenté,
/// Ed25519 seul, clé qui résout le puzzle, signature TLS vérifiée.
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
        // Aucune autorité : pas d'indice à envoyer.
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
        // Bon identifiant mais puzzle non résolu : refusé.
        assert!(!id.puzzle_ok());
        assert!(check(id).is_err());
        // Autre identifiant : refusé.
        assert!(check(NodeId([0; 32])).is_err());
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
