//! ES256 provider tokens for APNs token-based authentication.

use data_encoding::BASE64URL_NOPAD;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};

/// Minimal JSON string escaping (identifiers are plain ASCII in practice).
fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Builds `base64url(header).base64url(claims).base64url(signature)` with the
/// raw 64-byte (r || s) ES256 signature APNs expects.
pub fn apns_jwt(team_id: &str, key_id: &str, key: &SigningKey, iat: u64) -> String {
    let header = format!(r#"{{"alg":"ES256","kid":{}}}"#, json_str(key_id));
    let claims = format!(r#"{{"iss":{},"iat":{iat}}}"#, json_str(team_id));
    let signing_input = format!(
        "{}.{}",
        BASE64URL_NOPAD.encode(header.as_bytes()),
        BASE64URL_NOPAD.encode(claims.as_bytes())
    );
    let sig: Signature = key.sign(signing_input.as_bytes());
    format!(
        "{signing_input}.{}",
        BASE64URL_NOPAD.encode(&sig.to_bytes())
    )
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, SigningKey};

    use super::*;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32].into()).unwrap()
    }

    #[test]
    fn jwt_has_three_parts_and_verifies() {
        let key = key();
        let jwt = apns_jwt("TEAM123456", "KEY1234567", &key, 1_700_000_000);
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert!(!jwt.contains('='), "base64url without padding");
        let dec = |s: &str| data_encoding::BASE64URL_NOPAD.decode(s.as_bytes()).unwrap();
        assert_eq!(
            String::from_utf8(dec(parts[0])).unwrap(),
            r#"{"alg":"ES256","kid":"KEY1234567"}"#
        );
        assert_eq!(
            String::from_utf8(dec(parts[1])).unwrap(),
            r#"{"iss":"TEAM123456","iat":1700000000}"#
        );
        let sig = dec(parts[2]);
        assert_eq!(sig.len(), 64, "raw r||s signature");
        let sig = Signature::from_slice(&sig).unwrap();
        let signed = format!("{}.{}", parts[0], parts[1]);
        key.verifying_key()
            .verify(signed.as_bytes(), &sig)
            .expect("signature verifies with the public key");
    }
}
