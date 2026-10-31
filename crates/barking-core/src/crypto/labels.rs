//! Domain separation labels.
//!
//! Every signature and every key derivation uses a label of the
//! form `b"barking/v0/<usage>"`, centralised here. Later tasks add
//! their own constants here.

/// Seed of the root identity derived from the entropy of the recovery phrase.
pub const ROOT_FROM_ENTROPY: &[u8] = b"barking/v0/root-from-entropy";

/// BLAKE3 context of the fingerprint of a public root key.
pub const FINGERPRINT_CONTEXT: &str = "barking/v0/fingerprint";

/// Safety code domain (hash of the two sorted fingerprints).
pub const SAFETY_NUMBER: &[u8] = b"barking/v0/safety-number";

/// Signature domain of the device certificate by the root.
pub const DEVICE_CERT: &[u8] = b"barking/v0/device-cert";

/// Proof of possession: the device signs its own certificate (root,
/// public keys, name, date) with its signing key.
pub const DEVICE_POSSESSION: &[u8] = b"barking/v0/device-possession";

/// Signature domain of the device list by the root.
pub const DEVICE_LIST: &[u8] = b"barking/v0/device-list";

/// BLAKE3 context of the device identifier.
pub const DEVICE_ID_CONTEXT: &str = "barking/v0/device-id";

/// Signature domain of a key bundle by the device.
pub const PREKEYS: &[u8] = b"barking/v0/prekeys";

/// Derivation of the PQXDH session key.
pub const PQXDH_SK: &[u8] = b"barking/v0/pqxdh-sk";

/// Derivation of the mailbox secret at session opening.
pub const PQXDH_MAILBOX: &[u8] = b"barking/v0/pqxdh-mailbox";

/// Initial header keys of the double ratchet (`shared_hka || shared_nhkb`).
pub const RATCHET_HK: &[u8] = b"barking/v0/ratchet-hk";

/// KDF_RK of the double ratchet : `RK' || CK || NHK`.
pub const RATCHET_RK: &[u8] = b"barking/v0/ratchet-rk";

/// Key and nonce of a message body, derived from the message key.
pub const RATCHET_MK: &[u8] = b"barking/v0/ratchet-mk";

/// Session mailbox domain (hash keyed by `mailbox_secret`).
pub const MAILBOX: &[u8] = b"barking/v0/mailbox";

/// BLAKE3 context of the introduction mailbox (first message).
pub const INTRO_MAILBOX_CONTEXT: &str = "barking/v0/intro-mailbox";

/// BLAKE3 context of the packet identifier derived from the acknowledgement secret.
pub use barking_packet::labels::ACK_CONTEXT;

/// Sealing of the initial message: `key(32) || nonce(12)` derived from
/// `DH(e_seal, IK_B)`, with an ephemeral key specific to each Initial packet.
pub const INITIAL_SEAL: &[u8] = b"barking/v0/initial-seal";

/// Signature domain of the contact card by the root.
pub const CONTACT_CARD: &[u8] = b"barking/v0/contact-card";

/// BLAKE3 context of the frame key: 8 bytes of the hash of the whole packet.
pub use barking_packet::labels::FRAME_CONTEXT;

/// BLAKE3 context of the MAC key of the link request (derived from the
/// link secret).
pub const LINK_MAC: &str = "barking/v0/link/mac";

/// BLAKE3 context of the key of the link bundle (derived from the link secret).
pub const LINK_BUNDLE: &str = "barking/v0/link/bundle";

/// BLAKE3 context of the key of the history archive (derived from the link secret).
pub const LINK_HISTORY: &str = "barking/v0/link/history";

/// BLAKE3 context of the stored identifier of a received message:
/// `derive_key(MESSAGE_ID_IN, sender fingerprint || envelope
/// identifier)[..16]`. The sender chooses the envelope identifier;
/// binding it to their fingerprint prevents them from reaching another sender's messages.
pub const MESSAGE_ID_IN: &str = "barking/v0/message-id/in";

/// Domain of the root's signature over the plaintext of the link bundle
/// (`BLAKE3(postcard(plaintext))`): only the administrator can produce it, not
/// a mere holder of the link secret.
pub const LINK_BUNDLE_SIG: &[u8] = b"barking/v0/link/bundle-sig";

/// Domain of the root's signature over the plaintext of the history archive
/// (`BLAKE3(postcard(entries))`).
pub const LINK_HISTORY_SIG: &[u8] = b"barking/v0/link/history-sig";
