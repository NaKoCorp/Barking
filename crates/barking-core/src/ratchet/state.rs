//! Double ratchet state (Signal's "header encryption" variant, §4).

use super::header::{ENC_HEADER_LEN, Header, RatchetMessage};
use super::{MAX_SKIP, MAX_SKIPPED_AGE_SECS, MAX_SKIPPED_TOTAL};
use crate::crypto::aead::{open, seal};
use crate::crypto::kdf::{hkdf_sha256, hmac_sha256};
use crate::crypto::labels;
use crate::{CoreError, Result};
use core::fmt;
use rand_core::CryptoRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[cfg(test)]
thread_local! {
    /// Number of state copies made by `decrypt` on the current thread.
    /// Per thread (not global): tests run in parallel and
    /// measure differences without interfering with each other.
    pub(crate) static STATE_CLONES: core::cell::Cell<usize> =
        const { core::cell::Cell::new(0) };
}

/// Skipped message key, stored under the header key of its chain.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub(super) struct SkippedKey {
    pub hk: [u8; 32],
    pub n: u32,
    pub mk: [u8; 32],
    /// Set aside (Unix seconds, recipient's clock).
    pub stored_at: u64,
}

/// State of a double ratchet session.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct RatchetState {
    pub(super) dhs: Option<[u8; 32]>,
    pub(super) dhr: Option<[u8; 32]>,
    pub(super) rk: [u8; 32],
    pub(super) cks: Option<[u8; 32]>,
    pub(super) ckr: Option<[u8; 32]>,
    pub(super) hks: Option<[u8; 32]>,
    pub(super) hkr: Option<[u8; 32]>,
    pub(super) nhks: [u8; 32],
    pub(super) nhkr: [u8; 32],
    pub(super) ns: u32,
    pub(super) nr: u32,
    pub(super) pn: u32,
    pub(super) mkskipped: Vec<SkippedKey>,
}

impl fmt::Debug for RatchetState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Counters only: no key appears.
        f.debug_struct("RatchetState")
            .field("ns", &self.ns)
            .field("nr", &self.nr)
            .field("pn", &self.pn)
            .field("skipped", &self.mkskipped.len())
            .finish_non_exhaustive()
    }
}

impl RatchetState {
    /// RatchetInitAliceHE: the initiator immediately performs the sending DH step
    /// towards the responder's signed key (`their_spk`).
    pub fn init_initiator(
        sk: &[u8; 32],
        their_spk: [u8; 32],
        rng: &mut impl CryptoRng,
    ) -> Result<Self> {
        let (hka, nhkb) = initial_header_keys(sk)?;
        let mut s = RatchetState {
            dhs: None,
            dhr: Some(their_spk),
            rk: *sk,
            cks: None,
            ckr: None,
            hks: Some(hka),
            hkr: None,
            nhks: [0u8; 32],
            nhkr: nhkb,
            ns: 0,
            nr: 0,
            pn: 0,
            mkskipped: Vec::new(),
        };
        s.send_ratchet(rng)?;
        Ok(s)
    }

    /// RatchetInitBobHE: the responder's initial DH pair is its signed key.
    pub fn init_responder(sk: &[u8; 32], our_spk: &StaticSecret) -> Self {
        // Internal invariant: HKDF-SHA256 over 64 bytes cannot fail
        // (limit: 255 * 32 bytes), whatever the input.
        let (hka, nhkb) = initial_header_keys(sk).expect("64-byte HKDF");
        RatchetState {
            dhs: Some(our_spk.to_bytes()),
            dhr: None,
            rk: *sk,
            cks: None,
            ckr: None,
            hks: None,
            hkr: None,
            nhks: nhkb,
            nhkr: hka,
            ns: 0,
            nr: 0,
            pn: 0,
            mkskipped: Vec::new(),
        }
    }

    /// RatchetEncryptHE. The responder cannot send before having received
    /// a first message (`NoSession`).
    pub fn encrypt(
        &mut self,
        pt: &[u8],
        ad: &[u8],
        rng: &mut impl CryptoRng,
    ) -> Result<RatchetMessage> {
        if self.cks.is_none() {
            // "Send" half of DHRatchetHE, deferred from reception.
            self.send_ratchet(rng)?;
        }
        let (Some(cks), Some(hks), Some(dhs)) = (&self.cks, &self.hks, &self.dhs) else {
            return Err(CoreError::NoSession);
        };
        let next_ns = self.ns.checked_add(1).ok_or(CoreError::TooLarge)?;
        let (ck, mk) = kdf_ck(cks);
        let header = Header {
            dh: PublicKey::from(&StaticSecret::from(*dhs)).to_bytes(),
            pn: self.pn,
            n: self.ns,
        };
        let enc_header = header.seal(hks, rng);
        let ct = seal_body(&mk, ad, &enc_header, pt)?;
        self.cks = Some(*ck);
        self.ns = next_ns;
        Ok(RatchetMessage { enc_header, ct })
    }

    /// RatchetDecryptHE, transactional: on failure, `self` is unchanged.
    ///
    /// `now` (Unix seconds) dates the skipped keys; those set aside
    /// for more than `MAX_SKIPPED_AGE_SECS` are erased before any attempt.
    pub fn decrypt(&mut self, msg: &RatchetMessage, ad: &[u8], now: u64) -> Result<Vec<u8>> {
        #[cfg(test)]
        STATE_CLONES.with(|c| c.set(c.get() + 1));
        let mut next = self.clone();
        let pt = next.decrypt_in_place(msg, ad, now)?;
        // The old state is erased on drop (`ZeroizeOnDrop`).
        *self = next;
        Ok(pt)
    }

    /// Cheap pre-check: the encrypted header has the right size and
    /// opens with a skipped header key, `hkr` or `nhkr` (mirror of the
    /// header checks of `decrypt`, without the purge by date: `decrypt`
    /// decides). Neither copies nor modifies.
    pub(crate) fn could_open(&self, msg: &RatchetMessage) -> bool {
        let enc = &msg.enc_header;
        if enc.len() != ENC_HEADER_LEN {
            return false;
        }
        // Capacity fixed in advance: no reallocation leaves an unerased
        // copy of the header keys.
        let mut tried: Vec<[u8; 32]> = Vec::with_capacity(self.mkskipped.len());
        let mut skipped_ok = false;
        for entry in &self.mkskipped {
            if tried.contains(&entry.hk) {
                continue;
            }
            tried.push(entry.hk);
            if Header::open(&entry.hk, enc).is_ok() {
                skipped_ok = true;
                break;
            }
        }
        tried.zeroize();
        skipped_ok || self.decrypt_header(enc).is_ok()
    }

    fn decrypt_in_place(&mut self, msg: &RatchetMessage, ad: &[u8], now: u64) -> Result<Vec<u8>> {
        if msg.enc_header.len() != ENC_HEADER_LEN {
            return Err(CoreError::Malformed("encrypted header size"));
        }
        self.purge_skipped(now);
        if let Some(pt) = self.try_skipped_message_keys(msg, ad)? {
            return Ok(pt);
        }
        let (header, dh_ratchet) = self.decrypt_header(&msg.enc_header)?;
        if dh_ratchet {
            self.skip_message_keys(header.pn, now)?;
            self.receive_ratchet(&header)?;
        }
        if header.n < self.nr {
            // Message already decrypted (replay) or skipped key evicted.
            return Err(CoreError::Crypto);
        }
        self.skip_message_keys(header.n, now)?;
        let ckr = self.ckr.ok_or(CoreError::Crypto)?;
        let (ck, mk) = kdf_ck(&ckr);
        self.ckr = Some(*ck);
        self.nr = self.nr.checked_add(1).ok_or(CoreError::TooLarge)?;
        open_body(&mk, ad, &msg.enc_header, &msg.ct)
    }

    /// TrySkippedMessageKeysHE. Each distinct header key is tried
    /// only once (skipped keys are grouped by chain).
    fn try_skipped_message_keys(
        &mut self,
        msg: &RatchetMessage,
        ad: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        // Capacity fixed in advance: no reallocation leaves an unerased
        // copy of the header keys.
        let mut tried: Vec<[u8; 32]> = Vec::with_capacity(self.mkskipped.len());
        let mut found = None;
        for entry in &self.mkskipped {
            if tried.contains(&entry.hk) {
                continue;
            }
            tried.push(entry.hk);
            if let Ok(header) = Header::open(&entry.hk, &msg.enc_header) {
                found = Some((entry.hk, header.n));
                break;
            }
        }
        tried.zeroize();
        let Some((hk, n)) = found else {
            return Ok(None);
        };
        let Some(pos) = self.mkskipped.iter().position(|e| e.hk == hk && e.n == n) else {
            // Right header key but number absent: what follows decides (replay,
            // message of the current chain).
            return Ok(None);
        };
        let entry = self.mkskipped.remove(pos);
        open_body(&entry.mk, ad, &msg.enc_header, &msg.ct).map(Some)
    }

    /// DecryptHeader: HKr first, then NHKr (which announces a DH step).
    fn decrypt_header(&self, enc: &[u8]) -> Result<(Header, bool)> {
        if let Some(hkr) = &self.hkr
            && let Ok(h) = Header::open(hkr, enc)
        {
            return Ok((h, false));
        }
        Header::open(&self.nhkr, enc)
            .map(|h| (h, true))
            .map_err(|_| CoreError::Crypto)
    }

    /// Erases the skipped keys set aside for more than
    /// `MAX_SKIPPED_AGE_SECS` (a clock that went backwards erases nothing).
    /// Returns true if at least one key was removed.
    pub(crate) fn purge_skipped(&mut self, now: u64) -> bool {
        let before = self.mkskipped.len();
        // Removed elements are erased on drop.
        self.mkskipped
            .retain(|k| now.saturating_sub(k.stored_at) <= MAX_SKIPPED_AGE_SECS);
        self.mkskipped.len() != before
    }

    /// Number of skipped keys held in reserve (tests).
    #[cfg(test)]
    pub(crate) fn skipped_len(&self) -> usize {
        self.mkskipped.len()
    }

    /// SkipMessageKeysHE: at most `MAX_SKIP` keys ahead in the chain.
    fn skip_message_keys(&mut self, until: u32, now: u64) -> Result<()> {
        if u64::from(self.nr) + u64::from(MAX_SKIP) < u64::from(until) {
            return Err(CoreError::TooLarge);
        }
        let (Some(mut ckr), Some(hkr)) = (self.ckr, self.hkr) else {
            return Ok(());
        };
        while self.nr < until {
            let (ck, mk) = kdf_ck(&ckr);
            ckr = *ck;
            self.push_skipped(SkippedKey {
                hk: hkr,
                n: self.nr,
                mk: *mk,
                stored_at: now,
            });
            self.nr += 1;
        }
        self.ckr = Some(ckr);
        ckr.zeroize();
        Ok(())
    }

    /// Adds a skipped key, evicts the oldest beyond
    /// `MAX_SKIPPED_TOTAL`, without leaving an unerased copy in memory.
    fn push_skipped(&mut self, key: SkippedKey) {
        if self.mkskipped.len() == self.mkskipped.capacity() {
            // Manual reallocation: the old buffer is erased before being freed.
            let cap = (self.mkskipped.capacity() * 2).clamp(16, MAX_SKIPPED_TOTAL + 1);
            let mut grown = Vec::with_capacity(cap.max(self.mkskipped.len() + 1));
            grown.extend(self.mkskipped.iter().cloned());
            self.mkskipped.zeroize();
            self.mkskipped = grown;
        }
        self.mkskipped.push(key);
        if self.mkskipped.len() > MAX_SKIPPED_TOTAL {
            let excess = self.mkskipped.len() - MAX_SKIPPED_TOTAL;
            // Removed elements are erased on drop.
            self.mkskipped.drain(..excess);
        }
    }

    /// "Receive" half of DHRatchetHE. The old `DHs` private key is
    /// erased; the new one will be drawn at the next `encrypt`.
    fn receive_ratchet(&mut self, header: &Header) -> Result<()> {
        // Without `DHs`, the peer cannot have performed a legitimate DH step.
        let dhs = self.dhs.as_ref().ok_or(CoreError::Crypto)?;
        let shared = dh(dhs, &header.dh)?;
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.hks = Some(self.nhks);
        self.hkr = Some(self.nhkr);
        self.dhr = Some(header.dh);
        let (rk, ckr, nhkr) = kdf_rk(&self.rk, &shared)?;
        self.rk = rk;
        self.ckr = Some(ckr);
        self.nhkr = nhkr;
        self.cks = None;
        if let Some(mut old) = self.dhs.take() {
            old.zeroize();
        }
        Ok(())
    }

    /// "Send" half of DHRatchetHE: new DH pair, then KDF_RK.
    fn send_ratchet(&mut self, rng: &mut impl CryptoRng) -> Result<()> {
        let dhr = self.dhr.ok_or(CoreError::NoSession)?;
        let mut fresh = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(fresh.as_mut());
        let shared = dh(&fresh, &dhr)?;
        let (rk, cks, nhks) = kdf_rk(&self.rk, &shared)?;
        self.rk = rk;
        self.cks = Some(cks);
        self.nhks = nhks;
        self.dhs = Some(*fresh);
        Ok(())
    }
}

/// Initial header keys: `shared_hka || shared_nhkb`.
fn initial_header_keys(sk: &[u8; 32]) -> Result<([u8; 32], [u8; 32])> {
    let mut okm = Zeroizing::new([0u8; 64]);
    hkdf_sha256(None, sk, labels::RATCHET_HK, okm.as_mut())?;
    Ok((split32(&okm[..32]), split32(&okm[32..])))
}

/// X25519, rejecting an all-zero output (weak-order point).
fn dh(secret: &[u8; 32], public: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    let shared = StaticSecret::from(*secret).diffie_hellman(&PublicKey::from(*public));
    if !shared.was_contributory() {
        return Err(CoreError::Crypto);
    }
    Ok(Zeroizing::new(shared.to_bytes()))
}

/// KDF_RK : `HKDF(salt = RK, ikm = dh_out, RATCHET_RK)` → `RK' || CK || NHK`.
fn kdf_rk(rk: &[u8; 32], dh_out: &[u8; 32]) -> Result<([u8; 32], [u8; 32], [u8; 32])> {
    let mut okm = Zeroizing::new([0u8; 96]);
    hkdf_sha256(Some(rk), dh_out, labels::RATCHET_RK, okm.as_mut())?;
    Ok((
        split32(&okm[..32]),
        split32(&okm[32..64]),
        split32(&okm[64..]),
    ))
}

/// KDF_CK : `MK = HMAC(CK, 0x01)`, `CK' = HMAC(CK, 0x02)`. Returns `(CK', MK)`.
fn kdf_ck(ck: &[u8; 32]) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    let mk = Zeroizing::new(hmac_sha256(ck, &[0x01]));
    let next = Zeroizing::new(hmac_sha256(ck, &[0x02]));
    (next, mk)
}

/// Body key and nonce: `HKDF(None, MK, RATCHET_MK)` → 44 bytes.
fn body_key(mk: &[u8; 32]) -> Result<(Zeroizing<[u8; 32]>, [u8; 12])> {
    let mut okm = Zeroizing::new([0u8; 44]);
    hkdf_sha256(None, mk, labels::RATCHET_MK, okm.as_mut())?;
    let key = Zeroizing::new(split32(&okm[..32]));
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&okm[32..]);
    Ok((key, nonce))
}

fn body_ad(ad: &[u8], enc_header: &[u8]) -> Vec<u8> {
    let mut full = Vec::with_capacity(ad.len() + enc_header.len());
    full.extend_from_slice(ad);
    full.extend_from_slice(enc_header);
    full
}

fn seal_body(mk: &[u8; 32], ad: &[u8], enc_header: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
    let (key, nonce) = body_key(mk)?;
    Ok(seal(&key, &nonce, &body_ad(ad, enc_header), pt))
}

fn open_body(mk: &[u8; 32], ad: &[u8], enc_header: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
    let (key, nonce) = body_key(mk)?;
    open(&key, &nonce, &body_ad(ad, enc_header), ct)
}

/// Copies a 32-byte slice (callers always pass 32 bytes).
fn split32(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    out
}
