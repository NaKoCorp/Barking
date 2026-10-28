//! État du double ratchet (variante « header encryption » de Signal, §4).

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

/// Clé de message sautée, rangée sous la clé d'en-tête de sa chaîne.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub(super) struct SkippedKey {
    pub hk: [u8; 32],
    pub n: u32,
    pub mk: [u8; 32],
    /// Mise de côté (secondes Unix, horloge du destinataire).
    pub stored_at: u64,
}

/// État d'une session de double ratchet.
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
        // Compteurs seulement : aucune clé n'apparaît.
        f.debug_struct("RatchetState")
            .field("ns", &self.ns)
            .field("nr", &self.nr)
            .field("pn", &self.pn)
            .field("skipped", &self.mkskipped.len())
            .finish_non_exhaustive()
    }
}

impl RatchetState {
    /// RatchetInitAliceHE : l'initiateur fait tout de suite l'étape DH d'envoi
    /// vers la clé signée du répondeur (`their_spk`).
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

    /// RatchetInitBobHE : la paire DH initiale du répondeur est sa clé signée.
    pub fn init_responder(sk: &[u8; 32], our_spk: &StaticSecret) -> Self {
        // Invariant interne : HKDF-SHA256 sur 64 octets ne peut pas échouer
        // (limite : 255 * 32 octets), quelle que soit l'entrée.
        let (hka, nhkb) = initial_header_keys(sk).expect("HKDF de 64 octets");
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

    /// RatchetEncryptHE. Le répondeur ne peut pas émettre avant d'avoir reçu
    /// un premier message (`NoSession`).
    pub fn encrypt(
        &mut self,
        pt: &[u8],
        ad: &[u8],
        rng: &mut impl CryptoRng,
    ) -> Result<RatchetMessage> {
        if self.cks.is_none() {
            // Moitié « envoi » de DHRatchetHE, reportée depuis la réception.
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

    /// RatchetDecryptHE, transactionnelle : en cas d'échec, `self` est inchangé.
    ///
    /// `now` (secondes Unix) date les clés sautées ; celles mises de côté
    /// depuis plus de `MAX_SKIPPED_AGE_SECS` sont effacées avant tout essai.
    pub fn decrypt(&mut self, msg: &RatchetMessage, ad: &[u8], now: u64) -> Result<Vec<u8>> {
        let mut next = self.clone();
        let pt = next.decrypt_in_place(msg, ad, now)?;
        // L'ancien état est effacé à la destruction (`ZeroizeOnDrop`).
        *self = next;
        Ok(pt)
    }

    fn decrypt_in_place(&mut self, msg: &RatchetMessage, ad: &[u8], now: u64) -> Result<Vec<u8>> {
        if msg.enc_header.len() != ENC_HEADER_LEN {
            return Err(CoreError::Malformed("taille de l'en-tête chiffré"));
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
            // Message déjà déchiffré (rejeu) ou clé sautée évincée.
            return Err(CoreError::Crypto);
        }
        self.skip_message_keys(header.n, now)?;
        let ckr = self.ckr.ok_or(CoreError::Crypto)?;
        let (ck, mk) = kdf_ck(&ckr);
        self.ckr = Some(*ck);
        self.nr = self.nr.checked_add(1).ok_or(CoreError::TooLarge)?;
        open_body(&mk, ad, &msg.enc_header, &msg.ct)
    }

    /// TrySkippedMessageKeysHE. Chaque clé d'en-tête distincte n'est essayée
    /// qu'une fois (les clés sautées sont groupées par chaîne).
    fn try_skipped_message_keys(
        &mut self,
        msg: &RatchetMessage,
        ad: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        let mut tried: Vec<[u8; 32]> = Vec::new();
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
            // Bonne clé d'en-tête mais numéro absent : la suite décide (rejeu,
            // message de la chaîne courante).
            return Ok(None);
        };
        let entry = self.mkskipped.remove(pos);
        open_body(&entry.mk, ad, &msg.enc_header, &msg.ct).map(Some)
    }

    /// DecryptHeader : HKr d'abord, puis NHKr (qui annonce une étape DH).
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

    /// Efface les clés sautées mises de côté depuis plus de
    /// `MAX_SKIPPED_AGE_SECS` (une horloge revenue en arrière n'efface rien).
    fn purge_skipped(&mut self, now: u64) {
        // Les éléments retirés sont effacés à la destruction.
        self.mkskipped
            .retain(|k| now.saturating_sub(k.stored_at) <= MAX_SKIPPED_AGE_SECS);
    }

    /// SkipMessageKeysHE : au plus `MAX_SKIP` clés d'avance dans la chaîne.
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

    /// Ajoute une clé sautée, évince les plus anciennes au-delà de
    /// `MAX_SKIPPED_TOTAL`, sans laisser de copie non effacée en mémoire.
    fn push_skipped(&mut self, key: SkippedKey) {
        if self.mkskipped.len() == self.mkskipped.capacity() {
            // Réallocation manuelle : l'ancien tampon est effacé avant d'être libéré.
            let cap = (self.mkskipped.capacity() * 2).clamp(16, MAX_SKIPPED_TOTAL + 1);
            let mut grown = Vec::with_capacity(cap.max(self.mkskipped.len() + 1));
            grown.extend(self.mkskipped.iter().cloned());
            self.mkskipped.zeroize();
            self.mkskipped = grown;
        }
        self.mkskipped.push(key);
        if self.mkskipped.len() > MAX_SKIPPED_TOTAL {
            let excess = self.mkskipped.len() - MAX_SKIPPED_TOTAL;
            // Les éléments retirés sont effacés à la destruction.
            self.mkskipped.drain(..excess);
        }
    }

    /// Moitié « réception » de DHRatchetHE. L'ancienne clé privée `DHs` est
    /// effacée ; la nouvelle sera tirée au prochain `encrypt`.
    fn receive_ratchet(&mut self, header: &Header) -> Result<()> {
        // Sans `DHs`, le pair ne peut pas avoir fait d'étape DH légitime.
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

    /// Moitié « envoi » de DHRatchetHE : nouvelle paire DH, puis KDF_RK.
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

/// Clés d'en-tête initiales : `shared_hka || shared_nhkb`.
fn initial_header_keys(sk: &[u8; 32]) -> Result<([u8; 32], [u8; 32])> {
    let mut okm = Zeroizing::new([0u8; 64]);
    hkdf_sha256(None, sk, labels::RATCHET_HK, okm.as_mut())?;
    Ok((split32(&okm[..32]), split32(&okm[32..])))
}

/// X25519, en refusant une sortie nulle (point d'ordre faible).
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

/// KDF_CK : `MK = HMAC(CK, 0x01)`, `CK' = HMAC(CK, 0x02)`. Renvoie `(CK', MK)`.
fn kdf_ck(ck: &[u8; 32]) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    let mk = Zeroizing::new(hmac_sha256(ck, &[0x01]));
    let next = Zeroizing::new(hmac_sha256(ck, &[0x02]));
    (next, mk)
}

/// Clé et nonce du corps : `HKDF(None, MK, RATCHET_MK)` → 44 octets.
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

/// Copie une tranche de 32 octets (les appelants passent toujours 32 octets).
fn split32(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    out
}
