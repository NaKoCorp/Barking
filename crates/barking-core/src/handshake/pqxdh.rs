//! Poignée de main PQXDH hybride (X25519 + ML-KEM-768).

use super::prekeys::{PQ_CT_LEN, PrekeyBundle, PrekeySecrets};
use crate::crypto::{kdf::hkdf_sha256, labels};
use crate::identity::DeviceKeys;
use crate::{CoreError, Result};
use core::fmt;
use ml_kem::{Ciphertext, Decapsulate, Encapsulate, EncapsulationKey, MlKem768, TryKeyInit};
use rand_core::CryptoRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Préfixe du matériel de clé (spec PQXDH : 32 octets 0xFF pour X25519).
const KM_PREFIX: [u8; 32] = [0xFF; 32];
/// Taille maximale du matériel de clé : préfixe, 4 DH, secret ML-KEM.
const KM_MAX: usize = 32 * 6;

/// Premier message de l'initiateur : ce dont le répondeur a besoin pour
/// reproduire le calcul.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct InitialMessage {
    /// Clé d'identité X25519 de l'appareil initiateur (`DevicePublic.dh`).
    pub ik: [u8; 32],
    /// Clé éphémère X25519 de l'initiateur.
    pub ek: [u8; 32],
    pub spk_id: u32,
    pub pq_id: u32,
    pub opk_id: Option<u32>,
    /// Chiffré ML-KEM-768 (1088 octets).
    pub kem_ct: Vec<u8>,
}

/// Secrets issus de la poignée de main, partagés par les deux côtés.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SessionSecrets {
    pub sk: [u8; 32],
    pub mailbox_secret: [u8; 32],
    /// Données associées : `IK_A_pub || IK_B_pub`.
    pub ad: Vec<u8>,
}

impl fmt::Debug for SessionSecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionSecrets(<secret>)")
    }
}

/// Côté initiateur : vérifie le paquet de clés et dérive les secrets de session.
///
/// Le paquet doit en plus appartenir à un appareil attendu (certificat, liste
/// d'appareils) : c'est à l'appelant de le vérifier.
pub fn initiate(
    me: &DeviceKeys,
    bundle: &PrekeyBundle,
    rng: &mut impl CryptoRng,
) -> Result<(SessionSecrets, InitialMessage)> {
    bundle.verify()?;
    let pq_ek = EncapsulationKey::<MlKem768>::new_from_slice(&bundle.pq_ek)
        .map_err(|_| CoreError::Crypto)?;
    let ik_b = PublicKey::from(bundle.device.dh);
    let spk_b = PublicKey::from(bundle.spk);

    let mut ek_bytes = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(ek_bytes.as_mut());
    let ek = StaticSecret::from(*ek_bytes);

    let mut km = new_km();
    push_dh(&mut km, me.dh(&spk_b))?;
    push_dh(&mut km, ek.diffie_hellman(&ik_b).to_bytes())?;
    push_dh(&mut km, ek.diffie_hellman(&spk_b).to_bytes())?;
    if let Some((_, opk)) = &bundle.opk {
        push_dh(
            &mut km,
            ek.diffie_hellman(&PublicKey::from(*opk)).to_bytes(),
        )?;
    }
    let (ct, mut ss) = pq_ek.encapsulate_with_rng(rng);
    km.extend_from_slice(&ss);
    ss.zeroize();

    let ik_a = me.public().dh;
    let secrets = derive(&km, &ik_a, &bundle.device.dh)?;
    let init = InitialMessage {
        ik: ik_a,
        ek: PublicKey::from(&ek).to_bytes(),
        spk_id: bundle.spk_id,
        pq_id: bundle.pq_id,
        opk_id: bundle.opk.map(|(id, _)| id),
        kem_ct: ct.to_vec(),
    };
    Ok((secrets, init))
}

/// Côté répondeur : reproduit le calcul et consomme la clé à usage unique utilisée.
///
/// Identifiant de clé (signée, ML-KEM ou à usage unique) inconnu : `NoSession`.
/// En cas d'échec, la clé à usage unique n'est pas consommée.
pub fn respond(
    me: &DeviceKeys,
    secrets: &mut PrekeySecrets,
    init: &InitialMessage,
) -> Result<SessionSecrets> {
    if init.spk_id != secrets.spk_id() || init.pq_id != secrets.pq_id() {
        return Err(CoreError::NoSession);
    }
    if init.kem_ct.len() != PQ_CT_LEN {
        return Err(CoreError::Malformed("taille du chiffré ML-KEM"));
    }
    let ct = Ciphertext::<MlKem768>::try_from(init.kem_ct.as_slice())
        .map_err(|_| CoreError::Malformed("taille du chiffré ML-KEM"))?;
    let opk = match init.opk_id {
        Some(id) => Some(secrets.opk(id).ok_or(CoreError::NoSession)?),
        None => None,
    };
    let ik_a = PublicKey::from(init.ik);
    let ek_a = PublicKey::from(init.ek);
    let spk = secrets.spk();

    let mut km = new_km();
    push_dh(&mut km, spk.diffie_hellman(&ik_a).to_bytes())?;
    push_dh(&mut km, me.dh(&ek_a))?;
    push_dh(&mut km, spk.diffie_hellman(&ek_a).to_bytes())?;
    if let Some(opk) = opk {
        push_dh(&mut km, opk.diffie_hellman(&ek_a).to_bytes())?;
    }
    let mut ss = secrets.pq_dk().decapsulate(&ct);
    km.extend_from_slice(&ss);
    ss.zeroize();

    let session = derive(&km, &init.ik, &me.public().dh)?;
    if let Some(id) = init.opk_id {
        secrets.remove_opk(id);
    }
    Ok(session)
}

fn new_km() -> Zeroizing<Vec<u8>> {
    // Capacité fixée d'avance : aucune réallocation ne laisse de copie non effacée.
    let mut km = Zeroizing::new(Vec::with_capacity(KM_MAX));
    km.extend_from_slice(&KM_PREFIX);
    km
}

/// Ajoute une sortie X25519 au matériel de clé, en refusant la sortie nulle
/// (point d'ordre faible : l'échange ne serait pas contributif).
fn push_dh(km: &mut Zeroizing<Vec<u8>>, mut dh: [u8; 32]) -> Result<()> {
    let acc = dh.iter().fold(0u8, |acc, b| acc | b);
    if acc == 0 {
        return Err(CoreError::Crypto);
    }
    km.extend_from_slice(&dh);
    dh.zeroize();
    Ok(())
}

fn derive(km: &[u8], ik_a: &[u8; 32], ik_b: &[u8; 32]) -> Result<SessionSecrets> {
    let salt = [0u8; 32];
    let mut ad = Vec::with_capacity(64);
    ad.extend_from_slice(ik_a);
    ad.extend_from_slice(ik_b);
    let mut s = SessionSecrets {
        sk: [0u8; 32],
        mailbox_secret: [0u8; 32],
        ad,
    };
    hkdf_sha256(Some(&salt), km, labels::PQXDH_SK, &mut s.sk)?;
    hkdf_sha256(
        Some(&salt),
        km,
        labels::PQXDH_MAILBOX,
        &mut s.mailbox_secret,
    )?;
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CoreError;
    use crate::crypto::labels;
    use crate::handshake::prekeys::PQ_CT_LEN;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    struct Bob {
        dev: DeviceKeys,
        pre: PrekeySecrets,
    }

    fn bob(rng: &mut StdRng) -> Bob {
        let dev = DeviceKeys::generate(rng);
        let pre = PrekeySecrets::generate(rng, 2);
        Bob { dev, pre }
    }

    fn assert_agree(a: &SessionSecrets, b: &SessionSecrets) {
        assert_eq!(a.sk, b.sk);
        assert_eq!(a.mailbox_secret, b.mailbox_secret);
        assert_eq!(a.ad, b.ad);
        assert_ne!(a.sk, a.mailbox_secret);
        assert_ne!(a.sk, [0u8; 32]);
    }

    #[test]
    fn both_sides_agree() {
        let mut rng = StdRng::seed_from_u64(1);
        let alice = DeviceKeys::generate(&mut rng);
        let mut b = bob(&mut rng);
        for with_opk in [false, true] {
            let bundle = b.pre.bundle(&b.dev, with_opk);
            let (sa, init) = initiate(&alice, &bundle, &mut rng).unwrap();
            assert_eq!(init.ik, alice.public().dh);
            assert_eq!(init.opk_id.is_some(), with_opk);
            let sb = respond(&b.dev, &mut b.pre, &init).unwrap();
            assert_agree(&sa, &sb);
            let mut ad = alice.public().dh.to_vec();
            ad.extend_from_slice(&b.dev.public().dh);
            assert_eq!(sa.ad, ad);
        }
    }

    #[test]
    fn opk_changes_secret() {
        // Même aléa côté initiateur : seule la présence de la clé à usage unique diffère.
        let mut rng = StdRng::seed_from_u64(2);
        let alice = DeviceKeys::generate(&mut rng);
        let b = bob(&mut rng);
        let (s1, _) = initiate(
            &alice,
            &b.pre.bundle(&b.dev, false),
            &mut StdRng::seed_from_u64(7),
        )
        .unwrap();
        let (s2, _) = initiate(
            &alice,
            &b.pre.bundle(&b.dev, true),
            &mut StdRng::seed_from_u64(7),
        )
        .unwrap();
        assert_ne!(s1.sk, s2.sk);
    }

    #[test]
    fn tampered_bundle_rejected() {
        let mut rng = StdRng::seed_from_u64(3);
        let alice = DeviceKeys::generate(&mut rng);
        let b = bob(&mut rng);
        let mut bundle = b.pre.bundle(&b.dev, true);
        bundle.spk[5] ^= 0x40;
        assert_eq!(bundle.verify(), Err(CoreError::InvalidSignature));
        assert_eq!(
            initiate(&alice, &bundle, &mut rng).err(),
            Some(CoreError::InvalidSignature)
        );
    }

    #[test]
    fn opk_consumed_once() {
        let mut rng = StdRng::seed_from_u64(4);
        let alice = DeviceKeys::generate(&mut rng);
        let mut b = bob(&mut rng);
        let bundle = b.pre.bundle(&b.dev, true);
        let (_, init) = initiate(&alice, &bundle, &mut rng).unwrap();
        assert_eq!(b.pre.opk_count(), 2);
        respond(&b.dev, &mut b.pre, &init).unwrap();
        assert_eq!(b.pre.opk_count(), 1);
        assert_eq!(
            respond(&b.dev, &mut b.pre, &init).err(),
            Some(CoreError::NoSession)
        );
        // Le paquet suivant propose une autre clé à usage unique.
        assert_ne!(b.pre.bundle(&b.dev, true).opk, bundle.opk);
    }

    #[test]
    fn unknown_opk_id_is_no_session() {
        let mut rng = StdRng::seed_from_u64(5);
        let alice = DeviceKeys::generate(&mut rng);
        let mut b = bob(&mut rng);
        let (_, mut init) = initiate(&alice, &b.pre.bundle(&b.dev, true), &mut rng).unwrap();
        init.opk_id = init.opk_id.map(|id| id.wrapping_add(1));
        // Un identifiant inconnu (sauf collision improbable avec la seconde clé).
        if b.pre.bundle(&b.dev, true).opk.map(|(id, _)| id) != init.opk_id {
            assert_eq!(
                respond(&b.dev, &mut b.pre, &init).err(),
                Some(CoreError::NoSession)
            );
        }
    }

    #[test]
    fn unknown_spk_or_pq_id_is_no_session() {
        let mut rng = StdRng::seed_from_u64(6);
        let alice = DeviceKeys::generate(&mut rng);
        let mut b = bob(&mut rng);
        let (_, init) = initiate(&alice, &b.pre.bundle(&b.dev, false), &mut rng).unwrap();
        let mut i = init.clone();
        i.spk_id ^= 1;
        assert_eq!(
            respond(&b.dev, &mut b.pre, &i).err(),
            Some(CoreError::NoSession)
        );
        let mut i = init.clone();
        i.pq_id ^= 1;
        assert_eq!(
            respond(&b.dev, &mut b.pre, &i).err(),
            Some(CoreError::NoSession)
        );
    }

    #[test]
    fn bundle_without_opk_reusable() {
        let mut rng = StdRng::seed_from_u64(8);
        let a1 = DeviceKeys::generate(&mut rng);
        let a2 = DeviceKeys::generate(&mut rng);
        let mut b = bob(&mut rng);
        let bundle = b.pre.bundle(&b.dev, false);
        let (s1, i1) = initiate(&a1, &bundle, &mut rng).unwrap();
        let (s2, i2) = initiate(&a2, &bundle, &mut rng).unwrap();
        let r1 = respond(&b.dev, &mut b.pre, &i1).unwrap();
        let r2 = respond(&b.dev, &mut b.pre, &i2).unwrap();
        assert_agree(&s1, &r1);
        assert_agree(&s2, &r2);
        assert_ne!(s1.sk, s2.sk);
        assert_ne!(s1.mailbox_secret, s2.mailbox_secret);
        assert_ne!(s1.ad, s2.ad);
        assert_eq!(b.pre.opk_count(), 2);
    }

    #[test]
    fn initial_message_size() {
        let mut rng = StdRng::seed_from_u64(9);
        let alice = DeviceKeys::generate(&mut rng);
        let b = bob(&mut rng);
        let (_, init) = initiate(&alice, &b.pre.bundle(&b.dev, true), &mut rng).unwrap();
        assert_eq!(init.kem_ct.len(), PQ_CT_LEN);
        let len = postcard::to_allocvec(&init).unwrap().len();
        assert!((1100..=1300).contains(&len), "taille {len}");
        assert!(len > 1024, "au-delà du palier M : part en L");
    }

    /// Re-signe un paquet modifié, pour atteindre les vérifications après la signature.
    fn resign(bundle: &mut PrekeyBundle, dev: &DeviceKeys) {
        bundle.sig = dev.sign(labels::PREKEYS, &bundle.signed_bytes());
    }

    #[test]
    fn zero_spk_rejected() {
        let mut rng = StdRng::seed_from_u64(10);
        let alice = DeviceKeys::generate(&mut rng);
        let b = bob(&mut rng);
        let mut bundle = b.pre.bundle(&b.dev, false);
        bundle.spk = [0u8; 32];
        resign(&mut bundle, &b.dev);
        assert!(bundle.verify().is_ok());
        assert_eq!(
            initiate(&alice, &bundle, &mut rng).err(),
            Some(CoreError::Crypto)
        );
    }

    #[test]
    fn zero_opk_rejected() {
        let mut rng = StdRng::seed_from_u64(11);
        let alice = DeviceKeys::generate(&mut rng);
        let b = bob(&mut rng);
        let mut bundle = b.pre.bundle(&b.dev, true);
        bundle.opk = bundle.opk.map(|(id, _)| (id, [0u8; 32]));
        resign(&mut bundle, &b.dev);
        assert_eq!(
            initiate(&alice, &bundle, &mut rng).err(),
            Some(CoreError::Crypto)
        );
    }

    #[test]
    fn zero_identity_dh_rejected() {
        // Clé d'identité de l'appareil distant = point d'ordre faible (0) : DH2 nul.
        let mut rng = StdRng::seed_from_u64(12);
        let alice = DeviceKeys::generate(&mut rng);
        let b = bob(&mut rng);
        let mut bundle = b.pre.bundle(&b.dev, false);
        bundle.device.dh = [0u8; 32];
        resign(&mut bundle, &b.dev);
        assert_eq!(
            initiate(&alice, &bundle, &mut rng).err(),
            Some(CoreError::Crypto)
        );
    }

    #[test]
    fn responder_rejects_zero_points() {
        let mut rng = StdRng::seed_from_u64(13);
        let alice = DeviceKeys::generate(&mut rng);
        let mut b = bob(&mut rng);
        let (_, init) = initiate(&alice, &b.pre.bundle(&b.dev, true), &mut rng).unwrap();
        let mut i = init.clone();
        i.ik = [0u8; 32];
        assert_eq!(
            respond(&b.dev, &mut b.pre, &i).err(),
            Some(CoreError::Crypto)
        );
        let mut i = init.clone();
        i.ek = [0u8; 32];
        assert_eq!(
            respond(&b.dev, &mut b.pre, &i).err(),
            Some(CoreError::Crypto)
        );
        // Un échec ne consomme pas la clé à usage unique.
        assert_eq!(b.pre.opk_count(), 2);
        assert!(respond(&b.dev, &mut b.pre, &init).is_ok());
    }

    #[test]
    fn bad_kem_ct_size_rejected() {
        let mut rng = StdRng::seed_from_u64(14);
        let alice = DeviceKeys::generate(&mut rng);
        let mut b = bob(&mut rng);
        let (_, mut init) = initiate(&alice, &b.pre.bundle(&b.dev, false), &mut rng).unwrap();
        init.kem_ct.push(0);
        assert!(matches!(
            respond(&b.dev, &mut b.pre, &init),
            Err(CoreError::Malformed(_))
        ));
        init.kem_ct.truncate(10);
        assert!(matches!(
            respond(&b.dev, &mut b.pre, &init),
            Err(CoreError::Malformed(_))
        ));
    }

    #[test]
    fn tampered_kem_ct_gives_different_secret() {
        // ML-KEM rejette implicitement : le répondeur dérive un autre secret.
        let mut rng = StdRng::seed_from_u64(15);
        let alice = DeviceKeys::generate(&mut rng);
        let mut b = bob(&mut rng);
        let (sa, mut init) = initiate(&alice, &b.pre.bundle(&b.dev, false), &mut rng).unwrap();
        init.kem_ct[0] ^= 1;
        let sb = respond(&b.dev, &mut b.pre, &init).unwrap();
        assert_ne!(sa.sk, sb.sk);
    }

    #[test]
    fn debug_hides_session_secrets() {
        let mut rng = StdRng::seed_from_u64(16);
        let alice = DeviceKeys::generate(&mut rng);
        let b = bob(&mut rng);
        let (sa, _) = initiate(&alice, &b.pre.bundle(&b.dev, false), &mut rng).unwrap();
        assert_eq!(format!("{sa:?}"), "SessionSecrets(<secret>)");
    }
}
