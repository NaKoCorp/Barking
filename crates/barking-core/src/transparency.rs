//! Journal de transparence : ce que le cœur a fait, et ce que les
//! intermédiaires ont pu en voir (spec §8). Local uniquement.

use crate::identity::device::DeviceId;
use crate::identity::root::Fingerprint;
use crate::mailbox::MailboxId;
use crate::packet::{PacketId, Tier};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransparencyEvent {
    SessionEstablished {
        contact: Fingerprint,
        device: DeviceId,
        initiator: bool,
        post_quantum: bool,
    },
    PacketSealed {
        packet_id: PacketId,
        tier: Tier,
        size: u32,
        mailbox: MailboxId,
        expires_at: u32,
        recipient_device: DeviceId,
    },
    PacketOpened {
        packet_id: PacketId,
        sender: Fingerprint,
        transport: String,
    },
    AckEmitted {
        for_packet: PacketId,
    },
    AckVerified {
        for_packet: PacketId,
    },
    DecryptFailed {
        packet_id: PacketId,
        reason: String,
    },
    DuplicateIgnored {
        packet_id: PacketId,
    },
    ContactKeyChanged {
        alias: String,
        old: Fingerprint,
        new: Fingerprint,
    },
}

const RELAYS_SEE_NOTHING_PERSONAL: &str =
    "Ils ne voient pas : qui tu es, à qui tu écris, le contenu.";

impl TransparencyEvent {
    /// Texte français destiné à l'utilisateur. N'inclut jamais de texte de
    /// message (les événements n'en portent pas).
    pub fn describe(&self) -> String {
        match self {
            Self::SessionEstablished {
                contact,
                device,
                initiator,
                post_quantum,
            } => {
                let role = if *initiator {
                    "Tu as ouvert"
                } else {
                    "Ton contact a ouvert"
                };
                let crypto = if *post_quantum {
                    "protégée aussi contre les ordinateurs quantiques"
                } else {
                    "sans protection post-quantique"
                };
                format!(
                    "{role} une session avec le contact {contact} (appareil {}), {crypto}.",
                    hex(&device.0[..4])
                )
            }
            Self::PacketSealed {
                tier,
                size,
                expires_at,
                ..
            } => format!(
                "Paquet chiffré de {size} octets (palier {tier:?}) vers une boîte aux lettres \
                 temporaire (valable aujourd'hui seulement), expire le {}. \
                 Les relais voient : la taille, la boîte aux lettres, l'expiration. \
                 {RELAYS_SEE_NOTHING_PERSONAL}",
                format_utc(*expires_at)
            ),
            Self::PacketOpened {
                sender, transport, ..
            } => format!(
                "Paquet reçu par {transport} et déchiffré : il vient de {sender}. \
                 Les relais qui l'ont transporté ont vu : la taille, la boîte aux lettres, \
                 l'expiration. {RELAYS_SEE_NOTHING_PERSONAL}"
            ),
            Self::AckEmitted { for_packet } => format!(
                "Accusé de réception publié pour le paquet {}. Les relais voient un secret \
                 qui leur permet de supprimer leurs copies ; ils ne voient pas qui accuse \
                 réception.",
                hex(&for_packet.0[..4])
            ),
            Self::AckVerified { for_packet } => format!(
                "Ton paquet {} est arrivé : l'accusé de réception a été vérifié. \
                 Les relais n'ont pas appris qui l'a émis.",
                hex(&for_packet.0[..4])
            ),
            Self::DecryptFailed { packet_id, reason } => format!(
                "Paquet {} impossible à déchiffrer ({reason}). Il a été ignoré. \
                 Les relais voient seulement qu'un paquet a circulé ; \
                 ils ne savent pas s'il a été lu.",
                hex(&packet_id.0[..4])
            ),
            Self::DuplicateIgnored { packet_id } => format!(
                "Paquet {} déjà reçu : la copie a été ignorée. \
                 Les relais peuvent en transporter plusieurs copies ; c'est normal.",
                hex(&packet_id.0[..4])
            ),
            Self::ContactKeyChanged { alias, old, new } => format!(
                "Attention : la clé de {alias} a changé (ancienne empreinte {old}, \
                 nouvelle {new}). Vérifie le numéro de sécurité avec cette personne \
                 avant de continuer."
            ),
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Date UTC lisible `AAAA-MM-JJ HH:MM UTC`, sans horloge ni dépendance
/// (algorithme « civil from days » de Howard Hinnant).
fn format_utc(secs: u32) -> String {
    let secs = i64::from(secs);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02} UTC",
        rem / 3_600,
        rem % 3_600 / 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid() -> PacketId {
        PacketId([0xab; 16])
    }
    fn fp(b: u8) -> Fingerprint {
        Fingerprint([b; 32])
    }
    fn sealed() -> TransparencyEvent {
        TransparencyEvent::PacketSealed {
            packet_id: pid(),
            tier: Tier::M,
            size: 1024,
            mailbox: MailboxId([1; 16]),
            expires_at: 1_700_000_000,
            recipient_device: DeviceId([2; 16]),
        }
    }

    fn all() -> Vec<TransparencyEvent> {
        vec![
            TransparencyEvent::SessionEstablished {
                contact: fp(1),
                device: DeviceId([2; 16]),
                initiator: true,
                post_quantum: true,
            },
            sealed(),
            TransparencyEvent::PacketOpened {
                packet_id: pid(),
                sender: fp(3),
                transport: "fichier".into(),
            },
            TransparencyEvent::AckEmitted { for_packet: pid() },
            TransparencyEvent::AckVerified { for_packet: pid() },
            TransparencyEvent::DecryptFailed {
                packet_id: pid(),
                reason: "authentification invalide".into(),
            },
            TransparencyEvent::DuplicateIgnored { packet_id: pid() },
            TransparencyEvent::ContactKeyChanged {
                alias: "Alice".into(),
                old: fp(4),
                new: fp(5),
            },
        ]
    }

    #[test]
    fn describe_sealed_mentions_what_relays_see() {
        let d = sealed().describe();
        assert!(d.contains("Les relais voient"), "{d}");
        assert!(d.contains("Ils ne voient pas"), "{d}");
        assert!(d.contains("1024 octets"), "{d}");
        // 1_700_000_000 = 2023-11-14 22:13:20 UTC
        assert!(d.contains("2023-11-14 22:13 UTC"), "{d}");
    }

    #[test]
    fn describe_is_nonempty_for_all_variants() {
        for e in all() {
            assert!(!e.describe().is_empty(), "{e:?}");
        }
    }

    #[test]
    fn describe_packet_events_explain_visibility() {
        for e in all() {
            if matches!(
                e,
                TransparencyEvent::PacketOpened { .. }
                    | TransparencyEvent::DecryptFailed { .. }
                    | TransparencyEvent::AckEmitted { .. }
            ) {
                let d = e.describe();
                assert!(d.contains("relais"), "{d}");
            }
        }
    }

    #[test]
    fn civil_date_known_values() {
        assert_eq!(format_utc(0), "1970-01-01 00:00 UTC");
        assert_eq!(format_utc(951_782_400), "2000-02-29 00:00 UTC");
        assert_eq!(format_utc(u32::MAX), "2106-02-07 06:28 UTC");
    }

    #[test]
    fn serde_roundtrip_all_variants() {
        for e in all() {
            let bytes = postcard::to_allocvec(&e).unwrap();
            let back: TransparencyEvent = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(e, back);
        }
    }
}
