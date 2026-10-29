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
        /// Premier message d'une session (boîte aux lettres d'introduction).
        first_contact: bool,
    },
    PacketOpened {
        packet_id: PacketId,
        sender: Fingerprint,
        transport: String,
        /// Le paquet ouvrait une session (boîte aux lettres d'introduction).
        first_contact: bool,
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
    /// Trame rejetée au réassemblage ; `reason` est un texte fixe.
    FrameRejected {
        reason: String,
    },
    /// Côté administrateur : un nouvel appareil a été lié à mon compte.
    DeviceLinked {
        device: DeviceId,
        name: String,
    },
    /// Côté nouvel appareil : la liaison est terminée.
    LinkFinished {
        device_count: u32,
        contacts: u32,
    },
    /// Contenu de synchronisation reçu d'un de mes appareils et appliqué.
    SyncApplied {
        kind: SyncKind,
    },
    /// Copie de synchronisation non envoyée : trop volumineuse pour un paquet.
    SyncSkipped {
        kind: SyncKind,
    },
}

/// Type de synchronisation entre mes appareils.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncKind {
    Sent,
    Contact,
    Devices,
}

impl SyncKind {
    /// Nom affiché : « message envoyé », « contact », « liste d'appareils ».
    pub fn label(self) -> &'static str {
        match self {
            SyncKind::Sent => "message envoyé",
            SyncKind::Contact => "contact",
            SyncKind::Devices => "liste d'appareils",
        }
    }
}

/// Ce que tout relais lit dans l'en-tête en clair d'un paquet.
const RELAYS_SEE: &str = "Les relais voient : la taille, le type (message ou accusé), \
    le nombre de sauts, un identifiant de paquet, la boîte aux lettres, l'expiration.";

/// Ce que les relais ne voient pas (identité réelle, destinataire réel, contenu).
const RELAYS_DONT_SEE: &str = "Ils ne voient pas : qui tu es, à qui tu écris, le contenu.";

/// Variante pour un premier message : la boîte d'introduction désigne le destinataire.
const RELAYS_DONT_SEE_FIRST: &str = "Ils ne voient ni qui tu es, ni le contenu. Mais \
    quiconque possède la carte de contact du destinataire peut savoir que c'est un premier \
    message pour cette personne.";

/// Liaison message / accusé, visible des relais.
const ACK_LINK: &str = "L'identifiant du paquet permet aux relais de relier un message à son \
    accusé, et l'accusé reprend la boîte aux lettres du message : ils peuvent donc relier \
    les deux, sans apprendre l'identité réelle de personne.";

fn tier_label(tier: Tier) -> &'static str {
    match tier {
        Tier::S => "petit",
        Tier::M => "moyen",
        Tier::L => "grand",
    }
}

impl TransparencyEvent {
    /// Preuve de sécurité : une session établie, une clé de contact
    /// changée, un appareil lié à mon compte (côté administrateur) ou une
    /// liaison terminée (côté nouvel appareil : c'est la preuve de l'identité
    /// qu'il a rejointe). Ces entrées ont leur propre plafond au journal ; les
    /// autres (qu'un tiers peut provoquer en masse) ne les évincent jamais.
    pub fn is_security(&self) -> bool {
        matches!(
            self,
            Self::SessionEstablished { .. }
                | Self::ContactKeyChanged { .. }
                | Self::DeviceLinked { .. }
                | Self::LinkFinished { .. }
        )
    }

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
                first_contact,
                ..
            } => {
                let (mailbox, hidden) = if *first_contact {
                    (
                        "Premier message d'une session : la boîte aux lettres d'introduction \
                         est calculée à partir de la clé publique de l'appareil destinataire \
                         et du jour.",
                        RELAYS_DONT_SEE_FIRST,
                    )
                } else {
                    (
                        "La boîte aux lettres est temporaire : elle change chaque jour et ne \
                         révèle pas l'identité réelle de ton contact.",
                        RELAYS_DONT_SEE,
                    )
                };
                format!(
                    "Paquet chiffré de {size} octets (palier {}), expire le {}. {mailbox} \
                     {RELAYS_SEE} {hidden}",
                    tier_label(*tier),
                    format_utc(*expires_at)
                )
            }
            Self::PacketOpened {
                sender,
                transport,
                first_contact,
                ..
            } => {
                let (intro, hidden) = if *first_contact {
                    (
                        " Il ouvrait une session : il est arrivé dans ta boîte aux lettres \
                         d'introduction, calculée à partir de la clé publique de ton appareil \
                         et du jour.",
                        RELAYS_DONT_SEE_FIRST,
                    )
                } else {
                    ("", RELAYS_DONT_SEE)
                };
                format!(
                    "Paquet reçu par {transport} et déchiffré : il vient de {sender}.{intro} \
                     Les relais qui l'ont transporté ont pu lire son en-tête. {RELAYS_SEE} \
                     {hidden}"
                )
            }
            Self::AckEmitted { for_packet } => format!(
                "Accusé de réception publié pour le paquet {}. {RELAYS_SEE} {ACK_LINK} \
                 Le secret de l'accusé leur permet de supprimer leurs copies.",
                hex(&for_packet.0[..4])
            ),
            Self::AckVerified { for_packet } => format!(
                "Ton paquet {} est arrivé : l'accusé de réception a été vérifié. \
                 {RELAYS_SEE} {ACK_LINK}",
                hex(&for_packet.0[..4])
            ),
            Self::DecryptFailed { packet_id, reason } => format!(
                "Paquet {} impossible à déchiffrer ({reason}). Il a été ignoré. \
                 {RELAYS_SEE} Ils ne savent pas s'il a été lu.",
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
            Self::FrameRejected { reason } => format!(
                "Trame rejetée ({reason}) : elle ne correspond pas au paquet annoncé. \
                 Le paquet n'a pas été reconstitué ; l'expéditeur le renverra."
            ),
            Self::DeviceLinked { name, .. } => format!(
                "Nouvel appareil « {name} » lié à ton compte. \
                 Tes contacts vont recevoir ta nouvelle liste d'appareils."
            ),
            Self::LinkFinished {
                device_count,
                contacts,
            } => format!(
                "Cet appareil est maintenant lié à ton compte ({device_count} appareils, \
                 {contacts} contacts copiés). La clé racine n'a pas été copiée."
            ),
            Self::SyncApplied { kind } => {
                format!("Synchronisé depuis un de tes appareils : {}.", kind.label())
            }
            Self::SyncSkipped { kind } => format!(
                "Copie vers tes autres appareils non envoyée ({}) : trop volumineuse. \
                 Tes appareils peuvent différer sur ce point.",
                kind.label()
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
            first_contact: false,
        }
    }
    fn sealed_first() -> TransparencyEvent {
        match sealed() {
            TransparencyEvent::PacketSealed {
                packet_id,
                tier,
                size,
                mailbox,
                expires_at,
                recipient_device,
                ..
            } => TransparencyEvent::PacketSealed {
                packet_id,
                tier,
                size,
                mailbox,
                expires_at,
                recipient_device,
                first_contact: true,
            },
            _ => unreachable!(),
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
                first_contact: false,
            },
            TransparencyEvent::PacketOpened {
                packet_id: pid(),
                sender: fp(3),
                transport: "fichier".into(),
                first_contact: true,
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
            TransparencyEvent::FrameRejected {
                reason: "hash de trame incorrect".into(),
            },
            TransparencyEvent::DeviceLinked {
                device: DeviceId([6; 16]),
                name: "tablette".into(),
            },
            TransparencyEvent::LinkFinished {
                device_count: 2,
                contacts: 3,
            },
            TransparencyEvent::SyncApplied {
                kind: SyncKind::Sent,
            },
            TransparencyEvent::SyncApplied {
                kind: SyncKind::Contact,
            },
            TransparencyEvent::SyncApplied {
                kind: SyncKind::Devices,
            },
            TransparencyEvent::SyncSkipped {
                kind: SyncKind::Contact,
            },
        ]
    }

    #[test]
    fn describe_sync_applied_exact() {
        let d = |kind| TransparencyEvent::SyncApplied { kind }.describe();
        assert_eq!(
            d(SyncKind::Sent),
            "Synchronisé depuis un de tes appareils : message envoyé."
        );
        assert_eq!(
            d(SyncKind::Contact),
            "Synchronisé depuis un de tes appareils : contact."
        );
        assert_eq!(
            d(SyncKind::Devices),
            "Synchronisé depuis un de tes appareils : liste d'appareils."
        );
        assert!(
            !TransparencyEvent::SyncApplied {
                kind: SyncKind::Devices
            }
            .is_security()
        );
        let skipped = |kind| TransparencyEvent::SyncSkipped { kind };
        assert_eq!(
            skipped(SyncKind::Contact).describe(),
            "Copie vers tes autres appareils non envoyée (contact) : trop volumineuse. \
             Tes appareils peuvent différer sur ce point."
        );
        assert_eq!(
            skipped(SyncKind::Devices).describe(),
            "Copie vers tes autres appareils non envoyée (liste d'appareils) : trop \
             volumineuse. Tes appareils peuvent différer sur ce point."
        );
        assert!(!skipped(SyncKind::Sent).is_security());
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
    fn describe_lists_all_visible_header_fields() {
        let ack = TransparencyEvent::AckEmitted { for_packet: pid() }.describe();
        for d in [sealed().describe(), ack] {
            for w in [
                "type",
                "sauts",
                "identifiant",
                "boîte aux lettres",
                "expiration",
            ] {
                assert!(d.contains(w), "{w} manque : {d}");
            }
        }
        assert!(!sealed().describe().contains("Tier"));
        assert!(sealed().describe().contains("moyen"));
    }

    #[test]
    fn describe_ack_states_linkability() {
        let d = TransparencyEvent::AckVerified { for_packet: pid() }.describe();
        assert!(d.contains("relier"), "{d}");
    }

    #[test]
    fn describe_first_contact_mentions_contact_card() {
        let d = sealed_first().describe();
        assert!(d.contains("carte de contact"), "{d}");
        assert!(!sealed().describe().contains("carte de contact"));
    }

    #[test]
    fn describe_first_contact_does_not_claim_recipient_hidden() {
        let opened = |first_contact| TransparencyEvent::PacketOpened {
            packet_id: pid(),
            sender: fp(3),
            transport: "fichier".into(),
            first_contact,
        };
        for d in [sealed_first().describe(), opened(true).describe()] {
            assert!(!d.contains("à qui tu écris"), "{d}");
            assert!(d.contains("carte de contact"), "{d}");
            assert!(d.contains("Les relais voient"), "{d}");
            assert!(d.contains("qui tu es"), "{d}");
        }
        assert!(sealed().describe().contains("à qui tu écris"));
        assert!(!opened(false).describe().contains("carte de contact"));
    }

    #[test]
    fn security_class_is_session_key_change_and_link_only() {
        let security: Vec<_> = all().into_iter().filter(|e| e.is_security()).collect();
        assert_eq!(security.len(), 4);
        assert!(security.iter().all(|e| matches!(
            e,
            TransparencyEvent::SessionEstablished { .. }
                | TransparencyEvent::ContactKeyChanged { .. }
                | TransparencyEvent::DeviceLinked { .. }
                | TransparencyEvent::LinkFinished { .. }
        )));
    }

    #[test]
    fn describe_link_events_exact() {
        let linked = TransparencyEvent::DeviceLinked {
            device: DeviceId([6; 16]),
            name: "tablette".into(),
        };
        assert_eq!(
            linked.describe(),
            "Nouvel appareil « tablette » lié à ton compte. \
             Tes contacts vont recevoir ta nouvelle liste d'appareils."
        );
        let finished = TransparencyEvent::LinkFinished {
            device_count: 2,
            contacts: 3,
        };
        assert_eq!(
            finished.describe(),
            "Cet appareil est maintenant lié à ton compte (2 appareils, 3 contacts copiés). \
             La clé racine n'a pas été copiée."
        );
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
