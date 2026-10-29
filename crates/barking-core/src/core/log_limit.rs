//! Limiteur d'écritures au journal pour les événements qu'un tiers peut
//! provoquer à volonté (trames rejetées, paquets indéchiffrables, doublons) :
//! au plus une entrée par type et par raison toutes les
//! `NOISY_EVENT_LOG_INTERVAL_SECS`. En mémoire seulement : une réouverture
//! repart de zéro.

use super::log;
use crate::Result;
use crate::packet::PacketId;
use crate::store::Queries;
use crate::transparency::TransparencyEvent;

/// Intervalle minimal, par type d'événement bruyant et par raison, entre
/// deux entrées au journal.
pub const NOISY_EVENT_LOG_INTERVAL_SECS: u64 = 60;

/// Dernière écriture au journal par clé (type, raison). Les raisons sont des
/// textes fixes du cœur : le nombre de clés est borné.
#[derive(Default)]
pub(super) struct LogLimiter {
    last: Vec<(u8, String, u64)>,
}

/// Clé de regroupement d'un événement bruyant ; `None` : jamais regroupé.
fn key(e: &TransparencyEvent) -> Option<(u8, &str)> {
    match e {
        TransparencyEvent::FrameRejected { reason } => Some((0, reason)),
        TransparencyEvent::DecryptFailed { reason, .. } => Some((1, reason)),
        TransparencyEvent::DuplicateIgnored { .. } => Some((2, "")),
        _ => None,
    }
}

impl LogLimiter {
    /// `true` si `e` doit être écrit à `now` ; l'écriture est alors comptée
    /// (si la transaction qui l'écrit échoue, l'entrée est perdue : au plus
    /// une par intervalle).
    fn admit(&mut self, e: &TransparencyEvent, now: u64) -> bool {
        let Some((kind, reason)) = key(e) else {
            return true;
        };
        match self
            .last
            .iter_mut()
            .find(|(k, r, _)| *k == kind && r == reason)
        {
            Some((_, _, last)) => {
                if now.saturating_sub(*last) < NOISY_EVENT_LOG_INTERVAL_SECS {
                    return false;
                }
                *last = now;
            }
            None => self.last.push((kind, reason.to_owned(), now)),
        }
        true
    }
}

/// Journalise `e`, sauf s'il est bruyant et qu'une entrée de même type et
/// de même raison a été écrite il y a moins d'un intervalle.
pub(super) fn log_limited(
    q: &impl Queries,
    limiter: &mut LogLimiter,
    at: u64,
    packet: Option<PacketId>,
    e: &TransparencyEvent,
) -> Result<()> {
    if limiter.admit(e, at) {
        log(q, at, packet, e)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn failed(reason: &str) -> TransparencyEvent {
        TransparencyEvent::DecryptFailed {
            packet_id: PacketId([0; 16]),
            reason: reason.into(),
        }
    }

    #[test]
    fn one_entry_per_kind_and_reason_per_interval() {
        let mut l = LogLimiter::default();
        assert!(l.admit(&failed("a"), 100));
        assert!(!l.admit(&failed("a"), 159));
        assert!(l.admit(&failed("b"), 159));
        assert!(l.admit(&failed("a"), 160));
        let rejected = TransparencyEvent::FrameRejected { reason: "a".into() };
        assert!(l.admit(&rejected, 160));
        let opened = TransparencyEvent::AckVerified {
            for_packet: PacketId([0; 16]),
        };
        assert!(l.admit(&opened, 160));
        assert!(l.admit(&opened, 160));
    }
}
