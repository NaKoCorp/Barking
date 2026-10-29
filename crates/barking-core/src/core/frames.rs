//! Fragmentation et réassemblage : `frames` découpe un paquet pour un
//! transport à petit MTU, `receive_frame` recolle les trames reçues.

use rand_core::CryptoRng;

use super::{Core, ReceiveOutcome, log};
use crate::fragment::fragment;
use crate::transparency::TransparencyEvent;
use crate::{CoreError, Result};

/// Nombre maximal de paquets incomplets gardés en mémoire.
pub const MAX_PENDING_FRAMES: usize = 64;

/// Durée de vie, en secondes, d'un paquet incomplet.
pub const FRAME_TTL_SECS: u64 = 3600;

impl Core {
    /// Découpe un paquet encodé en trames d'au plus `mtu` octets.
    pub fn frames(&self, packet: &[u8], mtu: usize) -> Result<Vec<Vec<u8>>> {
        fragment(packet, mtu)
    }

    /// Nombre de paquets incomplets en attente de trames (diagnostic).
    pub fn pending_frames(&self) -> usize {
        self.frames.pending()
    }

    /// Traite une trame reçue par `transport`. `Partial` tant que le paquet
    /// est incomplet ; une trame invalide est journalisée puis ignorée
    /// (`NotForUs`) : son contenu n'est jamais conservé.
    pub fn receive_frame(
        &mut self,
        frame: &[u8],
        transport: &str,
        now: u64,
        rng: &mut impl CryptoRng,
    ) -> Result<ReceiveOutcome> {
        match self.frames.push(frame, now) {
            Ok(None) => Ok(ReceiveOutcome::Partial),
            Ok(Some(bytes)) => self.receive(&bytes, transport, now, rng),
            Err(e) => {
                let reason = match e {
                    CoreError::Malformed("hash de trame incorrect") => "hash de trame incorrect",
                    CoreError::Malformed("trames contradictoires") => "trames contradictoires",
                    _ => "trame mal formée",
                };
                let event = TransparencyEvent::FrameRejected {
                    reason: reason.to_owned(),
                };
                self.store.transaction(|tx| log(tx, now, None, &event))?;
                Ok(ReceiveOutcome::NotForUs)
            }
        }
    }
}
