//! Admin transfer: the root key handed to another of my devices.
//!
//! The administrator seals the root seed (`Body::AdminTransfer`) for the
//! target only, through their double ratchet session, and keeps its copy
//! until the target acknowledges the packet: erasing it at send time could
//! lose it everywhere if the packet expired undelivered. Meanwhile no
//! linking and no second transfer (`AdminTransferPending`). On the ack the
//! root is erased here and the target remembered as the holder; on expiry
//! the transfer is cancelled and the root stays.
//!
//! `transfer_and_leave` marks the transfer: at its ack, this device asks the
//! new holder to remove it (`Body::RemoveMe`, `core/remove.rs`). The mark
//! dies with the transfer (expiry, removal).

use rand_core::CryptoRng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::delivery;
use super::send::{SealTime, Target, seal_for};
use super::sync::R_SYNC_REFUSED;
use super::{Core, META_ROOT, OwnDevices, log, remove};
use crate::envelope::Body;
use crate::identity::{DeviceId, DeviceKeys, RootIdentity};
use crate::packet::PacketId;
use crate::store::{MessageId, Queries};
use crate::transparency::{SyncKind, TransparencyEvent};
use crate::{CoreError, Result};

/// Transfer awaiting the target's ack.
const META_ADMIN_TRANSFER: &str = "admin_transfer";
/// On a former administrator: the device it handed the root key to.
pub(super) const META_ROOT_HOLDER: &str = "root_holder";
/// The pending transfer was started by `transfer_and_leave`: its target, to
/// which `RemoveMe` goes at the ack.
const META_LEAVE_AFTER_TRANSFER: &str = "leave_after_transfer";

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct PendingTransfer {
    target: DeviceId,
    packet: PacketId,
    expires_at: u64,
}

/// The transfer still awaiting its ack at `now` (an expired one counts as none).
fn pending(q: &impl Queries, now: u64) -> Result<Option<PendingTransfer>> {
    Ok(q.get_meta::<PendingTransfer>(META_ADMIN_TRANSFER)?
        .filter(|p| now <= p.expires_at))
}

/// Erases a transfer whose packet expired without an ack: cancelled, the
/// root stays on this device.
pub(super) fn purge_expired(q: &impl Queries, now: u64) -> Result<()> {
    if let Some(p) = q.get_meta::<PendingTransfer>(META_ADMIN_TRANSFER)?
        && now > p.expires_at
    {
        forget(q)?;
    }
    Ok(())
}

/// Erases a pending transfer whatever its state (device removed), with its
/// leave mark.
pub(super) fn forget(q: &impl Queries) -> Result<()> {
    q.delete_meta(META_ADMIN_TRANSFER)?;
    q.delete_meta(META_LEAVE_AFTER_TRANSFER)?;
    Ok(())
}

/// `AdminTransferPending` while a transfer awaits its ack.
pub(super) fn ensure_none_pending(q: &impl Queries, now: u64) -> Result<()> {
    match pending(q, now)? {
        Some(_) => Err(CoreError::AdminTransferPending),
        None => Ok(()),
    }
}

/// Ack of `acked`: if it is the pending transfer's packet, the root is
/// erased and the target recorded as the holder; a transfer started by
/// `transfer_and_leave` then seals `RemoveMe` to the target. Returns `true`
/// then. To be called in the ack's transaction.
pub(super) fn on_ack(
    q: &impl Queries,
    device: &DeviceKeys,
    acked: PacketId,
    now: u64,
    rng: &mut impl CryptoRng,
) -> Result<bool> {
    let Some(p) = q.get_meta::<PendingTransfer>(META_ADMIN_TRANSFER)? else {
        return Ok(false);
    };
    if p.packet != acked {
        return Ok(false);
    }
    let leave = q.get_meta::<DeviceId>(META_LEAVE_AFTER_TRANSFER)? == Some(p.target);
    q.delete_meta(META_ROOT)?;
    forget(q)?;
    q.put_meta(META_ROOT_HOLDER, &p.target)?;
    log(
        q,
        now,
        Some(acked),
        &TransparencyEvent::AdminTransferred { device: p.target },
    )?;
    if leave {
        remove::send_remove_me(q, device, &Target::OwnDevice(p.target), now, rng)?;
    }
    Ok(true)
}

/// Root seed received from one of my devices (`Body::AdminTransfer`):
/// accepted only if it derives the root of my list, this device is not
/// removed, and my list is at least as recent as the sender's (`version`):
/// a holder behind on the list would sign a diverging one at its next link,
/// which would remove the devices it missed. Refused: no ack, the transfer
/// expires and the sender keeps the root. Already holding it: rewritten, no
/// effect.
pub(super) fn apply(
    q: &impl Queries,
    seed: &[u8; 32],
    version: u64,
) -> Result<core::result::Result<Option<SyncKind>, &'static str>> {
    let own = OwnDevices::read(q)?.ok_or(CoreError::LinkPending)?;
    if super::removed::read(q)?.is_some()
        || own.list.version < version
        || RootIdentity::from_seed(seed).public() != own.list.root
    {
        return Ok(Err(R_SYNC_REFUSED));
    }
    q.put_meta(META_ROOT, seed)?;
    q.delete_meta(META_ROOT_HOLDER)?;
    Ok(Ok(Some(SyncKind::Admin)))
}

impl Core {
    /// Hands the root key to `target`, another of my devices. The root stays
    /// here until `target` acknowledges it (see the module). Refused without
    /// the root (`NotAdmin`), while a transfer is pending
    /// (`AdminTransferPending`), for a device not in my list or this device
    /// (`Malformed`), or without a session nor key packet for it (`NoSession`).
    pub fn transfer_admin(
        &mut self,
        target: DeviceId,
        now: u64,
        rng: &mut impl CryptoRng,
    ) -> Result<()> {
        self.start_transfer(target, false, now, rng)
    }

    /// `transfer_admin` to `to`, then, at its ack, `RemoveMe` sent to `to`
    /// (become administrator) so that it removes this device; `leave_ready`
    /// says when the app may wipe. If the transfer expires, nothing is sent
    /// and the root stays here. Same refusals as `transfer_admin`.
    pub fn transfer_and_leave(
        &mut self,
        to: DeviceId,
        now: u64,
        rng: &mut impl CryptoRng,
    ) -> Result<()> {
        self.start_transfer(to, true, now, rng)
    }

    /// The transfer itself; with `leave`, marked for `transfer_and_leave` in
    /// the same transaction.
    fn start_transfer(
        &mut self,
        target: DeviceId,
        leave: bool,
        now: u64,
        rng: &mut impl CryptoRng,
    ) -> Result<()> {
        self.ensure_active()?;
        let Core {
            store,
            device,
            root,
            ..
        } = self;
        let root = root.as_ref().ok_or(CoreError::NotAdmin)?;
        store.transaction(|tx| {
            purge_expired(tx, now)?;
            ensure_none_pending(tx, now)?;
            let own = OwnDevices::read(tx)?.ok_or(CoreError::LinkPending)?;
            if target == device.public().id()
                || !own.list.certs.iter().any(|c| c.device.id() == target)
            {
                return Err(CoreError::Malformed("unknown target device"));
            }
            let mut id = [0u8; 16];
            rng.fill_bytes(&mut id);
            let message_id = MessageId(id);
            let mut body = Body::AdminTransfer {
                seed: *root.to_seed(),
                version: own.list.version,
            };
            let sealed = seal_for(
                tx,
                device,
                &Target::OwnDevice(target),
                &body,
                message_id,
                SealTime::at(now),
                rng,
            );
            if let Body::AdminTransfer { seed, .. } = &mut body {
                seed.zeroize();
            }
            let Some((packet, peer)) = sealed?.into_iter().next() else {
                return Err(CoreError::NoSession);
            };
            tx.add_delivery(
                message_id,
                packet.id,
                peer,
                true,
                now,
                delivery::packet_size(&packet),
            )?;
            tx.put_meta(
                META_ADMIN_TRANSFER,
                &PendingTransfer {
                    target,
                    packet: packet.id,
                    expires_at: u64::from(packet.expires_at),
                },
            )?;
            if leave {
                tx.put_meta(META_LEAVE_AFTER_TRANSFER, &target)?;
            } else {
                tx.delete_meta(META_LEAVE_AFTER_TRANSFER)?;
            }
            log(
                tx,
                now,
                Some(packet.id),
                &TransparencyEvent::AdminTransferStarted { device: target },
            )
        })
    }

    /// The device a transfer of the root key awaits the ack of, if any.
    pub fn admin_transfer_pending(&self, now: u64) -> Result<Option<DeviceId>> {
        Ok(pending(&self.store, now)?.map(|p| p.target))
    }

    /// Rereads the root key from the database (after an admin transfer
    /// received or completed, or a removal).
    pub(super) fn reload_root(&mut self) -> Result<()> {
        self.root = self
            .store
            .get_meta::<[u8; 32]>(META_ROOT)?
            .map(|seed| RootIdentity::from_seed(&zeroize::Zeroizing::new(seed)));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    #[test]
    fn seed_of_another_root_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let mut rng = StdRng::seed_from_u64(1);
        let (core, _) = Core::create(&d.path().join("a"), &[1; 32], "a", 1, &mut rng).unwrap();
        let mine = core.store.get_meta::<[u8; 32]>(META_ROOT).unwrap();
        let (other, _) = RootIdentity::generate(&mut rng);
        assert_eq!(
            apply(&core.store, &other.to_seed(), 0).unwrap(),
            Err(R_SYNC_REFUSED)
        );
        assert_eq!(core.store.get_meta::<[u8; 32]>(META_ROOT).unwrap(), mine);
        assert_eq!(
            apply(&core.store, &mine.unwrap(), 0).unwrap(),
            Ok(Some(SyncKind::Admin))
        );
    }
}
