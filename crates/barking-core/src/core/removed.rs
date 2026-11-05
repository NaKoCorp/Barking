//! Removal of this device from my account: a newer device list, signed by
//! my root, that no longer contains it (a recovery from the 24 words on
//! another device, or a removal by the administrator, `remove.rs`).
//!
//! It arrives through one of my devices (`SyncDevices`) or relayed by a
//! contact that dropped this device (`CardUpdate` carrying my own root).
//! The first old device to learn it forwards the card to its old siblings,
//! then records the removal and erases its root key: the phrase holder has
//! taken the account back, and a root left on a lost device would be a
//! dormant takeover key. A removed device can still receive and read, but
//! no longer send (`DeviceRemoved`).

use rand_core::CryptoRng;

use super::send::SealTime;
use super::{Core, META_ROOT, admin, log, sync};
use crate::contact::ContactCard;
use crate::envelope::Body;
use crate::identity::{DeviceKeys, DeviceList, DevicePublic};
use crate::store::{MessageId, Queries};
use crate::transparency::{SyncKind, TransparencyEvent};
use crate::{CoreError, Result};

/// The list that removed this device, and the date it was learned.
const META_REMOVED: &str = "removed";

/// This device was removed from my account (`Core::removed`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Removed {
    /// Version of the list that no longer contains this device.
    pub version: u64,
    /// When this device learned it (Unix seconds).
    pub at: u64,
}

pub(super) fn read(q: &impl Queries) -> Result<Option<Removed>> {
    Ok(q.get_meta::<(DeviceList, u64)>(META_REMOVED)?
        .map(|(list, at)| Removed {
            version: list.version,
            at,
        }))
}

/// `card` removes `me`: valid, signed by the root of `own`, newer than
/// `own`, without `me`.
pub(super) fn is_removal(own: &DeviceList, me: &DevicePublic, card: &ContactCard) -> bool {
    card.devices.supersedes(own)
        && !card.devices.certs.iter().any(|c| c.device == *me)
        && card.verify().is_ok()
}

/// Records the removal carried by `card` (checked by [`is_removal`]): the
/// card goes to my other (old) devices, then the root key and a pending
/// admin transfer are erased. Already removed: nothing, `false`.
pub(super) fn enter(
    q: &impl Queries,
    device: &DeviceKeys,
    card: &ContactCard,
    now: u64,
    rng: &mut impl CryptoRng,
) -> Result<bool> {
    if read(q)?.is_some() {
        return Ok(false);
    }
    let mut id = [0u8; 16];
    rng.fill_bytes(&mut id);
    let body = Body::SyncDevices {
        card: Box::new(card.clone()),
    };
    sync::seal_to_own(
        q,
        device,
        &body,
        SyncKind::Devices,
        MessageId(id),
        SealTime::at(now),
        rng,
    )?;
    q.put_meta(META_REMOVED, &(&card.devices, now))?;
    q.delete_meta(META_ROOT)?;
    admin::forget(q)?;
    log(
        q,
        now,
        None,
        &TransparencyEvent::ThisDeviceRemoved {
            version: card.devices.version,
        },
    )?;
    Ok(true)
}

impl Core {
    /// Removed from my account by a newer device list, if so.
    pub fn removed(&self) -> Result<Option<Removed>> {
        read(&self.store)
    }

    /// `DeviceRemoved` once this device is removed from my account.
    pub(super) fn ensure_not_removed(&self) -> Result<()> {
        match read(&self.store)? {
            Some(_) => Err(CoreError::DeviceRemoved),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{DeviceCertificate, RootIdentity};
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    fn card(root: &RootIdentity, version: u64, devices: &[&DeviceKeys]) -> ContactCard {
        let certs = devices
            .iter()
            .map(|d| DeviceCertificate::issue(root, d, "d", 1).unwrap())
            .collect();
        let list = DeviceList::sign(root, version, certs).unwrap();
        ContactCard::sign(root, "", list, Vec::new(), Vec::new()).unwrap()
    }

    #[test]
    fn removal_needs_a_newer_valid_list_without_me() {
        let mut rng = StdRng::seed_from_u64(1);
        let (root, _) = RootIdentity::generate(&mut rng);
        let me = DeviceKeys::generate(&mut rng);
        let other = DeviceKeys::generate(&mut rng);
        let own = card(&root, 10, &[&me, &other]).devices;
        let mine = me.public();
        assert!(is_removal(&own, &mine, &card(&root, 11, &[&other])));
        assert!(!is_removal(&own, &mine, &card(&root, 10, &[&other])));
        assert!(!is_removal(&own, &mine, &card(&root, 9, &[&other])));
        assert!(!is_removal(&own, &mine, &card(&root, 11, &[&me])));
        let (foreign, _) = RootIdentity::generate(&mut rng);
        assert!(!is_removal(&own, &mine, &card(&foreign, 11, &[&other])));
        let mut forged = card(&root, 11, &[&other]);
        forged.devices.version = 12;
        assert!(!is_removal(&own, &mine, &forged));
    }
}
