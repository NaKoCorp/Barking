//! Device linking (spec iOS messaging §5.8): offer and request travel as QR
//! codes or files, the bundle (and history) as one `.barkinglink` package.

use std::sync::Arc;

use barking_core::core::{HistoryArchive, LinkBundle, LinkOffer, LinkRequest};
use barking_core::{Core, CoreError};

use crate::device::{Device, DeviceConfig, now};
use crate::{BarkingError, guard};

/// Package magic and version: `BKLK`, 1, then the bundle length (u32 LE),
/// the bundle, and the history archive (the rest, empty if none).
const MAGIC: &[u8; 4] = b"BKLK";
const VERSION: u8 = 1;

/// A new device waiting for its bundle, and the request to show the
/// existing device.
#[derive(uniffi::Record)]
pub struct PendingLink {
    pub device: Arc<Device>,
    pub request: Vec<u8>,
}

impl std::fmt::Debug for PendingLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingLink")
            .field("request_len", &self.request.len())
            .finish_non_exhaustive()
    }
}

fn pack(bundle: &[u8], history: Option<&[u8]>) -> Vec<u8> {
    let len = u32::try_from(bundle.len()).unwrap_or(u32::MAX);
    let mut out = Vec::with_capacity(9 + bundle.len() + history.map_or(0, <[u8]>::len));
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bundle);
    out.extend_from_slice(history.unwrap_or_default());
    out
}

fn unpack(package: &[u8]) -> Result<(&[u8], Option<&[u8]>), BarkingError> {
    let unreadable = || BarkingError::from_link(CoreError::Link("unreadable link file"));
    if package.len() < 9 || &package[..4] != MAGIC || package[4] != VERSION {
        return Err(unreadable());
    }
    let len = u32::from_le_bytes(package[5..9].try_into().map_err(|_| unreadable())?) as usize;
    let rest = &package[9..];
    if rest.len() < len {
        return Err(unreadable());
    }
    let (bundle, history) = rest.split_at(len);
    Ok((bundle, (!history.is_empty()).then_some(history)))
}

/// Starts linking this device to an existing identity, from its offer.
#[uniffi::export]
pub fn begin_link(
    config: DeviceConfig,
    offer: Vec<u8>,
    device_name: String,
) -> Result<PendingLink, BarkingError> {
    guard(move || {
        let offer = LinkOffer::from_bytes(&offer).map_err(BarkingError::from_link)?;
        let mut request = Vec::new();
        let device = Device::init(config, |path, key| {
            let (core, req) =
                Core::begin_link(path, key, &offer, &device_name, now(), &mut rand::rng())
                    .map_err(BarkingError::from_link)?;
            request = req.to_bytes();
            Ok::<_, BarkingError>(core)
        })?;
        Ok(PendingLink {
            device: Arc::new(device),
            request,
        })
    })
}

/// The name of the device behind a request, for the confirmation screen.
#[uniffi::export]
pub fn inspect_link_request(request: Vec<u8>) -> Result<String, BarkingError> {
    guard(move || {
        Ok(LinkRequest::from_bytes(&request)
            .map_err(BarkingError::from_link)?
            .name)
    })
}

#[uniffi::export]
impl Device {
    /// A new link offer (valid 10 minutes, usable once), for the QR code.
    pub fn link_offer(&self) -> Result<Vec<u8>, BarkingError> {
        guard(|| {
            self.with_core(|core| {
                let offer = core
                    .link_offer(now(), &mut rand::rng())
                    .map_err(BarkingError::from_link)?;
                Ok(offer.to_bytes().to_vec())
            })
        })
    }

    /// Accepts a request: the `.barkinglink` package for the new device.
    pub fn link_device(
        &self,
        request: Vec<u8>,
        with_history: bool,
    ) -> Result<Vec<u8>, BarkingError> {
        guard(|| {
            let req = LinkRequest::from_bytes(&request).map_err(BarkingError::from_link)?;
            self.with_core(|core| {
                let out = core
                    .link_device(&req, with_history, now(), &mut rand::rng())
                    .map_err(BarkingError::from_link)?;
                let history = out.history.as_ref().map(HistoryArchive::to_bytes);
                Ok(pack(&out.bundle.to_bytes(), history.as_deref()))
            })
        })
    }

    /// Finishes linking from a `.barkinglink` package.
    pub fn finish_link(&self, package: Vec<u8>) -> Result<(), BarkingError> {
        guard(|| {
            let (bundle, history) = unpack(&package)?;
            self.finish_link_files(bundle.to_vec(), history.map(<[u8]>::to_vec))
        })
    }

    /// Finishes linking from the separate files `barking-cli` writes.
    pub fn finish_link_files(
        &self,
        bundle: Vec<u8>,
        history: Option<Vec<u8>>,
    ) -> Result<(), BarkingError> {
        guard(|| {
            let bundle = LinkBundle::from_bytes(&bundle).map_err(BarkingError::from_link)?;
            let history = history
                .map(|h| HistoryArchive::from_bytes(&h))
                .transpose()
                .map_err(BarkingError::from_link)?;
            self.with_core(|core| {
                core.finish_link(&bundle, history.as_ref(), now())
                    .map_err(BarkingError::from_link)
            })
        })
    }

    pub fn is_pending_link(&self) -> Result<bool, BarkingError> {
        guard(|| self.with_core(|core| Ok(core.is_pending_link())))
    }
}
