//! Bindings of the Barking core for the iOS and Android apps (spec iOS
//! foundations §3). The only surface the apps see: every exported function
//! is blocking, takes the database lock for the duration of the call and
//! never lets a panic cross into Swift or Kotlin.

mod contacts;
mod delivery;
mod device;
mod error;
mod identity;
mod link;
mod lock;
mod log;
mod messages;
mod net;
mod push;
mod route;

use std::panic::{UnwindSafe, catch_unwind};

pub use contacts::{CardPreview, inspect_card, inspect_card_text};
pub use delivery::{
    DeleteOutcome, Delivery, DeliveryChange, DeliveryCounts, DeliveryRowInfo, DeliveryState,
    DeliveryUpdate, DeviceDelivery, MessageDelivery, OwnCopies, PendingKind, PendingMessage,
    PendingPackets, PendingSync, RelayHop,
};
pub use device::{
    Contact, CreatedDevice, Device, DeviceConfig, Message, create_device, device_exists,
};
pub use error::{BarkingError, LinkReason};
pub use identity::{MyDeviceInfo, RemovedInfo, bip39_words, recover_device};
pub use link::{PendingLink, begin_link, inspect_link_request};
pub use log::{LogEntry, log_arg_tokens, log_keys};
pub use messages::{ChatSummary, KeyChange, UnreadCount};
pub use net::{LeaveState, NewMessage, NodeInfo, SyncSummary};
pub use push::PushSettings;
pub use route::RouteStepInfo;

uniffi::setup_scaffolding!();

/// Runs one exported call: a panic becomes `Internal`, without its message
/// (it may hold data).
pub(crate) fn guard<T>(
    f: impl FnOnce() -> Result<T, BarkingError> + UnwindSafe,
) -> Result<T, BarkingError> {
    catch_unwind(f).unwrap_or_else(|_| Err(BarkingError::internal("panic")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn panic_becomes_internal() {
        let r: Result<(), BarkingError> = guard(|| panic!("secret detail"));
        match r {
            Err(BarkingError::Internal { detail }) => assert!(!detail.contains("secret")),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn retry_errors_keep_their_own_variant() {
        use barking_core::CoreError;
        assert!(matches!(
            BarkingError::from(CoreError::NoSession),
            BarkingError::NoSession
        ));
        assert!(matches!(
            BarkingError::from(CoreError::NothingToRetry),
            BarkingError::NothingToRetry
        ));
    }
}
