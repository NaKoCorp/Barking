//! Bindings of the Barking core for the iOS and Android apps (spec iOS
//! foundations §3). The only surface the apps see: every exported function
//! is blocking, takes the database lock for the duration of the call and
//! never lets a panic cross into Swift or Kotlin.

mod device;
mod error;
mod lock;

use std::panic::{UnwindSafe, catch_unwind};

pub use device::{Contact, CreatedDevice, Device, DeviceConfig, Message, device_exists};
pub use error::BarkingError;

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
}
