//! Shared helpers of the barking-ffi integration tests.
#![allow(dead_code)]

use std::sync::Arc;

use barking_ffi::{Device, DeviceConfig};

pub fn config(dir: &tempfile::TempDir, key_byte: u8) -> DeviceConfig {
    DeviceConfig {
        db_path: dir.path().join("barking.db").display().to_string(),
        lock_path: dir.path().join("barking.lock").display().to_string(),
        db_key: vec![key_byte; 32],
        lock_timeout_ms: 1_000,
        allow_private: true,
    }
}

/// A new identity named `name` (display name set) in `dir`.
pub fn device(dir: &tempfile::TempDir, key_byte: u8, name: &str) -> Arc<Device> {
    let d = Device::create(config(dir, key_byte), format!("{name}-phone"))
        .unwrap()
        .device;
    d.set_display_name(name.to_owned()).unwrap();
    d
}
