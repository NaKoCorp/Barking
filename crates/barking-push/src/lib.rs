//! `barking-push`: stateless push relay. It opens the sealed wake tokens that
//! nodes forward, rate-limits them per device token and hands them to a
//! `Pusher` (the APNs client lives in the binary). Nothing is stored and no
//! address, mailbox or token is ever logged.

pub mod apns;
pub mod config;
pub mod jwt;
pub mod limit;
pub mod server;
pub mod stats;

pub use apns::ApnsPusher;
pub use config::{ApnsConfig, RelayConfig, SealKeyFile};
pub use limit::TokenLimiter;
pub use server::{ConnLimits, PushOutcome, Pusher, bind, serve};
pub use stats::{RelayStats, StatsSnapshot, report_loop};
