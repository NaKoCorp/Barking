//! `tracing` logs on stderr: never an IP address.
//!
//! Per-target filter, everything off except:
//! - `barking_node` and `barking_proto`: aggregated reports and internal errors;
//! - `quinn`, `quinn_proto`: `warn` and above, whose messages do not
//!   contain addresses (checked in the sources of quinn 0.11.12 and
//!   quinn-proto 0.11.19);
//! - `quinn_udp`: **off**, `log_sendmsg_error` writes the destination and
//!   source addresses there at `warn` level;
//! - `rustls` and the rest: off (default value).

use tracing::Subscriber;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{Layer, registry};

pub fn filter() -> Targets {
    Targets::new()
        .with_default(LevelFilter::OFF)
        .with_target("barking_node", LevelFilter::INFO)
        .with_target("barking_proto", LevelFilter::WARN)
        .with_target("quinn", LevelFilter::WARN)
        .with_target("quinn_proto", LevelFilter::WARN)
        .with_target("quinn_udp", LevelFilter::OFF)
}

/// Text subscriber (no timestamp: journald handles it) writing to `w`.
pub fn subscriber<W>(w: W) -> impl Subscriber + Send + Sync
where
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    registry().with(
        tracing_subscriber::fmt::layer()
            .with_writer(w)
            .with_ansi(false)
            .without_time()
            .with_filter(filter()),
    )
}

/// Installs the subscriber on stderr.
pub fn init_stderr() {
    let _ = tracing::subscriber::set_global_default(subscriber(std::io::stderr));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Buf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for Buf {
        type Writer = Buf;
        fn make_writer(&'a self) -> Buf {
            self.clone()
        }
    }

    fn captured(f: impl FnOnce()) -> String {
        let buf = Buf::default();
        tracing::subscriber::with_default(subscriber(buf.clone()), f);
        let bytes = buf.0.lock().unwrap().clone();
        String::from_utf8(bytes).unwrap()
    }

    #[test]
    fn quinn_udp_is_silent_even_at_error() {
        let out = captured(|| {
            tracing::warn!(target: "quinn_udp", "sendmsg error: destination: 203.0.113.9:4433");
            tracing::error!(target: "quinn_udp", "src_ip: 198.51.100.7");
            tracing::info!(target: "quinn_udp", "GSO");
        });
        assert_eq!(out, "");
    }

    #[test]
    fn quinn_keeps_warn_and_above_only() {
        let out = captured(|| {
            tracing::debug!(target: "quinn_proto::endpoint", "packet from 203.0.113.9");
            tracing::info!(target: "quinn", "connection from 203.0.113.9");
            tracing::trace!(target: "quinn_proto::connection", "x");
            tracing::warn!(target: "quinn_proto::connection", "illegal packet");
            tracing::error!(target: "quinn", "I/O error");
            tracing::warn!(target: "rustls::common_state", "alert");
            tracing::info!(target: "tokio", "x");
        });
        assert!(!out.contains("203.0.113.9"), "{out}");
        assert!(
            out.contains("illegal packet") && out.contains("I/O error"),
            "{out}"
        );
        assert!(!out.contains("alert"), "{out}");
        assert!(!out.contains(" x"), "{out}");
    }

    #[test]
    fn node_reports_pass() {
        let out = captured(|| tracing::info!(target: "barking_node::server", "report"));
        assert!(out.contains("report"));
    }
}
