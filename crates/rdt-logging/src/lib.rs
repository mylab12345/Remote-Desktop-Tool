//! Logging and auditing.
//!
//! Three sinks are wired up by [`init`]:
//!
//! * a human readable line writer on standard error, filtered by `RUST_LOG`;
//! * a rotating JSON lines file for post-incident analysis;
//! * a ring buffer that backs the Logs page of the desktop client.
//!
//! Every sink is wrapped in a redacting writer, so even if a secret ends up in a
//! log statement it is replaced by `<redacted>` before it reaches a file.

pub mod audit;
pub mod buffer;
pub mod redact_writer;

use std::path::PathBuf;
use std::sync::Arc;

use parking_lot::Mutex;
use rdt_platform::AppPaths;
use rdt_types::RdtResult;
use serde::{Deserialize, Serialize};
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Layer;

use crate::buffer::LogBuffer;
use crate::redact_writer::RedactingWriter;

/// Logging configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LogConfig {
    /// Level for the console writer (`off`, `error`, `warn`, `info`, `debug`, `trace`).
    #[serde(default = "default_level")]
    pub console_level: String,
    /// Level for the file writer.
    #[serde(default = "default_file_level")]
    pub file_level: String,
    /// Whether to write the JSON file at all.
    #[serde(default = "default_true")]
    pub file_enabled: bool,
    /// Maximum size of one log file before rotation, in bytes.
    #[serde(default = "default_max_bytes")]
    pub max_bytes_per_file: usize,
    /// Number of rotated files to keep.
    #[serde(default = "default_max_files")]
    pub max_files: usize,
    /// Literal secret values that must never appear in a log line.
    #[serde(default, skip_serializing)]
    #[serde(skip_deserializing)]
    pub secrets: Vec<String>,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            console_level: default_level(),
            file_level: default_file_level(),
            file_enabled: true,
            max_bytes_per_file: default_max_bytes(),
            max_files: default_max_files(),
            secrets: Vec::new(),
        }
    }
}

const fn default_true() -> bool {
    true
}
fn default_level() -> String {
    "info".to_owned()
}
fn default_file_level() -> String {
    "debug".to_owned()
}
const fn default_max_bytes() -> usize {
    8 * 1024 * 1024
}
const fn default_max_files() -> usize {
    5
}

/// Handles returned by [`init`]; keep them alive for as long as logging is used.
#[derive(Debug)]
pub struct LogHandles {
    /// Ring buffer shared with the UI.
    pub buffer: Arc<Mutex<LogBuffer>>,
    /// Path of the log file (when file logging is enabled).
    pub log_file: Option<PathBuf>,
    /// Audit writer.
    pub audit: audit::AuditLog,
    _guard: tracing::subscriber::SetGlobalDefaultGuard,
}

/// Installs the global tracing subscriber.
///
/// Calling this twice is an error (tracing allows exactly one global default);
/// tests should use [`buffer::LogBuffer`] directly instead.
pub fn init(paths: &AppPaths, config: &LogConfig) -> RdtResult<LogHandles> {
    paths.ensure()?;
    let buffer = Arc::new(Mutex::new(LogBuffer::new(2000)));

    let redactor = build_redactor(config);
    let stderr_layer = tracing_subscriber::fmt::layer()
        .with_writer(RedactingWriter::new(
            StderrWriter,
            redactor.clone(),
            buffer.clone(),
        ))
        .with_ansi(true)
        .with_filter(filter_for(&config.console_level));

    let file_layer = if config.file_enabled {
        let appender = tracing_appender::rolling::RollingFileAppender::new(
            tracing_appender::rolling::Rotation::NEVER,
            &paths.log_dir,
            "rdt.log",
        );
        Some(
            tracing_subscriber::fmt::layer()
                .json()
                .with_writer(RedactingWriter::new(
                    appender,
                    redactor.clone(),
                    Arc::new(Mutex::new(LogBuffer::new(0))),
                ))
                .with_filter(filter_for(&config.file_level)),
        )
    } else {
        None
    };

    let audit = audit::AuditLog::open(paths.audit_file(), redactor.clone())?;

    let subscriber = tracing_subscriber::registry()
        .with(stderr_layer)
        .with(file_layer);
    let guard = subscriber.set_global_default_with_guard().map_err(|error| {
        rdt_types::RdtError::new(
            rdt_types::ErrorCode::Internal,
            format!("cannot install the logging subscriber: {error}"),
        )
    })?;

    Ok(LogHandles {
        buffer,
        log_file: config.file_enabled.then(|| paths.log_file()),
        audit,
        _guard: guard,
    })
}

/// Builds the redactor from the configured secret list.
pub fn build_redactor(config: &LogConfig) -> rdt_types::Redactor {
    let mut redactor = rdt_types::Redactor::new();
    for secret in &config.secrets {
        redactor = redactor.with_secret(secret);
    }
    redactor
}

fn filter_for(level: &str) -> EnvFilter {
    let directive = std::env::var("RUST_LOG").unwrap_or_else(|_| format!("rdt={level},warn"));
    EnvFilter::try_new(directive).unwrap_or_else(|_| EnvFilter::new("warn"))
}

/// Writer that forwards to standard error.
#[derive(Debug, Clone, Copy)]
struct StderrWriter;

impl std::io::Write for StderrWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        use std::io::Write;
        std::io::stderr().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        use std::io::Write;
        std::io::stderr().flush()
    }
}

impl<'a> MakeWriter<'a> for StderrWriter {
    type Writer = StderrWriter;

    fn make_writer(&'a self) -> Self::Writer {
        *self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redactor_is_built_from_the_config() {
        let config = LogConfig {
            secrets: vec!["topsecret".to_owned(), "ab".to_owned()],
            ..Default::default()
        };
        let redactor = build_redactor(&config);
        assert_eq!(redactor.secret_count(), 1, "short secrets are ignored");
        let line = redactor.redact("auth with topsecret failed");
        assert!(!line.contains("topsecret"));
    }

    #[test]
    fn log_config_defaults_are_safe() {
        let config = LogConfig::default();
        assert!(config.file_enabled);
        assert_eq!(config.console_level, "info");
        assert_eq!(config.file_level, "debug");
        assert!(config.max_bytes_per_file > 0);
        assert!(config.max_files > 0);
    }

    #[test]
    fn log_config_survives_a_toml_round_trip() {
        let config = LogConfig::default();
        let text = toml::to_string(&config).expect("serialize");
        let parsed: LogConfig = toml::from_str(&text).expect("deserialize");
        assert_eq!(parsed, config);
    }
}
