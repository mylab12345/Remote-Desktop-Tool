//! Application configuration and connection profile storage.
//!
//! The whole user visible configuration lives in one TOML document so it can be
//! inspected, version controlled and backed up like any other dotfile:
//!
//! ```toml
//! schema_version = 1
//!
//! [settings]
//! theme = "dark"
//! log_level = "info"
//!
//! [[profiles]]
//! name = "build server"
//! host = "build.example.com"
//! port = 22
//! protocol = "ssh"
//! ```
//!
//! Secrets are **never** part of this document.  A profile references a secret
//! by [`rdt_types::CredentialSource`], which points at the OS keystore or the
//! encrypted vault managed by `rdt-secrets`.
//!
//! Writes are atomic (temporary file, `fsync`, rename) and the file is created
//! with owner-only permissions, so a crash mid-save cannot corrupt the store or
//! leak it to other local users.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod migrate;
mod profile;
mod settings;
mod store;

pub use migrate::{document_version, migrate};
pub use profile::ConnectionProfile;
pub use settings::{
    LogLevel, SecuritySettings, SessionSettings, Settings, Theme, UiSettings, CURRENT_SCHEMA_VERSION,
};
pub use store::{atomic_write, Config, ConfigStore, LoadError, SaveError, SortOrder};
