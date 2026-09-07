//! Shared domain types for the RDT remote access tool.
//!
//! This crate is deliberately dependency-light: it defines the vocabulary used
//! across every other crate (identifiers, secrets, authentication material,
//! protocol options and typed errors) so that higher layers never have to
//! depend on each other just to agree on a type.
#![forbid(unsafe_code)]

mod error;
mod ids;
mod proto;
mod redact;
mod rng;
mod secret;
mod timeutil;

pub use crate::error::{ErrorCode, RdtError, RdtResult};
pub use crate::ids::{IdParseError, ProfileId, SessionId};
pub use crate::proto::{
    AuthMethod, CertPolicy, ColorDepth, CredentialSource, Endpoint, HostKeyPolicy, KeyboardLayout,
    PrivateKeyAuth, Protocol, RdpOptions, ReconnectPolicy, SecretBackend, SshOptions, StoredSecret,
    TerminalOptions,
};
pub use crate::redact::{redact_secret_in, Redactor, REDACTED};
pub use crate::rng::{fill_random, RandomError};
pub use crate::secret::{Secret, SecretBytes};
pub use crate::timeutil::{format_rfc3339, format_uptime, utc_now, UtcStamp};

/// Every crate in the workspace reports the same version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Name of the product as shown in user interfaces.
pub const PRODUCT_NAME: &str = "RDT";

/// Long form of [`PRODUCT_NAME`].
pub const PRODUCT_LONG_NAME: &str = "RDT - Remote Desktop Tool";
