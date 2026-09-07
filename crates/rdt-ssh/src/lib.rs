//! SSH client implementation for RDT, built on [`russh`].
//!
//! The crate provides everything above the transport:
//!
//! * [`known_hosts`] — strict, OpenSSH compatible host key verification;
//! * [`SshConnection`] — connect, authenticate, open an interactive PTY,
//!   resize it, send keepalives and shut down cleanly;
//! * [`SftpClient`] — directory listing, upload, download, remove and rename
//!   with progress reporting and cancellation;
//! * [`ClientHandler`] — the [`russh::client::Handler`] implementation that
//!   enforces the host key policy and forwards channel events.
//!
//! Cancellation is cooperative and uniform: every long running operation takes a
//! [`CancellationToken`] (see `rdt_session`) or is driven by dropping the
//! returned future, so a user pressing "cancel" never leaves a half written
//! file or a dangling socket.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod agent;
pub mod handler;
pub mod known_hosts;
pub mod session;
pub mod sftp;

pub use handler::{ClientHandler, HostKeyDecision};
pub use known_hosts::{fingerprint, HostKeyStatus, KnownHostEntry, KnownHosts, Marker};
pub use session::{
    SshAuthMethod, SshConnection, SshEvent, SshOptions as ConnectionOptions, TerminalSize,
};
pub use sftp::{SftpClient, TransferDirection, TransferProgress};
