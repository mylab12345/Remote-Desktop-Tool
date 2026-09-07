//! Embedded RDP client built on [IronRDP](https://github.com/Devolutions/IronRDP).
//!
//! The whole RDP session is rendered **inside** the application: the server's
//! bitmap updates are decoded into a BGRA framebuffer
//! ([`Framebuffer`]) that the UI uploads as a texture, keyboard and mouse input
//! is encoded with `ironrdp-input`, the window can be resized at runtime through
//! the Display Control virtual channel and the clipboard is bridged with
//! [`ClipboardBridge`].  No external RDP client or window is ever launched.
//!
//! # Transport security
//!
//! TLS is provided by `ironrdp-tls` on top of `rustls` with the `ring`
//! provider.  Certificates are validated against the platform root store
//! (`webpki-roots`), and the [`CertPolicy`] selected by the profile decides what
//! happens when validation cannot succeed:
//!
//! * [`CertPolicy::Verify`] — the connection fails;
//! * [`CertPolicy::VerifyOrPinned`] — a matching SHA-256 fingerprint is accepted;
//! * [`CertPolicy::TrustOnFirstUse`] — the fingerprint is recorded on first
//!   connect and any later change is a hard failure.
//!
//! Self-signed certificates presented by RDP servers are the normal case, which
//! is why pinning rather than "accept anything" is the safe default.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod clipboard;
pub mod framebuffer;
pub mod session;
pub mod tls;

pub use clipboard::{ClipboardBridge, ClipboardFormat, ClipboardOperation};
pub use framebuffer::{DamageRect, Framebuffer};
pub use session::{RdpEvent, RdpInput, RdpSession, RdpTarget, SessionMetrics};
pub use tls::{CertificateDecision, CertificateVerifier, PinnedCertificates};
