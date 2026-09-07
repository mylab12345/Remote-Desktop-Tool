//! Typed errors shared by every crate in the workspace.
//!
//! A single error type keeps error handling at the UI boundary trivial while the
//! [`ErrorCode`] discriminant keeps it precise: the UI can react to
//! [`ErrorCode::HostKeyMismatch`] differently from [`ErrorCode::Timeout`]
//! without string matching, and audit records stay machine readable.

use std::fmt;

/// Machine readable classification of a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// A configuration file was missing, malformed or failed validation.
    Config,
    /// An I/O operation failed.
    Io,
    /// The operation needs privileges the process does not have.
    Permission,
    /// A cryptographic operation failed (AEAD, KDF, key parsing, …).
    Crypto,
    /// The encrypted secret vault could not be opened or written.
    Vault,
    /// The operating system keyring rejected the request or is unavailable.
    Keystore,
    /// A connection could not be established or dropped unexpectedly.
    Network,
    /// An operation exceeded its deadline.
    Timeout,
    /// The operation was cancelled by the user or by a shutdown.
    Cancelled,
    /// The remote side violated the protocol.
    Protocol,
    /// Authentication was refused by the remote side.
    Authentication,
    /// The host key is unknown and the policy forbids accepting it.
    HostKeyUnknown,
    /// The host key changed compared to the recorded one.
    HostKeyMismatch,
    /// TLS negotiation or certificate validation failed.
    Tls,
    /// A file transfer (SFTP) failed.
    Transfer,
    /// The terminal emulator rejected the input.
    Terminal,
    /// The session is not in a state that allows the requested operation.
    SessionState,
    /// The platform does not support the requested operation.
    Platform,
    /// A service could not be installed, started or removed.
    Service,
    /// A referenced object (profile, session, file, …) does not exist.
    NotFound,
    /// The operation is not supported on this platform or by the peer.
    Unsupported,
    /// The caller supplied an invalid argument.
    InvalidInput,
    /// An internal invariant was violated; please report it.
    Internal,
}

impl ErrorCode {
    /// Short, stable identifier suitable for logs, metrics and the audit trail.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Config => "config",
            Self::Io => "io",
            Self::Permission => "permission",
            Self::Crypto => "crypto",
            Self::Vault => "vault",
            Self::Keystore => "keystore",
            Self::Network => "network",
            Self::Timeout => "timeout",
            Self::Cancelled => "cancelled",
            Self::Protocol => "protocol",
            Self::Authentication => "authentication",
            Self::HostKeyUnknown => "host_key_unknown",
            Self::HostKeyMismatch => "host_key_mismatch",
            Self::Tls => "tls",
            Self::Transfer => "transfer",
            Self::Terminal => "terminal",
            Self::SessionState => "session_state",
            Self::Platform => "platform",
            Self::Service => "service",
            Self::NotFound => "not_found",
            Self::Unsupported => "unsupported",
            Self::InvalidInput => "invalid_input",
            Self::Internal => "internal",
        }
    }

    /// Whether the failure is worth retrying (used by the reconnection policy).
    pub fn is_retryable(self) -> bool {
        matches!(
            self,
            Self::Network | Self::Timeout | Self::SessionState | Self::Internal
        )
    }

    /// Whether the failure needs a human decision rather than a retry.
    pub fn needs_user_decision(self) -> bool {
        matches!(
            self,
            Self::HostKeyUnknown
                | Self::HostKeyMismatch
                | Self::Tls
                | Self::Authentication
                | Self::Permission
        )
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The workspace error type.
#[derive(Debug)]
pub struct RdtError {
    code: ErrorCode,
    message: String,
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    context: Vec<String>,
}

impl RdtError {
    /// Creates an error from a code and a human readable message.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            source: None,
            context: Vec::new(),
        }
    }

    /// Attaches an underlying error as the cause.
    pub fn with_source(mut self, source: impl std::error::Error + Send + Sync + 'static) -> Self {
        self.source = Some(Box::new(source));
        self
    }

    /// Adds a context line; the most recently added line is rendered first.
    pub fn context(mut self, context: impl Into<String>) -> Self {
        self.context.push(context.into());
        self
    }

    /// The error classification.
    pub fn code(&self) -> ErrorCode {
        self.code
    }

    /// The human readable message (context lines are not included).
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Whether this error should be surfaced to the user as a retryable problem.
    pub fn is_retryable(&self) -> bool {
        self.code.is_retryable()
    }

    /// Renders the whole chain as a single line, suitable for the UI status bar.
    pub fn to_single_line(&self) -> String {
        let mut parts: Vec<String> = Vec::with_capacity(self.context.len() + 2);
        parts.extend(self.context.iter().rev().cloned());
        parts.push(self.message.clone());
        if let Some(source) = &self.source {
            parts.push(source.to_string());
        }
        parts.join(": ")
    }
}

impl fmt::Display for RdtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.to_single_line())
    }
}

impl std::error::Error for RdtError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|boxed| boxed.as_ref() as &(dyn std::error::Error + 'static))
    }
}

impl From<std::io::Error> for RdtError {
    fn from(error: std::io::Error) -> Self {
        let code = match error.kind() {
            std::io::ErrorKind::PermissionDenied => ErrorCode::Permission,
            std::io::ErrorKind::NotFound => ErrorCode::Io,
            std::io::ErrorKind::TimedOut => ErrorCode::Timeout,
            std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::UnexpectedEof => ErrorCode::Network,
            std::io::ErrorKind::Interrupted => ErrorCode::Cancelled,
            _ => ErrorCode::Io,
        };
        Self::new(code, error.to_string()).with_source(error)
    }
}

/// Convenience alias used across the workspace.
pub type RdtResult<T> = Result<T, RdtError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct Inner;

    impl fmt::Display for Inner {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("inner boom")
        }
    }

    impl std::error::Error for Inner {}

    #[test]
    fn renders_code_message_and_source() {
        let error = RdtError::new(ErrorCode::Network, "dial failed")
            .context("connecting to host")
            .with_source(Inner);
        let text = error.to_string();
        assert!(text.starts_with("network: "), "{text}");
        assert!(text.contains("connecting to host"));
        assert!(text.contains("dial failed"));
        assert!(text.contains("inner boom"));
        assert!(std::error::Error::source(&error).is_some());
    }

    #[test]
    fn io_errors_are_classified() {
        let denied = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "nope");
        assert_eq!(RdtError::from(denied).code(), ErrorCode::Permission);
        let refused = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "nope");
        assert_eq!(RdtError::from(refused).code(), ErrorCode::Network);
    }

    #[test]
    fn retry_classification_is_stable() {
        assert!(ErrorCode::Network.is_retryable());
        assert!(!ErrorCode::HostKeyMismatch.is_retryable());
        assert!(ErrorCode::HostKeyMismatch.needs_user_decision());
        assert!(!ErrorCode::Network.needs_user_decision());
    }

    #[test]
    fn codes_are_stable_strings() {
        assert_eq!(ErrorCode::HostKeyUnknown.as_str(), "host_key_unknown");
        assert_eq!(ErrorCode::Tls.as_str(), "tls");
        assert_eq!(ErrorCode::Tls.to_string(), "tls");
    }
}
