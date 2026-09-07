//! SSH agent support.
//!
//! The agent holds private keys in a separate, user owned process; RDT only ever
//! sees the *public* keys and asks the agent to sign challenges.  That keeps key
//! material out of this process entirely, which is why agent authentication is
//! the recommended default.
//!
//! Two kinds of agent are supported:
//!
//! * a Unix domain socket (`SSH_AUTH_SOCK`), with a peer credential check so a
//!   world writable socket is refused;
//! * an OpenSSH agent over a named pipe on Windows (`\\.\pipe\openssh-ssh-agent`).

use std::path::{Path, PathBuf};

use rdt_types::{ErrorCode, RdtError, RdtResult};

/// Description of the agent RDT will talk to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentTransport {
    /// A Unix domain socket.
    UnixSocket(PathBuf),
    /// A Windows named pipe.
    NamedPipe(String),
}

impl AgentTransport {
    /// Locates the agent from the environment.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::Authentication`] when no agent is configured.
    pub fn detect() -> RdtResult<Self> {
        #[cfg(windows)]
        {
            if let Ok(value) = std::env::var("SSH_AUTH_SOCK") {
                if !value.trim().is_empty() {
                    return Ok(Self::NamedPipe(value));
                }
            }
            return Ok(Self::NamedPipe(r"\\.\pipe\openssh-ssh-agent".to_owned()));
        }
        #[cfg(not(windows))]
        {
            let value = std::env::var("SSH_AUTH_SOCK").map_err(|_| {
                RdtError::new(ErrorCode::Authentication, "SSH_AUTH_SOCK is not set")
            })?;
            if value.trim().is_empty() {
                return Err(RdtError::new(ErrorCode::Authentication, "SSH_AUTH_SOCK is empty"));
            }
            let path = PathBuf::from(value);
            verify_socket_permissions(&path)?;
            Ok(Self::UnixSocket(path))
        }
    }

    /// The path or pipe name, for display.
    pub fn display(&self) -> String {
        match self {
            Self::UnixSocket(path) => path.display().to_string(),
            Self::NamedPipe(name) => name.clone(),
        }
    }
}

/// Refuses an agent socket that other local users could replace.
///
/// An attacker who can write to the socket path can impersonate the agent and
/// harvest every signature request, so the socket must be owned by the current
/// user and must not be writable by anybody else.
///
/// # Errors
///
/// Returns [`ErrorCode::Permission`] when the check fails.
#[cfg(unix)]
pub fn verify_socket_permissions(path: &Path) -> RdtResult<()> {
    use std::os::unix::fs::MetadataExt;

    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        RdtError::new(ErrorCode::Io, format!("cannot inspect the agent socket: {error}"))
            .with_context("path", path.display().to_string())
    })?;
    if metadata.mode() & libc::S_IFSOCK == 0 {
        return Err(RdtError::new(
            ErrorCode::Permission,
            "SSH_AUTH_SOCK does not point at a socket",
        )
        .with_context("path", path.display().to_string()));
    }
    // SAFETY: getuid is a pure syscall wrapper with no preconditions.
    let uid = unsafe { libc::getuid() };
    if metadata.uid() != uid {
        return Err(RdtError::new(
            ErrorCode::Permission,
            "the agent socket is owned by another user",
        )
        .with_context("path", path.display().to_string()));
    }
    let mode = metadata.mode() & 0o777;
    if mode & 0o022 != 0 {
        return Err(RdtError::new(
            ErrorCode::Permission,
            format!("the agent socket is writable by others (mode {mode:o})"),
        )
        .with_context("path", path.display().to_string()));
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn verify_socket_permissions(_path: &Path) -> RdtResult<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_displays_its_target() {
        let transport = AgentTransport::UnixSocket(PathBuf::from("/tmp/agent.sock"));
        assert_eq!(transport.display(), "/tmp/agent.sock");
        let pipe = AgentTransport::NamedPipe(r"\\.\pipe\openssh-ssh-agent".to_owned());
        assert!(pipe.display().contains("openssh"));
    }

    #[test]
    fn a_missing_socket_is_refused() {
        let path = Path::new("/tmp/rdt-does-not-exist.sock");
        let error = verify_socket_permissions(path).expect_err("must fail");
        assert!(matches!(error.code(), ErrorCode::Io | ErrorCode::Permission));
    }

    #[cfg(unix)]
    #[test]
    fn detection_follows_the_environment() {
        // SAFETY: the test process is single threaded here.
        unsafe {
            std::env::remove_var("SSH_AUTH_SOCK");
        }
        assert!(AgentTransport::detect().is_err());
    }
}
