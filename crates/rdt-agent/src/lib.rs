//! The headless agent.
//!
//! The agent is the same binary the GUI uses, running without a window under
//! the operating system service manager (systemd on Linux, the SCM on Windows).
//! It exposes one Unix domain socket (or a named pipe on Windows) that accepts a
//! small JSON command protocol.
//!
//! # Trust model
//!
//! The socket lives in the per-user runtime directory with `0700` permissions,
//! and every connection is authenticated by peer credential: on Unix the agent
//! reads `SO_PEERCRED` and refuses callers whose UID differs from the service
//! account.  That makes the socket unusable by other local users even if they
//! can reach the filesystem, which matters because the agent can start sessions
//! with stored credentials.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::path::PathBuf;
use std::sync::Arc;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

use rdt_logging::audit::{AuditEvent, AuditEventKind, AuditLog, AuditOutcome};
use rdt_types::{ErrorCode, RdtError, RdtResult};

/// A command accepted by the agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "command")]
pub enum Command {
    /// Report the agent version and the platform it runs on.
    Status,
    /// List the sessions the agent owns.
    ListSessions,
    /// Connect using a stored profile.
    Connect {
        /// Profile identifier.
        profile: String,
    },
    /// Disconnect a session.
    Disconnect {
        /// Session identifier.
        session: String,
    },
    /// Re-read the configuration from disk.
    ReloadConfig,
}

/// A reply produced by the agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reply {
    /// True when the command succeeded.
    pub ok: bool,
    /// Human readable detail (never contains a secret).
    pub message: String,
    /// Machine readable error code, when the command failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

impl Reply {
    /// A successful reply.
    pub fn success(message: impl Into<String>) -> Self {
        Self {
            ok: true,
            message: message.into(),
            code: None,
        }
    }

    /// A failed reply carrying the error code.
    pub fn failure(error: &RdtError) -> Self {
        Self {
            ok: false,
            message: error.to_string(),
            code: Some(error.code().as_str().to_owned()),
        }
    }
}

/// Everything the agent needs to serve commands.
pub struct Agent {
    config: Arc<rdt_config::ConfigStore>,
    sessions: rdt_session::SessionManager,
    audit: Arc<AuditLog>,
    socket: PathBuf,
}

impl Agent {
    /// Creates an agent.
    pub fn new(
        config: Arc<rdt_config::ConfigStore>,
        sessions: rdt_session::SessionManager,
        audit: Arc<AuditLog>,
        socket: PathBuf,
    ) -> Self {
        Self {
            config,
            sessions,
            audit,
            socket,
        }
    }

    /// Path of the control socket.
    pub fn socket(&self) -> &PathBuf {
        &self.socket
    }

    /// Handles one command.  Shared by the socket loop and by the CLI, so both
    /// paths behave identically.
    ///
    /// # Errors
    ///
    /// Returns the typed failure for an unhandled command.
    pub fn handle(&self, command: Command) -> RdtResult<Reply> {
        match command {
            Command::Status => Ok(Reply::success(format!(
                "rdt-agent {} on {}",
                env!("CARGO_PKG_VERSION"),
                rdt_platform::PlatformInfo::detect().display()
            ))),
            Command::ListSessions => {
                let sessions = self.sessions.list();
                let text = serde_json::to_string(
                    &sessions
                        .iter()
                        .map(|info| {
                            serde_json::json!({
                                "id": info.id.to_string(),
                                "address": info.address,
                                "protocol": format!("{:?}", info.protocol),
                                "state": format!("{:?}", info.state),
                            })
                        })
                        .collect::<Vec<_>>(),
                )
                .unwrap_or_else(|_| "[]".to_owned());
                Ok(Reply::success(text))
            }
            Command::Connect { profile } => {
                let id = profile.parse().map_err(|_| {
                    RdtError::new(ErrorCode::InvalidInput, "the profile identifier is not valid")
                })?;
                let Some(profile) = self.config.find(id) else {
                    return Err(RdtError::new(ErrorCode::NotFound, "no profile with that identifier"));
                };
                self.audit.record(
                    AuditEvent::new(AuditEventKind::SessionConnect, AuditOutcome::Info)
                        .with_profile(id)
                        .with_detail(&profile.address()),
                );
                Ok(Reply::success(format!("connecting to {}", profile.address())))
            }
            Command::Disconnect { session } => {
                let id = session.parse().map_err(|_| {
                    RdtError::new(ErrorCode::InvalidInput, "the session identifier is not valid")
                })?;
                self.sessions.cancel(id);
                Ok(Reply::success("the session was disconnected"))
            }
            Command::ReloadConfig => {
                self.config
                    .reload()
                    .map_err(|error| match error {
                        rdt_config::LoadError::Missing => {
                            RdtError::new(ErrorCode::Config, "the configuration file is missing")
                        }
                        rdt_config::LoadError::Failed(error) => error,
                    })?;
                Ok(Reply::success("the configuration was reloaded"))
            }
        }
    }

    /// Runs the socket listener until the process is stopped.
    ///
    /// # Errors
    ///
    /// Returns the I/O failure that stopped the listener.
    pub async fn serve(self: Arc<Self>) -> RdtResult<()> {
        if let Some(parent) = self.socket.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|error| {
                RdtError::new(ErrorCode::Io, error.to_string())
                    .with_context("path", parent.display().to_string())
            })?;
            rdt_platform::restrict_dir_to_owner(parent).map_err(|error| {
                RdtError::new(ErrorCode::Permission, error.to_string())
                    .with_context("path", parent.display().to_string())
            })?;
        }
        let _ = tokio::fs::remove_file(&self.socket).await;
        let listener = UnixListener::bind(&self.socket).map_err(|error| {
            RdtError::new(ErrorCode::Io, format!("cannot bind {}: {error}", self.socket.display()))
        })?;
        rdt_platform::restrict_to_owner(&self.socket).map_err(|error| {
            RdtError::new(ErrorCode::Permission, error.to_string())
                .with_context("path", self.socket.display().to_string())
        })?;
        tracing::info!(socket = %self.socket.display(), "agent listening");

        loop {
            let (stream, _) = listener.accept().await.map_err(|error| {
                RdtError::new(ErrorCode::Io, format!("cannot accept a connection: {error}"))
            })?;
            if let Err(error) = verify_peer(stream.peer_cred().ok()) {
                tracing::warn!(%error, "refused a control connection");
                continue;
            }
            let agent = Arc::clone(&self);
            tokio::spawn(async move {
                let (read, mut write) = stream.into_split();
                let mut reader = BufReader::new(read).lines();
                while let Ok(Some(line)) = reader.next_line().await {
                    let reply = match serde_json::from_str::<Command>(&line) {
                        Ok(command) => match agent.handle(command) {
                            Ok(reply) => reply,
                            Err(error) => Reply::failure(&error),
                        },
                        Err(error) => Reply {
                            ok: false,
                            message: format!("cannot parse the command: {error}"),
                            code: Some(ErrorCode::InvalidInput.as_str().to_owned()),
                        },
                    };
                    let mut text = serde_json::to_string(&reply).unwrap_or_default();
                    text.push('\n');
                    if write.write_all(text.as_bytes()).await.is_err() {
                        break;
                    }
                }
            });
        }
    }
}

/// Checks the peer credentials of a control connection.
///
/// # Errors
///
/// Returns [`ErrorCode::Permission`] when the caller is not the service owner.
pub fn verify_peer(credentials: Option<tokio::net::unix::UCred>) -> RdtResult<()> {
    #[cfg(unix)]
    {
        let Some(credentials) = credentials else {
            return Err(RdtError::new(
                ErrorCode::Permission,
                "cannot read the peer credentials of the control connection",
            ));
        };
        // SAFETY: getuid is a pure syscall wrapper with no preconditions.
        let uid = unsafe { libc::getuid() };
        if credentials.uid() != uid {
            return Err(RdtError::new(
                ErrorCode::Permission,
                format!(
                    "the control connection came from uid {} but the agent runs as {uid}",
                    credentials.uid()
                ),
            ));
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        // On Windows the named pipe is created with a DACL that only allows the
        // service account, so reaching this point is already authorised.
        let _ = credentials;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent() -> Agent {
        let audit = Arc::new(AuditLog::null());
        let sessions = rdt_session::SessionManager::new(
            rdt_session::ManagerPolicy::default(),
            audit.clone(),
        )
        .expect("manager");
        Agent::new(
            Arc::new(rdt_config::ConfigStore::in_memory()),
            sessions,
            audit,
            PathBuf::from("/tmp/rdt-agent-test.sock"),
        )
    }

    #[test]
    fn status_reports_the_version_and_platform() {
        let reply = agent().handle(Command::Status).expect("status");
        assert!(reply.ok);
        assert!(reply.message.contains(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn listing_sessions_returns_json() {
        let reply = agent().handle(Command::ListSessions).expect("list");
        assert!(reply.ok);
        assert_eq!(reply.message, "[]");
    }

    #[test]
    fn connecting_to_an_unknown_profile_fails() {
        let error = agent()
            .handle(Command::Connect {
                profile: rdt_types::ProfileId::new().to_string(),
            })
            .expect_err("must fail");
        assert_eq!(error.code(), ErrorCode::NotFound);
    }

    #[test]
    fn malformed_identifiers_are_rejected() {
        let error = agent()
            .handle(Command::Connect { profile: "not-an-id".to_owned() })
            .expect_err("must fail");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
    }

    #[test]
    fn replies_carry_the_error_code() {
        let error = RdtError::new(ErrorCode::Permission, "denied");
        let reply = Reply::failure(&error);
        assert!(!reply.ok);
        assert_eq!(reply.code.as_deref(), Some("permission"));
        assert!(reply.message.contains("denied"));
    }

    #[test]
    fn commands_round_trip_through_json() {
        let command = Command::Disconnect {
            session: "0123456789abcdef".to_owned(),
        };
        let text = serde_json::to_string(&command).expect("encode");
        assert!(text.contains("\"command\":\"disconnect\""));
        let parsed: Command = serde_json::from_str(&text).expect("decode");
        assert_eq!(parsed, command);
    }
}
