//! The per-session command/event interface used by the UI.

use tokio::sync::mpsc;

use rdt_types::SessionId;

/// Commands the UI can send to one session.
#[derive(Debug, Clone)]
pub enum SessionCommand {
    /// Terminal input for an SSH session.
    TerminalInput(Vec<u8>),
    /// New terminal geometry.
    Resize {
        /// Columns.
        cols: u32,
        /// Rows.
        rows: u32,
    },
    /// Pointer or keyboard input for an RDP session.
    RemoteInput(Vec<u8>),
    /// Text to place on the remote clipboard.
    Clipboard(String),
    /// Start an SFTP listing of a path.
    ListDirectory(String),
    /// Upload a local file.
    Upload {
        /// Local path.
        local: String,
        /// Remote path.
        remote: String,
    },
    /// Download a remote file.
    Download {
        /// Remote path.
        remote: String,
        /// Local path.
        local: String,
    },
    /// Cancel the transfer in progress.
    CancelTransfer,
    /// End the session.
    Disconnect,
}

/// Events a session reports to the UI.
#[derive(Debug, Clone)]
pub enum SessionEvent {
    /// Terminal output.
    Output(Vec<u8>),
    /// A new frame for the RDP view.
    Frame,
    /// A transfer made progress.
    TransferProgress {
        /// Remote path.
        path: String,
        /// Bytes transferred.
        transferred: u64,
        /// Total bytes, when known.
        total: Option<u64>,
    },
    /// A transfer finished.
    TransferComplete {
        /// Remote path.
        path: String,
        /// Bytes transferred.
        bytes: u64,
    },
    /// A transfer failed.
    TransferFailed {
        /// Remote path.
        path: String,
        /// Reason.
        reason: String,
    },
    /// A remote directory listing.
    Directory {
        /// Listed path.
        path: String,
        /// Entry names with a directory flag.
        entries: Vec<(String, bool, Option<u64>)>,
    },
    /// The session needs a password or OTP.
    CredentialNeeded {
        /// Text shown next to the prompt.
        prompt: String,
        /// Whether the answer may be echoed.
        echo: bool,
    },
    /// The session ended.
    Closed(String),
}

/// A handle on one session.
#[derive(Debug, Clone)]
pub struct SessionHandle {
    /// The session this handle controls.
    pub id: SessionId,
    commands: mpsc::UnboundedSender<SessionCommand>,
}

impl SessionHandle {
    /// Sends a command.
    ///
    /// # Errors
    ///
    /// Returns [`rdt_types::ErrorCode::SessionState`] when the session ended.
    pub fn send(&self, command: SessionCommand) -> rdt_types::RdtResult<()> {
        self.commands.send(command).map_err(|_| {
            rdt_types::RdtError::new(rdt_types::ErrorCode::SessionState, "the session is closed")
        })
    }

    /// Disconnects the session.
    pub fn disconnect(&self) {
        let _ = self.send(SessionCommand::Disconnect);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_handle_reports_a_closed_session() {
        let (tx, rx) = mpsc::unbounded_channel();
        drop(rx);
        let handle = SessionHandle { id: SessionId::new(), commands: tx };
        let error = handle.send(SessionCommand::Disconnect).expect_err("must fail");
        assert_eq!(error.code(), rdt_types::ErrorCode::SessionState);
    }

    #[test]
    fn commands_reach_the_session() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let handle = SessionHandle { id: SessionId::new(), commands: tx };
        handle.send(SessionCommand::TerminalInput(b"ls\n".to_vec())).expect("send");
        handle.disconnect();
        assert!(matches!(rx.blocking_recv(), Some(SessionCommand::TerminalInput(_))));
        assert!(matches!(rx.blocking_recv(), Some(SessionCommand::Disconnect)));
    }
}
