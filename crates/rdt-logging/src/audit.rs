//! Append-only audit trail.
//!
//! Every security relevant action produces one JSON line: session lifecycle,
//! authentication attempts, host key decisions, file transfers, clipboard use,
//! configuration changes and vault access.  The file is append-only and each
//! record is redacted before it is written.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use rdt_types::{ErrorCode, RdtError, RdtResult, Redactor, UtcStamp};
use serde::{Deserialize, Serialize};

/// Kinds of audited events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventKind {
    /// A session started connecting.
    SessionConnect,
    /// A session reached the connected state.
    SessionEstablished,
    /// A session ended.
    SessionClosed,
    /// A reconnection attempt started.
    SessionReconnect,
    /// An authentication attempt was made.
    AuthAttempt,
    /// A host key was accepted and recorded.
    HostKeyAccepted,
    /// A host key mismatch was refused.
    HostKeyRejected,
    /// A server certificate decision was made.
    CertificateDecision,
    /// A file was uploaded or downloaded.
    FileTransfer,
    /// Clipboard content crossed the RDP channel.
    ClipboardTransfer,
    /// A configuration or profile was changed.
    ConfigChanged,
    /// The secret vault was unlocked, locked or created.
    VaultAccess,
    /// The agent service was installed or removed.
    ServiceChanged,
    /// A command was executed on the remote side.
    CommandExecuted,
}

impl AuditEventKind {
    /// Stable identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SessionConnect => "session_connect",
            Self::SessionEstablished => "session_established",
            Self::SessionClosed => "session_closed",
            Self::SessionReconnect => "session_reconnect",
            Self::AuthAttempt => "auth_attempt",
            Self::HostKeyAccepted => "host_key_accepted",
            Self::HostKeyRejected => "host_key_rejected",
            Self::CertificateDecision => "certificate_decision",
            Self::FileTransfer => "file_transfer",
            Self::ClipboardTransfer => "clipboard_transfer",
            Self::ConfigChanged => "config_changed",
            Self::VaultAccess => "vault_access",
            Self::ServiceChanged => "service_changed",
            Self::CommandExecuted => "command_executed",
        }
    }
}

/// Outcome of an audited action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    /// The action succeeded.
    Success,
    /// The action failed.
    Failure,
    /// The action was refused by policy.
    Denied,
    /// The action is informational only.
    Info,
}

/// One audit record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// When it happened.
    pub stamp: UtcStamp,
    /// What happened.
    pub kind: AuditEventKind,
    /// Outcome.
    pub outcome: AuditOutcome,
    /// Session identifier, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    /// Profile identifier, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// Free form, already redacted detail.
    pub detail: String,
}

impl AuditEvent {
    /// Builds an informational event.
    pub fn info(kind: AuditEventKind, detail: impl Into<String>) -> Self {
        Self::new(kind, AuditOutcome::Info, detail)
    }

    /// Builds an event with an explicit outcome.
    pub fn new(kind: AuditEventKind, outcome: AuditOutcome, detail: impl Into<String>) -> Self {
        Self {
            stamp: UtcStamp::now(),
            kind,
            outcome,
            session: None,
            profile: None,
            detail: detail.into(),
        }
    }

    /// Attaches a session identifier.
    pub fn with_session(mut self, session: impl Into<String>) -> Self {
        self.session = Some(session.into());
        self
    }

    /// Attaches a profile identifier.
    pub fn with_profile(mut self, profile: impl Into<String>) -> Self {
        self.profile = Some(profile.into());
        self
    }
}

/// Append-only writer for the audit trail.
#[derive(Debug, Clone)]
pub struct AuditLog {
    path: PathBuf,
    redactor: Redactor,
}

impl AuditLog {
    /// Opens (or creates) the audit file.
    pub fn open(path: impl Into<PathBuf>, redactor: Redactor) -> RdtResult<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Touch the file so that permission problems surface immediately.
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|error| {
                RdtError::new(
                    ErrorCode::Io,
                    format!("cannot open the audit file {}: {error}", path.display()),
                )
            })?;
        rdt_platform::restrict_to_owner(&path)?;
        Ok(Self { path, redactor })
    }

    /// A sink that discards records (used by tests and by `--no-audit`).
    pub fn null() -> Self {
        Self {
            path: PathBuf::from("/dev/null"),
            redactor: Redactor::new(),
        }
    }

    /// Path of the audit file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Appends one record.
    pub fn record(&self, mut event: AuditEvent) -> RdtResult<()> {
        event.detail = self.redactor.redact(&event.detail);
        let mut line = serde_json::to_string(&event)
            .map_err(|error| RdtError::new(ErrorCode::Internal, format!("cannot encode audit event: {error}")))?;
        line.push('\n');
        let mut file = OpenOptions::new().create(true).append(true).open(&self.path)?;
        file.write_all(line.as_bytes())?;
        file.flush()?;
        Ok(())
    }

    /// Reads the last `limit` records, ignoring malformed lines.
    pub fn read_recent(&self, limit: usize) -> RdtResult<Vec<AuditEvent>> {
        read_recent_from(&self.path, limit)
    }
}

/// Reads the last `limit` records of an audit file.
pub fn read_recent_from(path: &Path, limit: usize) -> RdtResult<Vec<AuditEvent>> {
    let content = match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(RdtError::from(error)),
    };
    let mut events: Vec<AuditEvent> = content
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();
    let skip = events.len().saturating_sub(limit);
    events.drain(..skip);
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rdt-audit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create dir");
        dir.join(name)
    }

    #[test]
    fn records_are_appended_and_read_back() {
        let path = temp_path("basic.jsonl");
        let _ = std::fs::remove_file(&path);
        let log = AuditLog::open(path.clone(), Redactor::new().with_secret("s3cr3tvalue")).expect("open");
        log.record(
            AuditEvent::new(
                AuditEventKind::AuthAttempt,
                AuditOutcome::Success,
                "password s3cr3tvalue accepted for alice",
            )
            .with_session("abcd")
            .with_profile("ef01"),
        )
        .expect("record");
        log.record(AuditEvent::info(AuditEventKind::SessionClosed, "closed by user")).expect("record");

        let events = log.read_recent(10).expect("read");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].kind, AuditEventKind::AuthAttempt);
        assert_eq!(events[0].session.as_deref(), Some("abcd"));
        assert!(!events[0].detail.contains("s3cr3tvalue"), "{:?}", events[0]);
        assert!(events[0].detail.contains("<redacted>"));
        assert_eq!(events[1].outcome, AuditOutcome::Info);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn read_recent_limits_the_result() {
        let path = temp_path("limit.jsonl");
        let _ = std::fs::remove_file(&path);
        let log = AuditLog::open(path.clone(), Redactor::new()).expect("open");
        for index in 0..5 {
            log.record(AuditEvent::info(AuditEventKind::FileTransfer, format!("file {index}")))
                .expect("record");
        }
        let last_two = log.read_recent(2).expect("read");
        assert_eq!(last_two.len(), 2);
        assert_eq!(last_two[1].detail, "file 4");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn missing_file_reads_as_empty() {
        let events = read_recent_from(Path::new("/definitely/not/here.jsonl"), 10).expect("read");
        assert!(events.is_empty());
    }

    #[test]
    fn malformed_lines_are_skipped() {
        let path = temp_path("malformed.jsonl");
        std::fs::write(&path, "not json\n{\"kind\":\"session_closed\"}\n").expect("write");
        let events = read_recent_from(&path, 10).expect("read");
        assert!(events.is_empty());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn event_kinds_have_stable_names() {
        assert_eq!(AuditEventKind::HostKeyRejected.as_str(), "host_key_rejected");
        let json = serde_json::to_string(AuditOutcome::Denied).expect("serialize");
        assert_eq!(json, "\"denied\"");
    }
}
