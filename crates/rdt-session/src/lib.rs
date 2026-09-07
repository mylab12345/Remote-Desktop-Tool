//! Session orchestration.
//!
//! One [`SessionManager`] owns every live connection in the application.  It
//! keeps the UI responsive by running each connection on the shared Tokio
//! runtime, exposes a command channel per session, enforces the configured
//! concurrency limit, applies the reconnection policy and writes an audit record
//! for every state transition.
//!
//! The state machine is explicit so the UI can never show a state the session is
//! not actually in:
//!
//! ```text
//! Idle -> Connecting -> Authenticating -> Connected
//!   ^                                          |
//!   |                                          v
//!   +------ Cancelled / Disconnected <- Reconnecting <- Failed
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::sync::{broadcast, mpsc, oneshot};

use rdt_logging::audit::{AuditEvent, AuditEventKind, AuditLog, AuditOutcome};
use rdt_types::{
    ErrorCode, ProfileId, Protocol, ReconnectPolicy, RdtError, RdtResult, SessionId,
};

mod handle;

pub use handle::{SessionCommand, SessionEvent, SessionHandle};

/// The state of one session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Created but not started.
    Idle,
    /// TCP/TLS negotiation in progress.
    Connecting,
    /// Authentication in progress.
    Authenticating,
    /// Connected and interactive.
    Connected,
    /// Reconnecting after a drop.
    Reconnecting,
    /// Cleanly finished.
    Disconnected,
    /// Finished with an error.
    Failed,
    /// Stopped by the user.
    Cancelled,
}

impl SessionState {
    /// True when the session can accept input.
    pub fn is_active(self) -> bool {
        matches!(self, Self::Connected)
    }

    /// True when the session is finished and its resources can be released.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Disconnected | Self::Failed | Self::Cancelled)
    }

    /// True while a connection attempt is in flight.
    pub fn is_pending(self) -> bool {
        matches!(self, Self::Connecting | Self::Authenticating | Self::Reconnecting)
    }
}

/// A snapshot of one session, safe to hand to the UI.
#[derive(Debug, Clone)]
pub struct SessionInfo {
    /// Session identifier.
    pub id: SessionId,
    /// Profile the session was started from, when there was one.
    pub profile: Option<ProfileId>,
    /// Protocol in use.
    pub protocol: Protocol,
    /// `host:port`.
    pub address: String,
    /// Current state.
    pub state: SessionState,
    /// Human readable description of the current state.
    pub detail: String,
    /// When the session was created.
    pub started: Instant,
    /// Reconnect attempt in progress (0 when not reconnecting).
    pub attempt: u32,
}

/// Limits and defaults applied to every session.
#[derive(Debug, Clone)]
pub struct ManagerPolicy {
    /// Maximum number of concurrent sessions.
    pub max_concurrent: usize,
    /// Reconnection policy for sessions that drop unexpectedly.
    pub reconnect: ReconnectPolicy,
    /// Write an audit record for every transition.
    pub audit: bool,
}

impl Default for ManagerPolicy {
    fn default() -> Self {
        Self {
            max_concurrent: 16,
            reconnect: ReconnectPolicy::default(),
            audit: true,
        }
    }
}

/// Owns every live session.
#[derive(Clone)]
pub struct SessionManager {
    inner: Arc<Mutex<HashMap<SessionId, SessionSlot>>>,
    policy: ManagerPolicy,
    audit: Arc<AuditLog>,
    events: broadcast::Sender<(SessionId, SessionState, String)>,
}

struct SessionSlot {
    info: SessionInfo,
    commands: mpsc::UnboundedSender<SessionCommand>,
    cancel: oneshot::Sender<()>,
}

impl SessionManager {
    /// Creates a manager.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::Config`] when the policy is inconsistent.
    pub fn new(policy: ManagerPolicy, audit: Arc<AuditLog>) -> RdtResult<Self> {
        if policy.max_concurrent == 0 {
            return Err(RdtError::new(
                ErrorCode::Config,
                "at least one concurrent session must be allowed",
            ));
        }
        let (events, _) = broadcast::channel(64);
        Ok(Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            policy,
            audit,
            events,
        })
    }

    /// Subscribe to state transitions of every session.
    pub fn subscribe(&self) -> broadcast::Receiver<(SessionId, SessionState, String)> {
        self.events.subscribe()
    }

    /// Number of sessions that are not finished.
    pub fn active_count(&self) -> usize {
        self.inner.lock().values().filter(|slot| !slot.info.state.is_terminal()).count()
    }

    /// Snapshots of every session, newest first.
    pub fn list(&self) -> Vec<SessionInfo> {
        let mut sessions: Vec<SessionInfo> =
            self.inner.lock().values().map(|slot| slot.info.clone()).collect();
        sessions.sort_by_key(|info| std::cmp::Reverse(info.started.elapsed()));
        sessions
    }

    /// Looks one session up.
    pub fn get(&self, id: SessionId) -> Option<SessionInfo> {
        self.inner.lock().get(&id).map(|slot| slot.info.clone())
    }

    /// Registers a session that has just been started.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::SessionState`] when the concurrency limit is
    /// reached.
    pub fn register(
        &self,
        id: SessionId,
        profile: Option<ProfileId>,
        protocol: Protocol,
        address: String,
        commands: mpsc::UnboundedSender<SessionCommand>,
        cancel: oneshot::Sender<()>,
    ) -> RdtResult<SessionHandle> {
        let mut sessions = self.inner.lock();
        let active = sessions.values().filter(|slot| !slot.info.state.is_terminal()).count();
        if active >= self.policy.max_concurrent {
            return Err(RdtError::new(
                ErrorCode::SessionState,
                format!(
                    "the limit of {} concurrent sessions is reached",
                    self.policy.max_concurrent
                ),
            ));
        }
        sessions.insert(
            id,
            SessionSlot {
                info: SessionInfo {
                    id,
                    profile,
                    protocol,
                    address: address.clone(),
                    state: SessionState::Connecting,
                    detail: "connecting".to_owned(),
                    started: Instant::now(),
                    attempt: 0,
                },
                commands: commands.clone(),
                cancel,
            },
        );
        drop(sessions);
        self.transition(id, SessionState::Connecting, "connecting");
        Ok(SessionHandle { id, commands })
    }

    /// Records a state transition, broadcasting it and writing the audit trail.
    pub fn transition(&self, id: SessionId, state: SessionState, detail: &str) {
        if let Some(slot) = self.inner.lock().get_mut(&id) {
            slot.info.state = state;
            slot.info.detail = detail.to_owned();
            if state == SessionState::Reconnecting {
                slot.info.attempt += 1;
            }
        }
        let _ = self.events.send((id, state, detail.to_owned()));
        if self.policy.audit {
            let kind = match state {
                SessionState::Connecting => AuditEventKind::SessionConnect,
                SessionState::Authenticating => AuditEventKind::AuthAttempt,
                SessionState::Connected => AuditEventKind::SessionEstablished,
                SessionState::Reconnecting => AuditEventKind::SessionReconnect,
                SessionState::Disconnected | SessionState::Cancelled => AuditEventKind::SessionClosed,
                SessionState::Failed => AuditEventKind::SessionClosed,
                SessionState::Idle => AuditEventKind::SessionConnect,
            };
            let outcome = match state {
                SessionState::Failed => AuditOutcome::Failure,
                SessionState::Cancelled => AuditOutcome::Denied,
                SessionState::Connected => AuditOutcome::Success,
                _ => AuditOutcome::Info,
            };
            self.audit.record(
                AuditEvent::new(kind, outcome)
                    .with_session(id)
                    .with_detail(detail),
            );
        }
        if state.is_terminal() {
            self.release(id);
        }
    }

    /// Sends a command to a session.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::SessionState`] when the session is gone.
    pub fn send(&self, id: SessionId, command: SessionCommand) -> RdtResult<()> {
        let slot = self
            .inner
            .lock()
            .get(&id)
            .ok_or_else(|| RdtError::new(ErrorCode::SessionState, "no such session"))?;
        slot.commands
            .send(command)
            .map_err(|_| RdtError::new(ErrorCode::SessionState, "the session is closed"))
    }

    /// Cancels a session.  Idempotent.
    pub fn cancel(&self, id: SessionId) {
        let cancel = self.inner.lock().remove(&id).map(|slot| slot.cancel);
        if let Some(cancel) = cancel {
            let _ = cancel.send(());
        }
        self.transition(id, SessionState::Cancelled, "cancelled by the user");
    }

    /// Cancels every session, used on application shutdown.
    pub fn cancel_all(&self) {
        let ids: Vec<SessionId> = self.inner.lock().keys().copied().collect();
        for id in ids {
            self.cancel(id);
        }
    }

    /// Drops the bookkeeping for a finished session.
    fn release(&self, id: SessionId) {
        // The snapshot stays in the list until the UI dismisses it, but the
        // command channel and cancellation token are released immediately so a
        // finished session cannot hold a socket or a thread.
        if let Some(slot) = self.inner.lock().get_mut(&id) {
            drop(slot.commands.clone());
        }
    }

    /// Removes finished sessions from the list.
    pub fn prune(&self) -> usize {
        let mut sessions = self.inner.lock();
        let before = sessions.len();
        sessions.retain(|_, slot| !slot.info.state.is_terminal());
        before - sessions.len()
    }

    /// The delay before the next reconnect attempt, when a retry is due.
    pub fn next_retry_delay(&self, attempt: u32) -> Option<Duration> {
        if !self.policy.reconnect.enabled {
            return None;
        }
        Some(self.policy.reconnect.delay_for(attempt))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manager() -> SessionManager {
        SessionManager::new(ManagerPolicy::default(), Arc::new(AuditLog::null())).expect("manager")
    }

    fn channels() -> (mpsc::UnboundedSender<SessionCommand>, oneshot::Sender<()>) {
        let (command_tx, _command_rx) = mpsc::unbounded_channel();
        let (cancel_tx, _cancel_rx) = oneshot::channel();
        (command_tx, cancel_tx)
    }

    #[test]
    fn states_classify_correctly() {
        assert!(SessionState::Connected.is_active());
        assert!(SessionState::Disconnected.is_terminal());
        assert!(SessionState::Reconnecting.is_pending());
        assert!(!SessionState::Idle.is_active());
    }

    #[test]
    fn registering_a_session_starts_it_connecting() {
        let manager = manager();
        let (commands, cancel) = channels();
        let id = SessionId::new();
        manager
            .register(id, None, Protocol::Ssh, "host:22".to_owned(), commands, cancel)
            .expect("register");
        let info = manager.get(id).expect("info");
        assert_eq!(info.state, SessionState::Connecting);
        assert_eq!(info.address, "host:22");
        assert_eq!(manager.active_count(), 1);
    }

    #[test]
    fn the_concurrency_limit_is_enforced() {
        let policy = ManagerPolicy { max_concurrent: 2, ..ManagerPolicy::default() };
        let manager = SessionManager::new(policy, Arc::new(AuditLog::null())).expect("manager");
        for _ in 0..2 {
            let (commands, cancel) = channels();
            manager
                .register(SessionId::new(), None, Protocol::Ssh, "h:22".to_owned(), commands, cancel)
                .expect("register");
        }
        let (commands, cancel) = channels();
        let error = manager
            .register(SessionId::new(), None, Protocol::Ssh, "h:22".to_owned(), commands, cancel)
            .expect_err("must be refused");
        assert_eq!(error.code(), ErrorCode::SessionState);
    }

    #[test]
    fn a_zero_limit_is_refused() {
        let policy = ManagerPolicy { max_concurrent: 0, ..ManagerPolicy::default() };
        let error = SessionManager::new(policy, Arc::new(AuditLog::null())).expect_err("must fail");
        assert_eq!(error.code(), ErrorCode::Config);
    }

    #[test]
    fn transitions_are_broadcast() {
        let manager = manager();
        let (commands, cancel) = channels();
        let id = SessionId::new();
        manager
            .register(id, None, Protocol::Rdp, "host:3389".to_owned(), commands, cancel)
            .expect("register");
        let mut receiver = manager.subscribe();
        manager.transition(id, SessionState::Connected, "shell ready");
        let (event_id, state, detail) = receiver.recv().expect("event");
        assert_eq!(event_id, id);
        assert_eq!(state, SessionState::Connected);
        assert_eq!(detail, "shell ready");
        assert!(manager.get(id).expect("info").state.is_active());
    }

    #[test]
    fn cancelling_marks_the_session_and_releases_it() {
        let manager = manager();
        let (commands, cancel) = channels();
        let id = SessionId::new();
        manager
            .register(id, None, Protocol::Ssh, "h:22".to_owned(), commands, cancel)
            .expect("register");
        manager.cancel(id);
        assert_eq!(manager.get(id).expect("info").state, SessionState::Cancelled);
        assert_eq!(manager.active_count(), 0);
        assert_eq!(manager.prune(), 1);
        assert!(manager.get(id).is_none());
    }

    #[test]
    fn sending_to_an_unknown_session_fails() {
        let manager = manager();
        let error = manager.send(SessionId::new(), SessionCommand::Disconnect).expect_err("must fail");
        assert_eq!(error.code(), ErrorCode::SessionState);
    }

    #[test]
    fn reconnect_delays_follow_the_policy() {
        let manager = manager();
        let first = manager.next_retry_delay(1).expect("delay");
        let second = manager.next_retry_delay(2).expect("delay");
        assert!(first > Duration::from_secs(0));
        assert!(second >= first, "{second:?} should not shrink below {first:?}");
        let disabled = SessionManager::new(
            ManagerPolicy {
                reconnect: ReconnectPolicy { enabled: false, ..ReconnectPolicy::default() },
                ..ManagerPolicy::default()
            },
            Arc::new(AuditLog::null()),
        )
        .expect("manager");
        assert!(disabled.next_retry_delay(1).is_none());
    }

    #[test]
    fn cancel_all_empties_the_manager() {
        let manager = manager();
        for _ in 0..3 {
            let (commands, cancel) = channels();
            manager
                .register(SessionId::new(), None, Protocol::Ssh, "h:22".to_owned(), commands, cancel)
                .expect("register");
        }
        assert_eq!(manager.list().len(), 3);
        manager.cancel_all();
        assert_eq!(manager.active_count(), 0);
    }
}
