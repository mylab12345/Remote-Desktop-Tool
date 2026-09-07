//! The [`russh::client::Handler`] implementation.
//!
//! Everything the transport asks us about lands here, and the security
//! decisions (host key verification) are made in one place so they cannot be
//! forgotten by a caller.

use std::collections::VecDeque;
use std::sync::Arc;

use parking_lot::Mutex;
use russh::client::{Handler, Msg};
use russh::{Channel, ChannelMsg};
use tokio::sync::{mpsc, oneshot};

use rdt_types::{ErrorCode, HostKeyPolicy, RdtError, RdtResult, REDACTED};

use crate::known_hosts::{fingerprint, HostKeyStatus, KnownHosts};

/// The user's decision about an unknown host key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKeyDecision {
    /// Accept this key for this connection only.
    AcceptOnce,
    /// Accept and write it to the known hosts database.
    AcceptAndSave,
    /// Refuse to connect.
    Reject,
}

/// A question posed to the user during connection.
#[derive(Debug, Clone)]
pub enum Prompt {
    /// The host key is unknown and the policy allows asking.
    UnknownHostKey {
        /// Host name as typed by the user.
        host: String,
        /// Port.
        port: u16,
        /// Key algorithm.
        key_type: String,
        /// `SHA256:…` fingerprint.
        fingerprint: String,
        /// Answer channel.
        reply: oneshot::Sender<HostKeyDecision>,
    },
    /// An interactive authentication challenge (password or OTP).
    Credential {
        /// Text shown to the user.
        instruction: String,
        /// Individual prompts, each with its echo flag.
        prompts: Vec<(String, bool)>,
        /// Answer channel.
        reply: oneshot::Sender<Vec<String>>,
    },
}

/// Errors surfaced by the handler.
pub type SshError = RdtError;

/// Shared state between the handler and the session.
#[derive(Debug)]
pub struct ClientHandler {
    known_hosts: Arc<Mutex<KnownHosts>>,
    host: String,
    port: u16,
    policy: HostKeyPolicy,
    prompts: mpsc::UnboundedSender<Prompt>,
    events: mpsc::UnboundedSender<SessionEvent>,
    channels: Arc<Mutex<VecDeque<Channel<Msg>>>>,
    /// Fingerprint of the key actually accepted, for the audit trail.
    accepted_fingerprint: Arc<Mutex<Option<String>>>,
}

/// Events the transport reports to the session layer.
#[derive(Debug, Clone)]
pub enum SessionEvent {
    /// A banner sent by the server before authentication.
    Banner(String),
    /// A channel was closed by the remote side.
    ChannelClosed(u32),
    /// The remote side ended the session.
    Disconnected(String),
}

impl ClientHandler {
    /// Creates a handler.
    pub fn new(
        known_hosts: Arc<Mutex<KnownHosts>>,
        host: String,
        port: u16,
        policy: HostKeyPolicy,
        prompts: mpsc::UnboundedSender<Prompt>,
        events: mpsc::UnboundedSender<SessionEvent>,
    ) -> Self {
        Self {
            known_hosts,
            host,
            port,
            policy,
            prompts,
            events,
            channels: Arc::new(Mutex::new(VecDeque::new())),
            accepted_fingerprint: Arc::new(Mutex::new(None)),
        }
    }

    /// Fingerprint of the accepted server key, once connected.
    pub fn accepted_fingerprint(&self) -> Option<String> {
        self.accepted_fingerprint.lock().clone()
    }

    /// Shared view of the channels opened by the server.
    pub fn channels(&self) -> Arc<Mutex<VecDeque<Channel<Msg>>>> {
        Arc::clone(&self.channels)
    }

    /// Runs the host key policy.  Returns `Ok(true)` when the connection may
    /// continue.
    fn verify_host_key(&self, key_type: &str, key: &[u8]) -> RdtResult<bool> {
        let database = self.known_hosts.lock();
        match database.check(&self.host, self.port, key_type, key) {
            HostKeyStatus::Trusted => Ok(true),
            HostKeyStatus::Unknown => {
                if self.policy.auto_accepts_unknown() {
                    // Only `AcceptNew` reaches this branch; `Strict` never does.
                    return Ok(true);
                }
                Err(RdtError::new(
                    ErrorCode::HostKeyUnknown,
                    format!(
                        "host key for {} is not recorded and the policy is strict",
                        self.host
                    ),
                )
                .with_context("fingerprint", fingerprint(key)))
            }
            HostKeyStatus::Changed {
                known_fingerprint,
                known_key_type,
            } => Err(RdtError::new(
                ErrorCode::HostKeyMismatch,
                format!(
                    "the host key for {} changed; recorded {known_key_type} {known_fingerprint}",
                    self.host
                ),
            )
            .with_context("fingerprint", fingerprint(key))),
            HostKeyStatus::Revoked => Err(RdtError::new(
                ErrorCode::HostKeyMismatch,
                format!("the host key for {} has been revoked", self.host),
            )),
            HostKeyStatus::Excluded => Err(RdtError::new(
                ErrorCode::HostKeyMismatch,
                format!("the host {} is excluded by a negated known_hosts pattern", self.host),
            )),
        }
    }

    /// Records a key the user accepted.
    pub fn remember_host_key(&self, key_type: &str, key: &[u8]) {
        let mut database = self.known_hosts.lock();
        database.accept(&self.host, self.port, key_type, key, &self.host);
        if let Err(error) = database.save() {
            tracing::warn!(error = %error, "cannot persist the accepted host key");
        }
    }
}

impl Handler for ClientHandler {
    type Error = SshError;

    fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKeyOrCertificate,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send {
        let key_type = server_public_key.algorithm().as_str().to_owned();
        let key = server_public_key.public_key().public_key_base64();
        let digest = fingerprint(&key);
        let handler = self.clone_for_callback();

        async move {
            // Fast path: already trusted.
            if let Ok(true) = handler.verify_host_key(&key_type, &key) {
                *handler.accepted_fingerprint.lock() = Some(digest.clone());
                return Ok(true);
            }

            // Under `Strict` a mismatch is fatal; under `AcceptNew` only an
            // *unknown* host may be accepted, and only after asking.
            let database = handler.known_hosts.lock();
            let status = database.check(&handler.host, handler.port, &key_type, &key);
            drop(database);

            if status.is_fatal() {
                return Err(RdtError::new(
                    ErrorCode::HostKeyMismatch,
                    format!("host key verification failed for {}: {status}", handler.host),
                ));
            }
            if handler.policy == HostKeyPolicy::Strict {
                return Err(RdtError::new(
                    ErrorCode::HostKeyUnknown,
                    format!("host key for {} is unknown and the policy is strict", handler.host),
                ));
            }

            let (reply_tx, reply_rx) = oneshot::channel();
            let prompt = Prompt::UnknownHostKey {
                host: handler.host.clone(),
                port: handler.port,
                key_type: key_type.clone(),
                fingerprint: digest.clone(),
                reply: reply_tx,
            };
            if handler.prompts.send(prompt).is_err() {
                return Err(RdtError::new(
                    ErrorCode::HostKeyUnknown,
                    "no user interface is available to confirm the host key",
                ));
            }
            match reply_rx.await {
                Ok(HostKeyDecision::AcceptAndSave) => {
                    handler.remember_host_key(&key_type, &key);
                    *handler.accepted_fingerprint.lock() = Some(digest);
                    Ok(true)
                }
                Ok(HostKeyDecision::AcceptOnce) => {
                    *handler.accepted_fingerprint.lock() = Some(digest);
                    Ok(true)
                }
                Ok(HostKeyDecision::Reject) | Err(_) => Err(RdtError::new(
                    ErrorCode::HostKeyUnknown,
                    "the host key was rejected",
                )),
            }
        }
    }

    fn auth_banner(
        &mut self,
        banner: &str,
        _: &mut russh::client::Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        let banner = banner.to_owned();
        let events = self.events.clone();
        async move {
            let _ = events.send(SessionEvent::Banner(banner));
            Ok(())
        }
    }

    fn channel_open_confirmation(
        &mut self,
        id: russh::ChannelId,
        _: u32,
        _: u32,
        _: u32,
        _: u32,
        _: &mut russh::client::Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        tracing::debug!(channel = %id, "channel opened");
        async { Ok(()) }
    }

    fn disconnected(
        &mut self,
        reason: russh::Disconnect,
        _: &mut russh::client::Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        let description = reason.description.to_string();
        let events = self.events.clone();
        async move {
            let _ = events.send(SessionEvent::Disconnected(description));
            Ok(())
        }
    }
}

impl ClientHandler {
    /// Cheap clone used by the async callbacks, which need `'static` data.
    fn clone_for_callback(&self) -> HandlerRef {
        HandlerRef {
            known_hosts: Arc::clone(&self.known_hosts),
            host: self.host.clone(),
            port: self.port,
            policy: self.policy,
            prompts: self.prompts.clone(),
            accepted_fingerprint: Arc::clone(&self.accepted_fingerprint),
        }
    }
}

/// Owned subset of the handler used inside `async` callbacks.
#[derive(Debug, Clone)]
struct HandlerRef {
    known_hosts: Arc<Mutex<KnownHosts>>,
    host: String,
    port: u16,
    policy: HostKeyPolicy,
    prompts: mpsc::UnboundedSender<Prompt>,
    accepted_fingerprint: Arc<Mutex<Option<String>>>,
}

impl HandlerRef {
    fn verify_host_key(&self, key_type: &str, key: &[u8]) -> RdtResult<bool> {
        let database = self.known_hosts.lock();
        match database.check(&self.host, self.port, key_type, key) {
            HostKeyStatus::Trusted => Ok(true),
            _ => Err(RdtError::new(ErrorCode::HostKeyUnknown, "not trusted")),
        }
    }

    fn remember_host_key(&self, key_type: &str, key: &[u8]) {
        let mut database = self.known_hosts.lock();
        database.accept(&self.host, self.port, key_type, key, &self.host);
        if let Err(error) = database.save() {
            tracing::warn!(error = %error, "cannot persist the accepted host key");
        }
    }
}

/// Formats a credential prompt for the audit log without leaking the answer.
pub fn describe_prompt(prompt: &Prompt) -> String {
    match prompt {
        Prompt::UnknownHostKey { host, fingerprint, .. } => {
            format!("host key {host} {fingerprint}")
        }
        Prompt::Credential { instruction, .. } => {
            format!("credential prompt: {instruction} (answer {REDACTED})")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::known_hosts::KnownHosts;

    fn handler(policy: HostKeyPolicy) -> (ClientHandler, mpsc::UnboundedReceiver<Prompt>) {
        let (prompt_tx, prompt_rx) = mpsc::unbounded_channel();
        let (event_tx, _event_rx) = mpsc::unbounded_channel();
        let handler = ClientHandler::new(
            Arc::new(Mutex::new(KnownHosts::empty())),
            "host.example.com".to_owned(),
            22,
            policy,
            prompt_tx,
            event_tx,
        );
        (handler, prompt_rx)
    }

    #[test]
    fn a_recorded_key_is_accepted_without_asking() {
        let (handler, _) = handler(HostKeyPolicy::Strict);
        handler.remember_host_key("ssh-ed25519", b"key-bytes");
        assert!(handler.verify_host_key("ssh-ed25519", b"key-bytes").is_ok());
        assert!(handler.accepted_fingerprint().is_none());
    }

    #[test]
    fn a_changed_key_is_fatal_under_both_policies() {
        for policy in [HostKeyPolicy::Strict, HostKeyPolicy::AcceptNew] {
            let (handler, _) = handler(policy);
            handler.remember_host_key("ssh-ed25519", b"key-bytes");
            let error = handler
                .verify_host_key("ssh-ed25519", b"different")
                .expect_err("must fail");
            assert!(matches!(
                error.code(),
                ErrorCode::HostKeyMismatch | ErrorCode::HostKeyUnknown
            ));
        }
    }

    #[test]
    fn strict_policy_refuses_unknown_hosts() {
        let (handler, _) = handler(HostKeyPolicy::Strict);
        let error = handler.verify_host_key("ssh-ed25519", b"key").expect_err("must fail");
        assert_eq!(error.code(), ErrorCode::HostKeyUnknown);
    }

    #[test]
    fn accept_new_policy_permits_unknown_hosts() {
        let (handler, _) = handler(HostKeyPolicy::AcceptNew);
        assert!(handler.verify_host_key("ssh-ed25519", b"key").is_ok());
    }

    #[test]
    fn prompts_never_carry_secret_material() {
        let (reply_tx, _reply_rx) = oneshot::channel();
        let prompt = Prompt::Credential {
            instruction: "Password for alice".to_owned(),
            prompts: vec![("Password: ".to_owned(), false)],
            reply: reply_tx,
        };
        let description = describe_prompt(&prompt);
        assert!(description.contains("<redacted>"), "{description}");
        assert!(!description.contains("hunter2"));

        let (reply_tx, _reply_rx) = oneshot::channel();
        let prompt = Prompt::UnknownHostKey {
            host: "host".to_owned(),
            port: 22,
            key_type: "ssh-ed25519".to_owned(),
            fingerprint: "SHA256:abc".to_owned(),
            reply: reply_tx,
        };
        assert!(describe_prompt(&prompt).contains("SHA256:abc"));
    }

    #[test]
    fn channels_are_shared_between_handler_and_session() {
        let (handler, _) = handler(HostKeyPolicy::Strict);
        let shared = handler.channels();
        assert!(shared.lock().is_empty());
    }
}
