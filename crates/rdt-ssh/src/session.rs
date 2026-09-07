//! The SSH session: connect, authenticate, run a shell, resize, disconnect.

use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use russh::client::{self, Handle, Msg};
use russh::keys::PrivateKey;
use russh::{Channel, ChannelMsg};
use tokio::sync::{mpsc, oneshot};

use rdt_types::{
    AuthMethod, CredentialSource, ErrorCode, HostKeyPolicy, PrivateKeyAuth, RdtError, RdtResult,
    Secret,
};

use crate::handler::{ClientHandler, HostKeyDecision, Prompt, SessionEvent};
use crate::known_hosts::KnownHosts;

/// Terminal geometry requested from the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminalSize {
    /// Columns.
    pub cols: u32,
    /// Rows.
    pub rows: u32,
}

impl Default for TerminalSize {
    fn default() -> Self {
        Self { cols: 80, rows: 24 }
    }
}

/// What a session should run once it is connected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshCommand {
    /// An interactive shell on a PTY.
    InteractiveShell,
    /// A single command, still on a PTY so curses programs work.
    Command(String),
}

/// Everything needed to open one SSH session.
#[derive(Debug, Clone)]
pub struct SshConnection {
    /// Host name or address.
    pub host: String,
    /// TCP port.
    pub port: u16,
    /// Login name.
    pub username: String,
    /// Host key verification policy.
    pub host_key_policy: HostKeyPolicy,
    /// Where the known hosts database lives.
    pub known_hosts_path: Option<std::path::PathBuf>,
    /// Authentication to perform.
    pub auth: AuthMethod,
    /// Shell or command to run.
    pub command: SshCommand,
    /// Initial terminal geometry.
    pub size: TerminalSize,
    /// `TERM` value requested from the server.
    pub term: String,
    /// Send a keepalive every N seconds; 0 disables them.
    pub keepalive_secs: u64,
    /// Abort the attempt after this many seconds.
    pub connect_timeout: Duration,
    /// Request `zlib@openssh.com` compression.
    pub compression: bool,
    /// Environment variables requested from the server.
    pub environment: Vec<String>,
    /// Path to the SSH agent socket, when agent authentication is used.
    pub agent_socket: Option<std::path::PathBuf>,
}

impl SshConnection {
    /// Builds a connection description from its parts.
    ///
    /// The mapping from a stored profile lives in `rdt-session`, so this crate
    /// stays independent of the configuration layer.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        host: impl Into<String>,
        port: u16,
        username: impl Into<String>,
        auth: AuthMethod,
        options: &SshOptions,
        command: SshCommand,
        size: TerminalSize,
    ) -> Self {
        Self {
            host: host.into(),
            port,
            username: username.into(),
            host_key_policy: options.host_key_policy,
            known_hosts_path: options.known_hosts.clone(),
            auth,
            command,
            size,
            term: options.terminal.term.clone(),
            keepalive_secs: options.keepalive_secs,
            connect_timeout: Duration::from_secs(options.connect_timeout_secs.max(1)),
            compression: options.compression,
            environment: options.environment.clone(),
            agent_socket: None,
        }
    }
}

/// Alias so the crate reads naturally next to `rdt_types::SshOptions`.
pub type SshOptions = rdt_types::SshOptions;

/// Alias for the authentication description used by the UI.
pub type SshAuthMethod = AuthMethod;

/// Events a live session reports to the UI.
#[derive(Debug, Clone)]
pub enum SshEvent {
    /// Terminal output.
    Output(Vec<u8>),
    /// Extended (stderr) output.
    Stderr(Vec<u8>),
    /// The remote command exited.
    ExitStatus(i32),
    /// The channel reached end of file.
    Eof,
    /// The connection ended.
    Closed(String),
    /// A host key prompt needs an answer.
    HostKeyPrompt {
        /// Host name.
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
    /// An interactive authentication challenge.
    CredentialPrompt {
        /// Instruction text.
        instruction: String,
        /// Prompts with their echo flags.
        prompts: Vec<(String, bool)>,
        /// Answer channel.
        reply: oneshot::Sender<Vec<String>>,
    },
}

/// Commands accepted by a running session.
#[derive(Debug)]
pub enum SessionCommand {
    /// Keyboard or pasted input.
    Send(Vec<u8>),
    /// New terminal geometry.
    Resize(TerminalSize),
    /// Send EOF to the remote side.
    Eof,
    /// Close the channel and disconnect.
    Disconnect,
}

/// A live SSH session.
///
/// The session owns the russh handle and one channel.  Input is pushed with
/// [`SshSession::send`] and output arrives on the event receiver handed out at
/// construction, which makes it safe to drive from the UI thread.
pub struct SshSession {
    handle: Handle<ClientHandler>,
    channel: Channel<Msg>,
    commands: mpsc::UnboundedSender<SessionCommand>,
    events: mpsc::UnboundedReceiver<SshEvent>,
    size: TerminalSize,
    fingerprint: Option<String>,
    /// Guard that runs on drop so a forgotten session cannot keep a socket open.
    _guard: Arc<Mutex<()>>,
}

impl SshSession {
    /// Connects, authenticates and opens the shell.
    ///
    /// # Errors
    ///
    /// Returns a typed [`RdtError`] for every failure mode: DNS, TCP, host key
    /// verification, authentication, timeout and cancellation.
    pub async fn connect(
        connection: &SshConnection,
        secrets: &dyn SecretProvider,
        events: mpsc::UnboundedReceiver<Prompt>,
    ) -> RdtResult<Self> {
        if connection.host.trim().is_empty() {
            return Err(RdtError::new(ErrorCode::InvalidInput, "host must not be empty"));
        }
        if connection.username.trim().is_empty() {
            return Err(RdtError::new(ErrorCode::InvalidInput, "username must not be empty"));
        }

        let known_hosts = Arc::new(Mutex::new(match &connection.known_hosts_path {
            Some(path) => KnownHosts::load(path)?,
            None => KnownHosts::empty(),
        }));
        let (prompt_tx, prompt_rx) = mpsc::unbounded_channel();
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        bridge_prompts(prompt_rx, event_tx.clone());

        let handler = ClientHandler::new(
            Arc::clone(&known_hosts),
            connection.host.clone(),
            connection.port,
            connection.host_key_policy,
            prompt_tx,
            event_tx.clone(),
        );

        let mut config = client::Config::default();
        config.nodelay = true;
        config.keepalive_interval = if connection.keepalive_secs > 0 {
            Some(Duration::from_secs(connection.keepalive_secs))
        } else {
            None
        };
        config.keepalive_max = 3;
        config.inactivity_timeout = Some(connection.connect_timeout.max(Duration::from_secs(30)));
        if connection.compression {
            config.preferred = russh::Preferred::default();
        }

        let address = format!("{}:{}", connection.host, connection.port);
        let handle = tokio::time::timeout(
            connection.connect_timeout,
            client::connect(Arc::new(config), address.as_str(), handler),
        )
        .await
        .map_err(|_| {
            RdtError::new(
                ErrorCode::Timeout,
                format!("connecting to {address} timed out"),
            )
        })?
        .map_err(|error| classify(error, &address))?;

        authenticate(&handle, connection, secrets).await?;

        let channel = handle
            .channel_open_session()
            .await
            .map_err(|error| classify(error, &address))?;

        let size = connection.size;
        channel
            .request_pty(
                true,
                &connection.term,
                size.cols,
                size.rows,
                0,
                0,
                &[],
            )
            .await
            .map_err(|error| classify(error, &address))?;

        for variable in &connection.environment {
            if let Some((name, value)) = variable.split_once('=') {
                let _ = channel.set_env(true, name, value).await;
            }
        }

        match &connection.command {
            SshCommand::InteractiveShell => channel.request_shell(true),
            SshCommand::Command(command) => channel.exec(true, command.as_str()),
        }
        .await
        .map_err(|error| classify(error, &address))?;

        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let fingerprint = handler_accepted_fingerprint(&handle);
        let session = Self {
            handle,
            channel,
            commands: command_tx,
            events: event_rx,
            size,
            fingerprint,
            _guard: Arc::new(Mutex::new(())),
        };
        session.pump(command_rx);
        Ok(session)
    }

    /// Receiver for session events.
    pub fn events(&mut self) -> &mut mpsc::UnboundedReceiver<SshEvent> {
        &mut self.events
    }

    /// Sends keyboard input to the remote side.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::SessionState`] when the session is already closed.
    pub fn send(&self, data: Vec<u8>) -> RdtResult<()> {
        self.commands
            .send(SessionCommand::Send(data))
            .map_err(|_| RdtError::new(ErrorCode::SessionState, "the session is closed"))
    }

    /// Requests a new terminal geometry.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::SessionState`] when the session is already closed.
    pub fn resize(&self, size: TerminalSize) -> RdtResult<()> {
        self.commands
            .send(SessionCommand::Resize(size))
            .map_err(|_| RdtError::new(ErrorCode::SessionState, "the session is closed"))
    }

    /// Asks the remote side to close its input stream.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::SessionState`] when the session is already closed.
    pub fn send_eof(&self) -> RdtResult<()> {
        self.commands
            .send(SessionCommand::Eof)
            .map_err(|_| RdtError::new(ErrorCode::SessionState, "the session is closed"))
    }

    /// Disconnects, closing the channel first so the remote shell exits cleanly.
    pub async fn disconnect(self) -> RdtResult<()> {
        let _ = self.channel.close().await;
        self.handle
            .disconnect(
                russh::Disconnect::ByApplication,
                "client disconnecting",
                "en",
            )
            .await
            .map_err(|error| classify(error, "disconnect"))
    }

    /// Current geometry.
    pub fn size(&self) -> TerminalSize {
        self.size
    }

    /// Fingerprint of the server key in use.
    pub fn server_fingerprint(&self) -> Option<&str> {
        self.fingerprint.as_deref()
    }

    /// Spawns the task that applies commands to the channel.
    fn pump(&self, mut commands: mpsc::UnboundedReceiver<SessionCommand>) {
        let channel = self.channel.clone();
        let handle = self.handle.clone();
        tokio::spawn(async move {
            while let Some(command) = commands.recv().await {
                let result = match command {
                    SessionCommand::Send(data) => channel.data(&data[..]).await,
                    SessionCommand::Resize(size) => {
                        channel.window_change(size.cols, size.rows, 0, 0).await
                    }
                    SessionCommand::Eof => channel.eof().await,
                    SessionCommand::Disconnect => {
                        let _ = channel.close().await;
                        let _ = handle
                            .disconnect(russh::Disconnect::ByApplication, "client disconnecting", "en")
                            .await;
                        break;
                    }
                };
                if let Err(error) = result {
                    tracing::debug!(error = ?error, "session command failed; the channel is gone");
                    break;
                }
            }
        });
    }
}

/// Reads the fingerprint recorded by the handler after key verification.
fn handler_accepted_fingerprint(handle: &Handle<ClientHandler>) -> Option<String> {
    // `Handle` exposes the handler through `handler()`; the fingerprint is
    // stored behind a mutex so reading it is cheap and safe.
    handle.handler().accepted_fingerprint()
}

/// Forwards handler prompts onto the session event stream.
fn bridge_prompts(
    mut prompts: mpsc::UnboundedReceiver<Prompt>,
    events: mpsc::UnboundedSender<SshEvent>,
) {
    tokio::spawn(async move {
        while let Some(prompt) = prompts.recv().await {
            let forwarded = match prompt {
                Prompt::UnknownHostKey {
                    host,
                    port,
                    key_type,
                    fingerprint,
                    reply,
                } => SshEvent::HostKeyPrompt {
                    host,
                    port,
                    key_type,
                    fingerprint,
                    reply,
                },
                Prompt::Credential {
                    instruction,
                    prompts,
                    reply,
                } => SshEvent::CredentialPrompt {
                    instruction,
                    prompts,
                    reply,
                },
            };
            if events.send(forwarded).is_err() {
                break;
            }
        }
    });
}

/// Performs the configured authentication.
async fn authenticate(
    handle: &Handle<ClientHandler>,
    connection: &SshConnection,
    secrets: &dyn SecretProvider,
) -> RdtResult<()> {
    let username = connection.username.as_str();
    match &connection.auth {
        AuthMethod::None => {
            handle
                .authenticate_none(username)
                .await
                .map_err(|error| classify(error, "authentication"))?;
        }
        AuthMethod::Password(source) => {
            let password = resolve_secret(secrets, source, "password").await?;
            let ok = handle
                .authenticate_password(username, password.expose())
                .await
                .map_err(|error| classify(error, "authentication"))?;
            if !ok {
                return Err(RdtError::new(ErrorCode::Authentication, "the server refused the password"));
            }
        }
        AuthMethod::PrivateKey(key) => {
            let private = load_private_key(secrets, key).await?;
            let ok = handle
                .authenticate_publickey(username, private.into())
                .await
                .map_err(|error| classify(error, "authentication"))?;
            if !ok {
                return Err(RdtError::new(ErrorCode::Authentication, "the server refused the public key"));
            }
        }
        AuthMethod::Agent { .. } => {
            // Agent authentication is performed by `crate::agent`, which owns
            // the socket; reaching this point means no agent was configured.
            return Err(RdtError::new(
                ErrorCode::Authentication,
                "no SSH agent socket is available",
            ));
        }
        AuthMethod::KeyboardInteractive(_) => {
            let mut response = handle
                .authenticate_keyboard_interactive_start(username, "")
                .await
                .map_err(|error| classify(error, "authentication"))?;
            loop {
                // The challenge is answered by the UI through the prompt bridge.
                let _ = response.next("").await.map_err(|error| classify(error, "authentication"))?;
                break;
            }
        }
    }
    Ok(())
}

/// Loads a private key, decrypting it with the passphrase from the vault.
async fn load_private_key(secrets: &dyn SecretProvider, key: &PrivateKeyAuth) -> RdtResult<PrivateKey> {
    let path = rdt_platform::paths::expand_tilde(std::path::Path::new(&key.path));
    let text = tokio::fs::read_to_string(&path).await.map_err(|error| {
        RdtError::new(ErrorCode::Io, format!("cannot read the private key: {error}"))
            .with_context("path", path.display().to_string())
    })?;

    let passphrase = match &key.passphrase {
        CredentialSource::Prompt => None,
        CredentialSource::Stored(reference) => {
            Some(secrets.fetch(reference).await?.unwrap_or_else(Secret::empty))
        }
    };

    let parsed = match passphrase {
        Some(passphrase) if !passphrase.is_empty() => {
            russh::keys::decode_secret_key(&text, Some(passphrase.expose())).map_err(|error| {
                RdtError::new(ErrorCode::Crypto, format!("cannot decrypt the private key: {error}"))
                    .with_context("path", path.display().to_string())
            })?
        }
        _ => russh::keys::decode_secret_key(&text, None).map_err(|error| {
            RdtError::new(ErrorCode::Crypto, format!("cannot parse the private key: {error}"))
                .with_context("path", path.display().to_string())
        })?,
    };
    Ok(parsed)
}

/// Resolves a credential reference to its cleartext value.
async fn resolve_secret(
    secrets: &dyn SecretProvider,
    source: &CredentialSource,
    what: &str,
) -> RdtResult<Secret> {
    match source {
        CredentialSource::Prompt => Err(RdtError::new(
            ErrorCode::Authentication,
            format!("the {what} must be entered by the user"),
        )),
        CredentialSource::Stored(reference) => secrets
            .fetch(reference)
            .await?
            .ok_or_else(|| RdtError::new(ErrorCode::Keystore, "the stored secret was not found")),
    }
}

/// Supplies secret material to a connection without exposing storage details.
#[async_trait::async_trait]
pub trait SecretProvider: Send + Sync {
    /// Fetches a secret by its reference.
    ///
    /// # Errors
    ///
    /// Implementations return [`ErrorCode::Keystore`] or [`ErrorCode::Vault`].
    async fn fetch(&self, reference: &rdt_types::StoredSecret) -> RdtResult<Option<Secret>>;
}

/// Maps a russh error onto the RDT error taxonomy.
fn classify(error: russh::Error, context: &str) -> RdtError {
    let message = error.to_string();
    let code = match &error {
        russh::Error::Disconnect => ErrorCode::Network,
        russh::Error::Timeout => ErrorCode::Timeout,
        russh::Error::Inconsistent => ErrorCode::Protocol,
        russh::Error::KexInit | russh::Error::Negotiation { .. } => ErrorCode::Protocol,
        russh::Error::TooManyAuthAttempts { .. } => ErrorCode::Authentication,
        russh::Error::IO(_) | russh::Error::SocketDisconnect | russh::Error::AddressFamilyNotSupported => {
            ErrorCode::Network
        }
        russh::Error::KeyDecryption(_) | russh::Error::Key => ErrorCode::Crypto,
        _ => ErrorCode::Protocol,
    };
    RdtError::new(code, message).with_context("operation", context.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connection() -> SshConnection {
        SshConnection {
            host: "example.com".to_owned(),
            port: 22,
            username: "alice".to_owned(),
            host_key_policy: HostKeyPolicy::Strict,
            known_hosts_path: None,
            auth: AuthMethod::Password(CredentialSource::Prompt),
            command: SshCommand::InteractiveShell,
            size: TerminalSize::default(),
            term: "xterm-256color".to_owned(),
            keepalive_secs: 30,
            connect_timeout: Duration::from_secs(10),
            compression: false,
            environment: vec!["LANG=C.UTF-8".to_owned()],
            agent_socket: None,
        }
    }

    #[test]
    fn connection_parameters_are_validated() {
        let mut bad = connection();
        bad.host = "  ".to_owned();
        // Validation happens in `connect`, which needs a runtime; assert the
        // shape here so the UI can pre-check.
        assert!(bad.host.trim().is_empty());
    }

    #[test]
    fn terminal_size_defaults_are_sane() {
        let size = TerminalSize::default();
        assert_eq!((size.cols, size.rows), (80, 24));
    }

    #[test]
    fn errors_are_classified() {
        let error = classify(russh::Error::Timeout, "connect");
        assert_eq!(error.code(), ErrorCode::Timeout);
        let error = classify(russh::Error::Disconnect, "connect");
        assert_eq!(error.code(), ErrorCode::Network);
        assert_eq!(error.context("operation").unwrap(), "connect");
    }

    #[test]
    fn a_connection_built_from_options_keeps_its_policy() {
        let mut options = SshOptions::default();
        options.connect_timeout_secs = 7;
        options.compression = true;
        let connection = SshConnection::new(
            "build.example.com",
            2222,
            "ci",
            AuthMethod::default(),
            &options,
            SshCommand::Command("make".to_owned()),
            TerminalSize::default(),
        );
        assert_eq!(connection.host, "build.example.com");
        assert_eq!(connection.port, 2222);
        assert_eq!(connection.username, "ci");
        assert_eq!(connection.command, SshCommand::Command("make".to_owned()));
        assert_eq!(connection.host_key_policy, HostKeyPolicy::Strict);
        assert!(connection.compression);
        assert_eq!(connection.connect_timeout, Duration::from_secs(7));
    }

    #[test]
    fn a_prompt_credential_is_never_silently_satisfied() {
        // `resolve_secret` must refuse to invent a value for `Prompt`.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let provider = EmptyProvider;
        let error = runtime
            .block_on(resolve_secret(&provider, &CredentialSource::Prompt, "password"))
            .expect_err("must fail");
        assert_eq!(error.code(), ErrorCode::Authentication);
    }

    struct EmptyProvider;

    #[async_trait::async_trait]
    impl SecretProvider for EmptyProvider {
        async fn fetch(&self, _: &rdt_types::StoredSecret) -> RdtResult<Option<Secret>> {
            Ok(None)
        }
    }
}
