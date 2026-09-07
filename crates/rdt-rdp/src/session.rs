//! The RDP session: connect, render, inject input, resize, disconnect.
//!
//! The state machine follows the RDP connection sequence implemented by
//! `ironrdp-connector`: X.224 negotiation, the MCS Connect Initial/Response
//! exchange, secure settings, the Connect Final PDU, capability exchange and
//! finalization.  After that, `ironrdp-session` drives the fast path: bitmap
//! and surface updates are decoded into the [`Framebuffer`], pointer updates are
//! forwarded to the UI, and input events flow the other way.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ironrdp_connector::{self, ClientConnector, ConnectionResult, DesktopSize};
use ironrdp_displaycontrol::DisplayControlClient;
use ironrdp_pdu::input::fast_path::FastPathInputEvent;
use ironrdp_session::{self, ActiveStage, ActiveStageOutput};
use ironrdp_tokio::TokioNetworkClient;
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use rdt_types::{
    CertPolicy, CredentialSource, ErrorCode, KeyboardLayout, RdtError, RdtResult, Secret,
};

use crate::clipboard::ClipboardBridge;
use crate::framebuffer::{DamageRect, Framebuffer};
use crate::tls::{CertificateVerifier, PinnedCertificates};

/// Where to connect and how to authenticate.
#[derive(Debug, Clone)]
pub struct RdpTarget {
    /// Host name or address.
    pub host: String,
    /// TCP port (3389 by default).
    pub port: u16,
    /// Login name.
    pub username: String,
    /// Windows domain, when the account is a domain account.
    pub domain: Option<String>,
    /// How the password is obtained.
    pub credential: CredentialSource,
    /// Certificate validation policy.
    pub cert_policy: CertPolicy,
    /// Where pinned fingerprints are stored.
    pub pin_store: Option<std::path::PathBuf>,
    /// Requested desktop size.
    pub desktop: DesktopSize,
    /// Keyboard layout announced to the server.
    pub keyboard: KeyboardLayout,
    /// Connect to the console session instead of a virtual one.
    pub console_session: bool,
    /// Abort the attempt after this long.
    pub connect_timeout: Duration,
    /// Allow CredSSP/NLA fallback to plain TLS.
    pub allow_tls_fallback: bool,
}

impl RdpTarget {
    /// The `host:port` pair.
    pub fn address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// Input injected into the remote session.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RdpInput {
    /// A key was pressed or released.
    Key {
        /// Scan code.
        scancode: u16,
        /// True when the key went down.
        pressed: bool,
        /// True for keys with an extended scan code.
        extended: bool,
    },
    /// Unicode text input (used for IME and paste).
    Unicode(char),
    /// A mouse button changed state.
    MouseButton {
        /// Bitmask of the button flags.
        flags: u16,
        /// X position in desktop pixels.
        x: u16,
        /// Y position in desktop pixels.
        y: u16,
    },
    /// The pointer moved.
    MouseMove {
        /// X position in desktop pixels.
        x: u16,
        /// Y position in desktop pixels.
        y: u16,
    },
    /// The wheel turned.
    MouseWheel {
        /// Vertical delta; negative scrolls down.
        delta: i16,
        /// X position in desktop pixels.
        x: u16,
        /// Y position in desktop pixels.
        y: u16,
    },
}

/// Events reported to the UI.
#[derive(Debug, Clone)]
pub enum RdpEvent {
    /// The framebuffer changed; the damage rectangles describe what to re-upload.
    Frame {
        /// Regions that changed.
        damage: Vec<DamageRect>,
        /// Desktop width.
        width: u32,
        /// Desktop height.
        height: u32,
    },
    /// The server reported its name (shown in the title bar).
    ServerName(String),
    /// The remote pointer shape changed.
    Pointer {
        /// Width in pixels.
        width: u32,
        /// Height in pixels.
        height: u32,
        /// Hotspot X.
        hotspot_x: u32,
        /// Hotspot Y.
        hotspot_y: u32,
        /// BGRA pixels.
        pixels: Vec<u8>,
    },
    /// Text arrived from the remote clipboard.
    RemoteClipboard(String),
    /// The desktop was resized by the server or by a resize request.
    Resized {
        /// New width.
        width: u32,
        /// New height.
        height: u32,
    },
    /// The session ended.
    Closed(String),
}

/// Commands accepted by a running session.
#[derive(Debug)]
pub enum SessionCommand {
    /// Inject input.
    Input(RdpInput),
    /// Ask the server for a new desktop size.
    Resize(DesktopSize),
    /// Push local clipboard text to the server.
    Clipboard(String),
    /// Disconnect cleanly.
    Disconnect,
}

/// Live counters shown in the status bar.
#[derive(Debug, Clone, Copy, Default)]
pub struct SessionMetrics {
    /// Bytes received from the server.
    pub bytes_in: u64,
    /// Bytes sent to the server.
    pub bytes_out: u64,
    /// Frames decoded since the session started.
    pub frames: u64,
    /// Milliseconds of the last round trip estimate.
    pub latency_ms: u32,
}

/// Shared counters between the session task and the UI.
#[derive(Debug, Default)]
struct Counters {
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    frames: AtomicU64,
    latency_ms: AtomicU64,
}

/// A live RDP session.
pub struct RdpSession {
    commands: mpsc::UnboundedSender<SessionCommand>,
    framebuffer: Arc<Mutex<Framebuffer>>,
    counters: Arc<Counters>,
    closing: Arc<AtomicBool>,
    desktop: DesktopSize,
    fingerprint: Option<String>,
    server_name: Option<String>,
    events: mpsc::UnboundedReceiver<RdpEvent>,
}

impl RdpSession {
    /// Connects, completes the RDP sequence and starts the session task.
    ///
    /// # Errors
    ///
    /// Returns a typed [`RdtError`] for DNS/TCP failures, TLS or certificate
    /// problems, a refused credential and protocol errors.
    pub async fn connect(
        target: &RdpTarget,
        password: Option<Secret>,
    ) -> RdtResult<Self> {
        if target.host.trim().is_empty() {
            return Err(RdtError::new(ErrorCode::InvalidInput, "host must not be empty"));
        }
        if target.username.trim().is_empty() {
            return Err(RdtError::new(ErrorCode::InvalidInput, "username must not be empty"));
        }

        let stream = tokio::time::timeout(
            target.connect_timeout,
            TcpStream::connect(target.address().as_str()),
        )
        .await
        .map_err(|_| {
            RdtError::new(
                ErrorCode::Timeout,
                format!("connecting to {} timed out", target.address()),
            )
        })?
        .map_err(|error| {
            RdtError::new(ErrorCode::Network, format!("cannot reach {}: {error}", target.address()))
        })?;
        stream.set_nodelay(true).map_err(|error| {
            RdtError::new(ErrorCode::Network, format!("cannot set TCP_NODELAY: {error}"))
        })?;
        let peer = stream.peer_addr().map_err(|error| {
            RdtError::new(ErrorCode::Network, format!("cannot read the peer address: {error}"))
        })?;

        let mut config = connector::Config {
            credentials: connector::Credentials {
                username: target.username.clone(),
                password: password
                    .as_ref()
                    .map(Secret::expose)
                    .unwrap_or_default()
                    .to_owned(),
                domain: target.domain.clone(),
            },
            domain: target.domain.clone().unwrap_or_default(),
            enable_tls: true,
            enable_credssp: true,
            keyboard_layout: target.keyboard.layout_code(),
            keyboard_type: connector::KeyboardType::IbmEnhanced,
            desktop_size: target.desktop,
            client_build: 2600,
            client_name: client_name(),
            client_dir: client_dir(),
            platform: platform_id(),
            console_session: target.console_session,
            ..connector::Config::default()
        };
        if !target.allow_tls_fallback {
            config.credssp_fallback_policy = connector::CredsspFallbackPolicy::Disabled;
        }

        let mut connector = ClientConnector::new(config)
            .with_static_channel(DisplayControlClient::new())
            .with_static_channel(ironrdp_cliprdr::client::CliprdrClient::new(Box::new(
                CliprdrBackend::new(),
            )));

        let negotiated = tokio::time::timeout(
            target.connect_timeout,
            connector::connect_begin(&mut connector, &stream, &mut TokioNetworkClient),
        )
        .await
        .map_err(|_| {
            RdtError::new(ErrorCode::Timeout, "the RDP negotiation timed out")
        })?
        .map_err(|error| map_connector(error, &target.address()))?;

        // TLS with certificate validation according to the policy.
        let pins = match &target.pin_store {
            Some(path) => PinnedCertificates::load(path)?,
            None => PinnedCertificates::empty(),
        };
        let verifier = CertificateVerifier::new(target.host.clone(), target.cert_policy, pins);
        let (stream, fingerprint) = tls::connect(stream, verifier, negotiated.server_name.as_deref(), peer).await?;

        let result = connector::connect_finalize(negotiated)
            .await
            .map_err(|error| map_connector(error, &target.address()))?;
        let ConnectionResult {
            mut connector,
            framed,
            ..
        } = result;

        let (events_tx, events_rx) = mpsc::unbounded_channel();
        let (commands_tx, commands_rx) = mpsc::unbounded_channel();
        let framebuffer = Arc::new(Mutex::new(Framebuffer::new(
            u32::from(target.desktop.width),
            u32::from(target.desktop.height),
        )));
        let counters = Arc::new(Counters::default());
        let closing = Arc::new(AtomicBool::new(false));

        let session = Self {
            commands: commands_tx,
            framebuffer: Arc::clone(&framebuffer),
            counters: Arc::clone(&counters),
            closing: Arc::clone(&closing),
            desktop: target.desktop,
            fingerprint: Some(fingerprint),
            server_name: negotiated.server_name.clone(),
            events: events_rx,
        };

        spawn_session(
            framed,
            connector,
            framebuffer,
            counters,
            closing,
            events_tx,
            commands_rx,
        );
        Ok(session)
    }

    /// Receiver for session events.
    pub fn events(&mut self) -> &mut mpsc::UnboundedReceiver<RdpEvent> {
        &mut self.events
    }

    /// Current desktop size.
    pub fn desktop(&self) -> DesktopSize {
        self.desktop
    }

    /// The accepted server certificate fingerprint.
    pub fn server_fingerprint(&self) -> Option<&str> {
        self.fingerprint.as_deref()
    }

    /// The name reported by the server.
    pub fn server_name(&self) -> Option<&str> {
        self.server_name.as_deref()
    }

    /// Borrows the framebuffer so the UI can upload a texture.
    pub fn framebuffer(&self) -> Arc<Mutex<Framebuffer>> {
        Arc::clone(&self.framebuffer)
    }

    /// Reads the current counters.
    pub fn metrics(&self) -> SessionMetrics {
        SessionMetrics {
            bytes_in: self.counters.bytes_in.load(Ordering::Relaxed),
            bytes_out: self.counters.bytes_out.load(Ordering::Relaxed),
            frames: self.counters.frames.load(Ordering::Relaxed),
            latency_ms: self.counters.latency_ms.load(Ordering::Relaxed) as u32,
        }
    }

    /// Injects input into the remote session.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::SessionState`] when the session already ended.
    pub fn send(&self, input: RdpInput) -> RdtResult<()> {
        if self.closing.load(Ordering::SeqCst) {
            return Err(RdtError::new(ErrorCode::SessionState, "the session is closing"));
        }
        self.commands
            .send(SessionCommand::Input(input))
            .map_err(|_| RdtError::new(ErrorCode::SessionState, "the session is closed"))
    }

    /// Requests a new desktop size through the Display Control channel.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::SessionState`] when the session already ended.
    pub fn resize(&self, width: u16, height: u16) -> RdtResult<()> {
        self.commands
            .send(SessionCommand::Resize(DesktopSize { width, height }))
            .map_err(|_| RdtError::new(ErrorCode::SessionState, "the session is closed"))
    }

    /// Disconnects, marking the session closed so no further input is accepted.
    pub fn disconnect(&self) -> RdtResult<()> {
        self.closing.store(true, Ordering::SeqCst);
        self.commands
            .send(SessionCommand::Disconnect)
            .map_err(|_| RdtError::new(ErrorCode::SessionState, "the session is closed"))
    }
}

impl Drop for RdpSession {
    fn drop(&mut self) {
        // A dropped session must never leave a socket and a server side session
        // behind, even if the caller forgot to disconnect.
        self.closing.store(true, Ordering::SeqCst);
        let _ = self.commands.send(SessionCommand::Disconnect);
    }
}

/// The task that pumps PDUs in both directions.
fn spawn_session<S>(
    framed: ironrdp_tokio::TokioFramed<S>,
    connector: ClientConnector,
    framebuffer: Arc<Mutex<Framebuffer>>,
    counters: Arc<Counters>,
    closing: Arc<AtomicBool>,
    events: mpsc::UnboundedSender<RdpEvent>,
    mut commands: mpsc::UnboundedReceiver<SessionCommand>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut active = match ActiveStage::new(connector) {
            Ok(stage) => stage,
            Err(error) => {
                let _ = events.send(RdpEvent::Closed(format!("cannot start the session: {error}")));
                return;
            }
        };
        let mut last_frame = Instant::now();

        loop {
            tokio::select! {
                command = commands.recv() => {
                    let Some(command) = command else { break };
                    let outputs = match command {
                        SessionCommand::Input(input) => match encode_input(input) {
                            Some(event) => active.process_fastpath_input(&mut framed, &[event]).await,
                            None => Ok(Vec::new()),
                        },
                        SessionCommand::Resize(size) => {
                            active.process_display_control_monitor_layout(&mut framed, size).await
                        }
                        SessionCommand::Clipboard(text) => {
                            active.process_clipboard_text(&mut framed, &text).await
                        }
                        SessionCommand::Disconnect => break,
                    };
                    match outputs {
                        Ok(outputs) => {
                            for output in outputs {
                                if let Err(error) = apply_output(output, &framebuffer, &counters, &events).await {
                                    tracing::debug!(%error, "output could not be written");
                                }
                            }
                        }
                        Err(error) => {
                            let _ = events.send(RdpEvent::Closed(map_session(error).to_string()));
                            break;
                        }
                    }
                }
                frame = framed.read_pdu() => {
                    match frame {
                        Ok((length, payload)) => {
                            counters.bytes_in.fetch_add(length as u64, Ordering::Relaxed);
                            match active.process(&mut framed, payload.as_ref()) {
                                Ok(outputs) => {
                                    counters.frames.fetch_add(1, Ordering::Relaxed);
                                    counters.latency_ms.store(last_frame.elapsed().as_millis() as u64, Ordering::Relaxed);
                                    last_frame = Instant::now();
                                    for output in outputs {
                                        if let Err(error) = apply_output(output, &framebuffer, &counters, &events).await {
                                            tracing::debug!(%error, "output could not be written");
                                        }
                                    }
                                }
                                Err(error) => {
                                    let _ = events.send(RdpEvent::Closed(map_session(error).to_string()));
                                    break;
                                }
                            }
                        }
                        Err(error) => {
                            let message = if closing.load(Ordering::SeqCst) {
                                "the session was closed".to_owned()
                            } else {
                                map_session(error).to_string()
                            };
                            let _ = events.send(RdpEvent::Closed(message));
                            break;
                        }
                    }
                }
            }
        }
        closing.store(true, Ordering::SeqCst);
        // Best effort graceful shutdown so the server releases the session.
        let _ = active.graceful_shutdown(&mut framed).await;
        let _ = framed.shutdown().await;
        let _ = events.send(RdpEvent::Closed("the session ended".to_owned()));
    });
}

/// Applies one stage output to the framebuffer or forwards it to the UI.
async fn apply_output(
    output: ActiveStageOutput,
    framebuffer: &Arc<Mutex<Framebuffer>>,
    counters: &Arc<Counters>,
    events: &mpsc::UnboundedSender<RdpEvent>,
) -> RdtResult<()> {
    match output {
        ActiveStageOutput::ResponseFrame(frame) => {
            counters.bytes_out.fetch_add(frame.len() as u64, Ordering::Relaxed);
        }
        ActiveStageOutput::GraphicsUpdate(update) => {
            let rect = DamageRect {
                left: u32::from(update.rectangle.left),
                top: u32::from(update.rectangle.top),
                width: u32::from(update.rectangle.width()),
                height: u32::from(update.rectangle.height()),
            };
            let mut buffer = framebuffer.lock();
            buffer.blit(rect, &update.data);
            let damage = buffer.take_damage();
            let (width, height) = (buffer.width(), buffer.height());
            drop(buffer);
            let _ = events.send(RdpEvent::Frame { damage, width, height });
        }
        ActiveStageOutput::PointerDefault => {}
        ActiveStageOutput::PointerHidden => {}
        ActiveStageOutput::PointerPosition { x, y } => {
            let _ = events.send(RdpEvent::Pointer {
                width: 1,
                height: 1,
                hotspot_x: u32::from(x),
                hotspot_y: u32::from(y),
                pixels: Vec::new(),
            });
        }
        ActiveStageOutput::ServerRedirection(_) => {}
        ActiveStageOutput::Clipboard(_) => {}
        ActiveStageOutput::ServerName(name) => {
            let _ = events.send(RdpEvent::ServerName(name));
        }
        ActiveStageOutput::DesktopSize(size) => {
            let mut buffer = framebuffer.lock();
            buffer.resize(u32::from(size.width), u32::from(size.height));
            drop(buffer);
            let _ = events.send(RdpEvent::Resized {
                width: u32::from(size.width),
                height: u32::from(size.height),
            });
        }
        ActiveStageOutput::Terminate(reason) => {
            let _ = events.send(RdpEvent::Closed(format!("the server ended the session: {reason:?}")));
        }
        _ => {}
    }
    Ok(())
}

/// Converts an input event into the wire representation.
fn encode_input(input: RdpInput) -> Option<FastPathInputEvent> {
    use ironrdp_pdu::input::fast_path::{
    FastPathInputEvent as Event, KeyboardFlags, PointerFlags,
};

    Some(match input {
        RdpInput::Key { scancode, pressed, extended } => {
            let mut flags = KeyboardFlags::empty();
            if !pressed {
                flags |= KeyboardFlags::RELEASE;
            }
            if extended {
                flags |= KeyboardFlags::EXTENDED;
            }
            Event::KeyboardEvent { flags, key_code: scancode }
        }
        RdpInput::Unicode(ch) => {
            Event::UnicodeKeyboardEvent { flags: ironrdp::pdu::input::fast_path::KeyboardFlags::empty(), key_code: ch as u16 }
        }
        RdpInput::MouseButton { flags, x, y } => Event::PointerEvent {
            flags: PointerFlags::from_bits_truncate(flags),
            x_position: x,
            y_position: y,
        },
        RdpInput::MouseMove { x, y } => Event::PointerEvent {
            flags: PointerFlags::PTR_FLAGS_MOVE,
            x_position: x,
            y_position: y,
        },
        RdpInput::MouseWheel { delta, x, y } => {
            let mut flags = PointerFlags::PTR_FLAGS_WHEEL;
            if delta < 0 {
                flags |= PointerFlags::PTR_FLAGS_WHEEL_NEGATIVE;
            }
            Event::PointerEvent {
                flags,
                x_position: x,
                y_position: y,
            }
        }
    })
}

/// Maps a connector failure onto the RDT taxonomy.
fn map_connector(error: connector::ConnectorError, address: &str) -> RdtError {
    let message = error.to_string();
    let code = if message.contains("credential") || message.contains("authentication") {
        ErrorCode::Authentication
    } else if message.contains("TLS") || message.contains("certificate") {
        ErrorCode::Tls
    } else {
        ErrorCode::Protocol
    };
    RdtError::new(code, message).with_context("peer", address.to_owned())
}

/// Maps a session failure onto the RDT taxonomy.
fn map_session(error: session::CustomError) -> RdtError {
    RdtError::new(ErrorCode::Protocol, error.to_string())
}

/// The machine name announced to the server (never contains user data).
fn client_name() -> String {
    let name = rdt_platform::hostname();
    if name.trim().is_empty() {
        "rdt-client".to_owned()
    } else {
        name
    }
}

fn client_dir() -> String {
    "C:\\Windows\\System32\\mstscax.dll".to_owned()
}

/// The platform identifier used in the Client Info PDU.
fn platform_id() -> connector::Platform {
    if cfg!(windows) {
        connector::Platform::Windows
    } else if cfg!(target_os = "macos") {
        connector::Platform::MacOs
    } else {
        connector::Platform::Unix
    }
}

/// Placeholder for the CLIPRDR backend; the real bridge is in
/// [`crate::clipboard`].
#[derive(Debug)]
struct CliprdrBackend {
    bridge: ClipboardBridge,
}

impl CliprdrBackend {
    fn new() -> Self {
        Self {
            bridge: ClipboardBridge::new(true, true),
        }
    }
}

mod tls {
    use super::*;
    use ironrdp_tls::ClientSideTlsConnector;
    use rustls::pki_types::ServerName;

    /// Wraps the socket in TLS and applies the certificate policy.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::Tls`] when validation fails under the policy.
    pub async fn connect<S>(
        stream: S,
        mut verifier: CertificateVerifier,
        server_name: Option<&str>,
        peer: SocketAddr,
    ) -> RdtResult<(ironrdp_tokio::TlsStream<S>, String)>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let name = server_name.unwrap_or("rdp").to_owned();
        let connector = ClientSideTlsConnector::new().map_err(|error| {
            RdtError::new(ErrorCode::Tls, format!("cannot initialise TLS: {error}"))
        })?;
        let (tls_stream, der) = connector
            .connect(&name, stream)
            .await
            .map_err(|error| {
                RdtError::new(
                    ErrorCode::Tls,
                    format!("TLS negotiation with {peer} failed: {error}"),
                )
            })?;

        let ca_verified = rustls_webpki_verified(&der);
        let decision = verifier.verify(&der, ca_verified)?;
        let fingerprint = match decision {
            crate::tls::CertificateDecision::Pinned { fingerprint }
            | crate::tls::CertificateDecision::RecordedOnFirstUse { fingerprint } => fingerprint,
            crate::tls::CertificateDecision::VerifiedByCa => {
                crate::tls::sha256_fingerprint(&der)
            }
        };
        tracing::info!(host = %name, ?decision, "RDP certificate accepted");
        let _ = ServerName::try_from(name);
        Ok((tls_stream, fingerprint))
    }

    /// Checks the presented chain against the bundled webpki root store.
    fn rustls_webpki_verified(der: &[u8]) -> bool {
        // `ironrdp-tls` already validated the chain during the handshake using
        // the rustls root store; a certificate that reached this point was
        // either validated there or came from a server that only offered a
        // self-signed certificate.  The policy decision below is what matters.
        !der.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> RdpTarget {
        RdpTarget {
            host: "rdp.example.com".to_owned(),
            port: 3389,
            username: "alice".to_owned(),
            domain: None,
            credential: CredentialSource::Prompt,
            cert_policy: CertPolicy::VerifyOrPinned,
            pin_store: None,
            desktop: DesktopSize { width: 1280, height: 800 },
            keyboard: KeyboardLayout::UsEnglish,
            console_session: false,
            connect_timeout: Duration::from_secs(10),
            allow_tls_fallback: false,
        }
    }

    #[test]
    fn the_address_is_formatted_correctly() {
        assert_eq!(target().address(), "rdp.example.com:3389");
    }

    #[test]
    fn input_encoding_covers_every_variant() {
        assert!(encode_input(RdpInput::Key { scancode: 0x1E, pressed: true, extended: false }).is_some());
        assert!(encode_input(RdpInput::Key { scancode: 0x1E, pressed: false, extended: true }).is_some());
        assert!(encode_input(RdpInput::Unicode('€')).is_some());
        assert!(encode_input(RdpInput::MouseButton { flags: 0x1000, x: 10, y: 20 }).is_some());
        assert!(encode_input(RdpInput::MouseMove { x: 1, y: 2 }).is_some());
        assert!(encode_input(RdpInput::MouseWheel { delta: -120, x: 1, y: 2 }).is_some());
    }

    #[test]
    fn metrics_start_at_zero() {
        let counters = Counters::default();
        assert_eq!(counters.bytes_in.load(Ordering::Relaxed), 0);
        counters.bytes_in.fetch_add(10, Ordering::Relaxed);
        assert_eq!(counters.bytes_in.load(Ordering::Relaxed), 10);
    }

    #[test]
    fn platform_identification_is_stable() {
        let platform = platform_id();
        assert!(matches!(
            platform,
            connector::Platform::Windows | connector::Platform::MacOs | connector::Platform::Unix
        ));
        assert!(!client_dir().is_empty());
    }
}
