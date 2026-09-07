//! Protocol and connection option types shared by the SSH, RDP, config and UI
//! crates.
//!
//! Everything here is serializable so that it can be stored in profiles, sent to
//! the agent over its control socket, and rendered in the settings UI without
//! translation layers.

use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::{ErrorCode, RdtError, RdtResult};

/// Remote access protocols supported by RDT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// Secure Shell (interactive PTY, command execution and SFTP).
    #[default]
    Ssh,
    /// Remote Desktop Protocol with an embedded client renderer.
    Rdp,
}

impl Protocol {
    /// The conventional port for the protocol.
    pub const fn default_port(self) -> u16 {
        match self {
            Self::Ssh => 22,
            Self::Rdp => 3389,
        }
    }

    /// Stable lowercase name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ssh => "ssh",
            Self::Rdp => "rdp",
        }
    }

    /// Human readable name used in the UI.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ssh => "SSH",
            Self::Rdp => "RDP",
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Protocol {
    type Err = RdtError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text.trim().to_ascii_lowercase().as_str() {
            "ssh" => Ok(Self::Ssh),
            "rdp" | "rdp-tcp" => Ok(Self::Rdp),
            other => Err(RdtError::new(
                ErrorCode::InvalidInput,
                format!("unknown protocol '{other}'; expected 'ssh' or 'rdp'"),
            )),
        }
    }
}

/// A network endpoint (host or IP literal plus port).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Endpoint {
    /// Host name, IPv4 or IPv6 literal.  IPv6 literals are stored without the
    /// surrounding brackets.
    pub host: String,
    /// TCP port.
    pub port: u16,
}

impl Endpoint {
    /// Builds an endpoint, validating the host.
    pub fn new(host: impl Into<String>, port: u16) -> RdtResult<Self> {
        let host = host.into();
        validate_host(&host)?;
        Ok(Self { host, port })
    }

    /// Builds an endpoint from `host` or `host:port`, falling back to the
    /// default port of `protocol`.
    pub fn parse(text: &str, protocol: Protocol) -> RdtResult<Self> {
        let text = text.trim();
        if text.is_empty() {
            return Err(RdtError::new(ErrorCode::InvalidInput, "empty host"));
        }
        // IPv6 literals may carry brackets: [::1]:3389
        if let Some(rest) = text.strip_prefix('[') {
            let (host, remainder) = rest.split_once(']').ok_or_else(|| {
                RdtError::new(ErrorCode::InvalidInput, "unterminated IPv6 literal")
            })?;
            let port = match remainder.strip_prefix(':') {
                Some(port_text) => parse_port(port_text)?,
                None if remainder.is_empty() => protocol.default_port(),
                None => {
                    return Err(RdtError::new(
                        ErrorCode::InvalidInput,
                        format!("unexpected suffix '{remainder}' after IPv6 literal"),
                    ))
                }
            };
            return Self::new(host, port);
        }
        match text.rsplit_once(':') {
            Some((host, port_text)) if !host.is_empty() => Self::new(host, parse_port(port_text)?),
            _ => Self::new(text, protocol.default_port()),
        }
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

fn parse_port(text: &str) -> RdtResult<u16> {
    text.trim()
        .parse::<u16>()
        .map_err(|_| RdtError::new(ErrorCode::InvalidInput, format!("invalid port '{text}'")))
}

fn validate_host(host: &str) -> RdtResult<()> {
    if host.is_empty() {
        return Err(RdtError::new(
            ErrorCode::InvalidInput,
            "host must not be empty",
        ));
    }
    if host.len() > 253 {
        return Err(RdtError::new(ErrorCode::InvalidInput, "host name too long"));
    }
    if host.chars().any(char::is_whitespace) {
        return Err(RdtError::new(
            ErrorCode::InvalidInput,
            "host must not contain whitespace",
        ));
    }
    if host.contains('/') || host.contains('@') {
        return Err(RdtError::new(
            ErrorCode::InvalidInput,
            "host must not contain '/' or '@'",
        ));
    }
    Ok(())
}

/// How unknown or changed SSH host keys are treated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum HostKeyPolicy {
    /// Unknown keys require an explicit user decision; changed keys are always
    /// refused.  This is the default and matches OpenSSH's `ask` behaviour with
    /// a hard failure on mismatch.
    #[default]
    Strict,
    /// Unknown keys are recorded automatically; changed keys are refused.
    /// Equivalent to OpenSSH's `StrictHostKeyChecking=accept-new`.
    AcceptNew,
}

impl HostKeyPolicy {
    /// Stable name used in configuration files.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::AcceptNew => "accept-new",
        }
    }

    /// Whether an unknown key may be accepted without a human decision.
    pub const fn auto_accepts_unknown(self) -> bool {
        matches!(self, Self::AcceptNew)
    }
}

impl FromStr for HostKeyPolicy {
    type Err = RdtError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text.trim().to_ascii_lowercase().as_str() {
            "strict" => Ok(Self::Strict),
            "accept-new" | "acceptnew" => Ok(Self::AcceptNew),
            other => Err(RdtError::new(
                ErrorCode::InvalidInput,
                format!("unknown host key policy '{other}'"),
            )),
        }
    }
}

/// Where a stored secret lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretBackend {
    /// The platform keyring (Windows DPAPI protected store, the Secret Service
    /// on Linux desktops).
    OsKeystore,
    /// The passphrase protected, AEAD encrypted vault file managed by RDT.
    EncryptedVault,
}

impl SecretBackend {
    /// Stable configuration name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OsKeystore => "os-keystore",
            Self::EncryptedVault => "encrypted-vault",
        }
    }
}

/// A reference to secret material that is stored outside of the profile file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredSecret {
    /// Backend that holds the value.
    pub backend: SecretBackend,
    /// Opaque key inside that backend.
    pub key: String,
}

/// How a credential is obtained at connect time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case", tag = "source")]
pub enum CredentialSource {
    /// Ask the user in the UI (never persisted).
    #[default]
    Prompt,
    /// Read the value from a secret store.
    Stored(StoredSecret),
}

/// Authentication material for SSH.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "method")]
pub enum AuthMethod {
    /// No authentication (only meaningful for protocols that allow it).
    None,
    /// Password authentication.
    Password(CredentialSource),
    /// Private key authentication.
    PrivateKey(PrivateKeyAuth),
    /// Use a running SSH agent.
    Agent {
        /// Optional identity hint passed to the agent.
        #[serde(default)]
        identity: Option<String>,
    },
    /// Keyboard-interactive authentication (for example one time passwords).
    KeyboardInteractive(CredentialSource),
}

impl Default for AuthMethod {
    fn default() -> Self {
        // New profiles ask for a password at connect time and store nothing.
        Self::Password(CredentialSource::Prompt)
    }
}

impl AuthMethod {
    /// Human readable description that never contains secret material.
    pub fn describe(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Password(_) => "password",
            Self::PrivateKey(key) => {
                if key.passphrase == CredentialSource::Prompt {
                    "private key"
                } else {
                    "private key (stored passphrase)"
                }
            }
            Self::Agent { .. } => "ssh agent",
            Self::KeyboardInteractive(_) => "keyboard-interactive",
        }
    }
}

/// Private key authentication settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateKeyAuth {
    /// Path to the private key file (OpenSSH or PEM format).
    pub path: PathBuf,
    /// Where the passphrase comes from; `Prompt` for unencrypted keys too.
    #[serde(default)]
    pub passphrase: CredentialSource,
}

impl Default for PrivateKeyAuth {
    fn default() -> Self {
        Self {
            path: PathBuf::from("~/.ssh/id_ed25519"),
            passphrase: CredentialSource::Prompt,
        }
    }
}

/// SSH specific connection options.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SshOptions {
    /// Send a keepalive every N seconds; 0 disables keepalives.
    #[serde(default = "default_keepalive_secs")]
    pub keepalive_secs: u64,
    /// Abort the connection attempt after this many seconds.
    #[serde(default = "default_connect_timeout_secs")]
    pub connect_timeout_secs: u64,
    /// Close an idle session after this many seconds; 0 disables the timer.
    #[serde(default)]
    pub idle_timeout_secs: u64,
    /// Request `zlib@openssh.com` compression.
    #[serde(default)]
    pub compression: bool,
    /// Host key verification policy.
    #[serde(default)]
    pub host_key_policy: HostKeyPolicy,
    /// Location of the known hosts database.
    #[serde(default)]
    pub known_hosts: Option<PathBuf>,
    /// Terminal settings for interactive sessions.
    #[serde(default)]
    pub terminal: TerminalOptions,
    /// Command to execute instead of an interactive shell.
    #[serde(default)]
    pub command: Option<String>,
    /// Environment variables requested from the server (`KEY=VALUE`).
    #[serde(default)]
    pub environment: Vec<String>,
    /// Open the SFTP subsystem alongside the shell.
    #[serde(default = "default_true")]
    pub sftp_enabled: bool,
    /// Automatic reconnection policy.
    #[serde(default)]
    pub reconnect: ReconnectPolicy,
}

impl Default for SshOptions {
    fn default() -> Self {
        Self {
            keepalive_secs: default_keepalive_secs(),
            connect_timeout_secs: default_connect_timeout_secs(),
            idle_timeout_secs: 0,
            compression: false,
            host_key_policy: HostKeyPolicy::default(),
            known_hosts: None,
            terminal: TerminalOptions::default(),
            command: None,
            environment: Vec::new(),
            sftp_enabled: true,
            reconnect: ReconnectPolicy::default(),
        }
    }
}

/// Terminal emulation settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TerminalOptions {
    /// Initial column count.
    #[serde(default = "default_cols")]
    pub cols: u16,
    /// Initial row count.
    #[serde(default = "default_rows")]
    pub rows: u16,
    /// Number of scrollback lines kept in memory.
    #[serde(default = "default_scrollback")]
    pub scrollback_lines: usize,
    /// Font size in logical points.
    #[serde(default = "default_font_size")]
    pub font_size: f32,
    /// `$TERM` value requested from the server.
    #[serde(default = "default_term")]
    pub term: String,
    /// Ring the terminal bell by flashing the tab.
    #[serde(default = "default_true")]
    pub bell: bool,
}

impl Default for TerminalOptions {
    fn default() -> Self {
        Self {
            cols: default_cols(),
            rows: default_rows(),
            scrollback_lines: default_scrollback(),
            font_size: default_font_size(),
            term: default_term(),
            bell: true,
        }
    }
}

/// RDP colour depth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ColorDepth {
    /// 16 bit RGB565.
    Rgb565,
    /// 24 bit true colour.
    #[default]
    TrueColor24,
    /// 32 bit colour with an unused alpha channel.
    TrueColor32,
}

impl ColorDepth {
    /// Bits per pixel for the wire format.
    pub const fn bits_per_pixel(self) -> u8 {
        match self {
            Self::Rgb565 => 16,
            Self::TrueColor24 => 24,
            Self::TrueColor32 => 32,
        }
    }
}

/// How the RDP server certificate is trusted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CertPolicy {
    /// Validate the certificate against the bundled root store (plus an optional
    /// CA bundle) and refuse anything that does not chain.
    #[default]
    Verify,
    /// Like [`Self::Verify`], but also accept a certificate whose SHA-256
    /// fingerprint matches the pinned value stored in the profile.
    VerifyOrPinned,
    /// Ask the user once and remember the fingerprint in the profile.
    TrustOnFirstUse,
}

/// RDP specific connection options.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RdpOptions {
    /// Initial desktop width in pixels.
    #[serde(default = "default_width")]
    pub width: u16,
    /// Initial desktop height in pixels.
    #[serde(default = "default_height")]
    pub height: u16,
    /// Colour depth negotiated with the server.
    #[serde(default)]
    pub color_depth: ColorDepth,
    /// Certificate trust policy.
    #[serde(default)]
    pub cert_policy: CertPolicy,
    /// Pinned certificate fingerprint (`sha256:<hex>`).
    #[serde(default)]
    pub pinned_fingerprint: Option<String>,
    /// Optional PEM bundle with additional trusted CAs.
    #[serde(default)]
    pub ca_bundle: Option<PathBuf>,
    /// Request the clipboard channel.
    #[serde(default = "default_true")]
    pub clipboard: bool,
    /// Ask the server to change the desktop size when the window is resized.
    #[serde(default = "default_true")]
    pub dynamic_resize: bool,
    /// Domain (NetBIOS) part of the user name.
    #[serde(default)]
    pub domain: Option<String>,
    /// Connect to the console session instead of a new one.
    #[serde(default)]
    pub console_session: bool,
    /// Allow the RDP server to fall back from CredSSP to plain TLS.
    #[serde(default)]
    pub allow_tls_fallback: bool,
    /// Automatic reconnection policy.
    #[serde(default)]
    pub reconnect: ReconnectPolicy,
    /// Abort the connection attempt after this many seconds.
    #[serde(default = "default_connect_timeout_secs")]
    pub connect_timeout_secs: u64,
}

impl Default for RdpOptions {
    fn default() -> Self {
        Self {
            width: default_width(),
            height: default_height(),
            color_depth: ColorDepth::default(),
            cert_policy: CertPolicy::default(),
            pinned_fingerprint: None,
            ca_bundle: None,
            clipboard: true,
            dynamic_resize: true,
            domain: None,
            console_session: false,
            allow_tls_fallback: false,
            reconnect: ReconnectPolicy::default(),
            connect_timeout_secs: default_connect_timeout_secs(),
        }
    }
}

/// Automatic reconnection behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconnectPolicy {
    /// Whether to reconnect at all.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Maximum number of consecutive attempts; 0 means "keep trying".
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,
    /// Delay before the first attempt.
    #[serde(default = "default_initial_backoff_secs")]
    pub initial_backoff_secs: u64,
    /// Upper bound for the exponentially growing delay.
    #[serde(default = "default_max_backoff_secs")]
    pub max_backoff_secs: u64,
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            max_attempts: default_max_attempts(),
            initial_backoff_secs: default_initial_backoff_secs(),
            max_backoff_secs: default_max_backoff_secs(),
        }
    }
}

impl ReconnectPolicy {
    /// Delay before attempt number `attempt` (1 based), including deterministic
    /// jitter so that a fleet of clients does not reconnect in lockstep.
    pub fn delay_for(&self, attempt: u32) -> Option<Duration> {
        if !self.enabled || attempt == 0 {
            return None;
        }
        if self.max_attempts > 0 && attempt > self.max_attempts {
            return None;
        }
        let exp = attempt.saturating_sub(1).min(6);
        let base = self
            .initial_backoff_secs
            .saturating_mul(1u64 << exp)
            .min(self.max_backoff_secs.max(self.initial_backoff_secs));
        // Deterministic jitter of up to 25 % of the computed delay.
        let jitter = base / 4 * ((attempt % 4) as u64);
        Some(Duration::from_secs(
            (base + jitter).min(self.max_backoff_secs.max(base)),
        ))
    }

    /// Validates the configured bounds.
    pub fn validate(&self) -> RdtResult<()> {
        if self.initial_backoff_secs == 0 {
            return Err(RdtError::new(
                ErrorCode::InvalidInput,
                "reconnect initial backoff must be at least one second",
            ));
        }
        if self.max_backoff_secs < self.initial_backoff_secs {
            return Err(RdtError::new(
                ErrorCode::InvalidInput,
                "reconnect max backoff must be >= initial backoff",
            ));
        }
        Ok(())
    }
}

/// A keyboard layout advertised to the RDP server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyboardLayout {
    /// Windows keyboard layout identifier (HKL).
    pub id: u32,
    /// Display name.
    pub name: &'static str,
}

impl KeyboardLayout {
    /// US English layout.
    pub const US: Self = Self {
        id: 0x0000_0409,
        name: "US English",
    };
    /// UK English layout.
    pub const UK: Self = Self {
        id: 0x0000_0809,
        name: "UK English",
    };
    /// German layout.
    pub const DE: Self = Self {
        id: 0x0000_0407,
        name: "German",
    };
    /// French layout.
    pub const FR: Self = Self {
        id: 0x0000_040C,
        name: "French",
    };
    /// Spanish layout.
    pub const ES: Self = Self {
        id: 0x0000_040A,
        name: "Spanish",
    };

    /// The layouts offered in the UI.
    pub const ALL: &'static [Self] = &[Self::US, Self::UK, Self::DE, Self::FR, Self::ES];
}

impl Default for KeyboardLayout {
    fn default() -> Self {
        Self::US
    }
}

const fn default_true() -> bool {
    true
}
const fn default_keepalive_secs() -> u64 {
    30
}
const fn default_connect_timeout_secs() -> u64 {
    15
}
const fn default_cols() -> u16 {
    100
}
const fn default_rows() -> u16 {
    30
}
const fn default_scrollback() -> usize {
    5000
}
const fn default_font_size() -> f32 {
    14.0
}
fn default_term() -> String {
    "xterm-256color".to_owned()
}
const fn default_width() -> u16 {
    1280
}
const fn default_height() -> u16 {
    800
}
const fn default_max_attempts() -> u32 {
    5
}
const fn default_initial_backoff_secs() -> u64 {
    2
}
const fn default_max_backoff_secs() -> u64 {
    60
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_defaults_are_conventional() {
        assert_eq!(Protocol::Ssh.default_port(), 22);
        assert_eq!(Protocol::Rdp.default_port(), 3389);
        assert_eq!("RDP".parse::<Protocol>().expect("parse"), Protocol::Rdp);
        assert!("telnet".parse::<Protocol>().is_err());
    }

    #[test]
    fn endpoint_parsing_handles_ports_and_ipv6() {
        assert_eq!(
            Endpoint::parse("db01:2222", Protocol::Ssh)
                .expect("parse")
                .to_string(),
            "db01:2222"
        );
        assert_eq!(
            Endpoint::parse("db01", Protocol::Rdp)
                .expect("parse")
                .to_string(),
            "db01:3389"
        );
        let v6 = Endpoint::parse("[2001:db8::1]:3390", Protocol::Rdp).expect("parse");
        assert_eq!(v6.host, "2001:db8::1");
        assert_eq!(v6.port, 3390);
        assert_eq!(v6.to_string(), "[2001:db8::1]:3390");
        assert!(Endpoint::parse("host:notaport", Protocol::Ssh).is_err());
        assert!(Endpoint::parse("", Protocol::Ssh).is_err());
        assert!(Endpoint::parse("bad host", Protocol::Ssh).is_err());
    }

    #[test]
    fn host_key_policy_parses() {
        assert_eq!(
            "strict".parse::<HostKeyPolicy>().expect("parse"),
            HostKeyPolicy::Strict
        );
        assert_eq!(
            "accept-new".parse::<HostKeyPolicy>().expect("parse"),
            HostKeyPolicy::AcceptNew
        );
        assert!(!HostKeyPolicy::Strict.auto_accepts_unknown());
        assert!("no".parse::<HostKeyPolicy>().is_err());
    }

    #[test]
    fn auth_method_descriptions_never_leak() {
        let method = AuthMethod::Password(CredentialSource::Prompt);
        assert_eq!(method.describe(), "password");
        for method in [
            AuthMethod::None,
            AuthMethod::Password(CredentialSource::Prompt),
            AuthMethod::PrivateKey(PrivateKeyAuth::default()),
            AuthMethod::Agent { identity: None },
            AuthMethod::KeyboardInteractive(CredentialSource::Prompt),
        ] {
            let description = method.describe();
            assert!(!description.contains("hunter2"), "{description}");
            assert!(description.len() < 64, "{description}");
        }
    }

    #[test]
    fn reconnect_backoff_grows_and_stops() {
        let policy = ReconnectPolicy {
            enabled: true,
            max_attempts: 3,
            initial_backoff_secs: 2,
            max_backoff_secs: 60,
        };
        assert_eq!(policy.delay_for(0), None);
        let first = policy.delay_for(1).expect("delay");
        let second = policy.delay_for(2).expect("delay");
        assert!(
            second >= first,
            "{second:?} should not shrink below {first:?}"
        );
        assert_eq!(policy.delay_for(4), None);
        let disabled = ReconnectPolicy {
            enabled: false,
            ..policy
        };
        assert_eq!(disabled.delay_for(1), None);
    }

    #[test]
    fn reconnect_validation_rejects_nonsense() {
        assert!(ReconnectPolicy::default().validate().is_ok());
        let broken = ReconnectPolicy {
            initial_backoff_secs: 0,
            ..Default::default()
        };
        assert_eq!(
            broken.validate().unwrap_err().code(),
            ErrorCode::InvalidInput
        );
        let inverted = ReconnectPolicy {
            initial_backoff_secs: 30,
            max_backoff_secs: 5,
            ..Default::default()
        };
        assert!(inverted.validate().is_err());
    }

    #[test]
    fn option_defaults_are_safe_and_sane() {
        let options = RdpOptions::default();
        assert_eq!(options.cert_policy, CertPolicy::Verify);
        assert!(options.clipboard);
        assert!(options.dynamic_resize);
        assert!(!options.console_session);
        assert!(!options.allow_tls_fallback);
        assert_eq!(options.width, default_width());
        assert_eq!(options.height, default_height());

        let ssh = SshOptions::default();
        assert_eq!(ssh.host_key_policy, HostKeyPolicy::Strict);
        assert!(!ssh.compression);
        assert!(ssh.sftp_enabled);
        assert_eq!(ssh.keepalive_secs, default_keepalive_secs());
        assert!(ssh.connect_timeout_secs > 0);
        assert!(ssh.reconnect.enabled);
    }

    #[test]
    fn color_depth_reports_bpp() {
        assert_eq!(ColorDepth::Rgb565.bits_per_pixel(), 16);
        assert_eq!(ColorDepth::default().bits_per_pixel(), 24);
    }
}
