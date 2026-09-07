//! Application wide settings (everything that is not a connection profile).

use serde::{Deserialize, Serialize};

use rdt_types::TerminalOptions;

/// Version of the on-disk document produced by this build.
pub const CURRENT_SCHEMA_VERSION: u32 = 1;

/// Colour theme.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Theme {
    /// Follow the operating system.
    #[default]
    System,
    /// Light background.
    Light,
    /// Dark background.
    Dark,
}

/// Verbosity of the rotating log files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    /// Only errors.
    Error,
    /// Errors and warnings.
    Warn,
    /// Normal operational detail.
    #[default]
    Info,
    /// Protocol level detail; can be large.
    Debug,
    /// Everything, including tracing spans.
    Trace,
}

impl LogLevel {
    /// The `tracing` level filter matching this setting.
    pub fn as_filter(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }
}

/// Interface preferences.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UiSettings {
    /// Colour theme.
    #[serde(default)]
    pub theme: Theme,
    /// Interface scale in percent.
    #[serde(default = "default_ui_scale")]
    pub ui_scale_percent: u16,
    /// Show the status bar at the bottom of the window.
    #[serde(default = "default_true")]
    pub show_status_bar: bool,
    /// Page shown after start up.
    #[serde(default)]
    pub start_page: String,
    /// Confirm before closing an active session.
    #[serde(default = "default_true")]
    pub confirm_disconnect: bool,
    /// Wrap text in the log viewer.
    #[serde(default)]
    pub wrap_logs: bool,
}

impl Default for UiSettings {
    fn default() -> Self {
        Self {
            theme: Theme::default(),
            ui_scale_percent: default_ui_scale(),
            show_status_bar: true,
            start_page: "dashboard".to_owned(),
            confirm_disconnect: true,
            wrap_logs: false,
        }
    }
}

/// Security relevant preferences.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecuritySettings {
    /// Copy text from a remote session to the local clipboard.
    #[serde(default = "default_true")]
    pub allow_remote_to_local_clipboard: bool,
    /// Send local clipboard text to a remote session.
    #[serde(default = "default_true")]
    pub allow_local_to_remote_clipboard: bool,
    /// Redact anything that looks like a secret before it reaches a log file.
    #[serde(default = "default_true")]
    pub redact_logs: bool,
    /// Lock the vault after this many idle minutes (0 disables the timer).
    #[serde(default = "default_vault_lock_minutes")]
    pub vault_lock_after_minutes: u32,
    /// Forget an SSH agent forwarding socket as soon as a session ends.
    #[serde(default = "default_true")]
    pub revoke_agent_forwarding_on_disconnect: bool,
}

impl Default for SecuritySettings {
    fn default() -> Self {
        Self {
            allow_remote_to_local_clipboard: true,
            allow_local_to_remote_clipboard: true,
            redact_logs: true,
            vault_lock_after_minutes: default_vault_lock_minutes(),
            revoke_agent_forwarding_on_disconnect: true,
        }
    }
}

/// Session behaviour defaults applied to new profiles.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionSettings {
    /// Maximum number of concurrent sessions.
    #[serde(default = "default_max_sessions")]
    pub max_concurrent_sessions: usize,
    /// Keep sessions alive when the window is minimised.
    #[serde(default = "default_true")]
    pub keep_alive_when_minimised: bool,
    /// Write an audit record for every connection state change.
    #[serde(default = "default_true")]
    pub audit_connections: bool,
    /// Days of audit history to keep (0 keeps everything).
    #[serde(default = "default_audit_retention_days")]
    pub audit_retention_days: u32,
}

impl Default for SessionSettings {
    fn default() -> Self {
        Self {
            max_concurrent_sessions: default_max_sessions(),
            keep_alive_when_minimised: true,
            audit_connections: true,
            audit_retention_days: default_audit_retention_days(),
        }
    }
}

/// The `[settings]` table of the configuration document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Settings {
    /// Interface preferences.
    #[serde(default)]
    pub ui: UiSettings,
    /// Security preferences.
    #[serde(default)]
    pub security: SecuritySettings,
    /// Session defaults.
    #[serde(default)]
    pub session: SessionSettings,
    /// Terminal defaults applied to new SSH profiles.
    #[serde(default)]
    pub terminal: TerminalOptions,
    /// Verbosity written to the rotating log files.
    #[serde(default)]
    pub log_level: LogLevel,
    /// Largest single log file before rotation, in mebibytes.
    #[serde(default = "default_log_max_mib")]
    pub log_max_mib: u32,
    /// Number of rotated log files to keep.
    #[serde(default = "default_log_keep")]
    pub log_keep: usize,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            ui: UiSettings::default(),
            security: SecuritySettings::default(),
            session: SessionSettings::default(),
            terminal: TerminalOptions::default(),
            log_level: LogLevel::default(),
            log_max_mib: default_log_max_mib(),
            log_keep: default_log_keep(),
        }
    }
}

const fn default_true() -> bool {
    true
}

const fn default_ui_scale() -> u16 {
    100
}

const fn default_max_sessions() -> usize {
    16
}

const fn default_vault_lock_minutes() -> u32 {
    15
}

const fn default_audit_retention_days() -> u32 {
    90
}

const fn default_log_max_mib() -> u32 {
    16
}

const fn default_log_keep() -> usize {
    5
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_safe() {
        let settings = Settings::default();
        assert!(settings.security.redact_logs);
        assert!(settings.security.revoke_agent_forwarding_on_disconnect);
        assert!(settings.session.audit_connections);
        assert_eq!(settings.session.max_concurrent_sessions, 16);
        assert_eq!(settings.log_level, LogLevel::Info);
        assert_eq!(settings.ui.theme, Theme::System);
    }

    #[test]
    fn log_levels_map_to_filters() {
        assert_eq!(LogLevel::Error.as_filter(), "error");
        assert_eq!(LogLevel::Trace.as_filter(), "trace");
        assert_eq!(LogLevel::default().as_filter(), "info");
    }

    #[test]
    fn ui_scale_is_plausible() {
        assert_eq!(UiSettings::default().ui_scale_percent, 100);
    }
}
