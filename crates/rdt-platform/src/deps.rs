//! Runtime dependency detection.
//!
//! `rdt doctor` and the dashboard both render the result of
//! [`probe_dependencies`].  Probing is read-only: it never installs anything and
//! never requires elevated privileges.

use std::path::Path;
use std::process::Command;

use serde::{Deserialize, Serialize};

/// Identity of a probed dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyId {
    /// A running SSH agent (`SSH_AUTH_SOCK` on Unix, pageant on Windows).
    SshAgent,
    /// The platform secret store (libsecret CLI on Linux, DPAPI on Windows).
    SecretStore,
    /// systemd, required to install the unattended agent as a service.
    Systemd,
    /// The Windows service control manager.
    WindowsScm,
    /// A clipboard bridge used by the RDP clipboard channel.
    Clipboard,
    /// An OpenSSH known hosts file that RDT can write to.
    KnownHosts,
    /// The encrypted vault used when no OS keyring is available.
    Vault,
}

impl DependencyId {
    /// Stable identifier used in configuration and reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SshAgent => "ssh-agent",
            Self::SecretStore => "secret-store",
            Self::Systemd => "systemd",
            Self::WindowsScm => "windows-scm",
            Self::Clipboard => "clipboard",
            Self::KnownHosts => "known-hosts",
            Self::Vault => "encrypted-vault",
        }
    }

    /// Human readable description shown in `rdt doctor`.
    pub const fn describe(self) -> &'static str {
        match self {
            Self::SshAgent => "SSH agent for key based authentication without passphrases on disk",
            Self::SecretStore => "Operating system secret store for saved passwords",
            Self::Systemd => "systemd, used to run the unattended agent in the background",
            Self::WindowsScm => "Windows service control manager for the unattended agent",
            Self::Clipboard => "Clipboard bridge used by the RDP clipboard channel",
            Self::KnownHosts => "Writable known_hosts database for SSH host key verification",
            Self::Vault => "Encrypted vault file used when no OS keyring is present",
        }
    }
}

/// Result of probing a single dependency.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyReport {
    /// What was probed.
    pub id: DependencyId,
    /// Outcome.
    pub status: DependencyStatus,
    /// Human readable detail (path, program name, error message).
    pub detail: String,
    /// Whether RDT can work without this dependency.
    pub optional: bool,
}

impl DependencyReport {
    /// Whether the dependency is usable.
    pub fn available(&self) -> bool {
        matches!(self.status, DependencyStatus::Available)
    }
}

/// Outcome of a probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyStatus {
    /// Present and usable.
    Available,
    /// Not present.
    Missing,
    /// Present but unusable (for example a socket without permissions).
    Degraded,
    /// Not applicable on this platform.
    NotApplicable,
}

/// The full probe result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencySuite {
    /// Individual results, in display order.
    pub reports: Vec<DependencyReport>,
    /// Whether every *required* dependency is usable.
    pub ready: bool,
}

impl DependencySuite {
    /// Every report that is not usable.
    pub fn problems(&self) -> Vec<&DependencyReport> {
        self.reports
            .iter()
            .filter(|report| !report.optional && !report.available())
            .collect()
    }
}

/// Probes every dependency RDT knows about.
pub fn probe_dependencies(paths: &crate::AppPaths) -> DependencySuite {
    let reports = vec![
        probe_ssh_agent(),
        probe_secret_store(),
        probe_service_manager(),
        probe_clipboard(),
        probe_known_hosts(paths),
        probe_vault(paths),
    ];
    let ready = reports
        .iter()
        .all(|report| report.optional || report.available());
    DependencySuite { reports, ready }
}

fn report(
    id: DependencyId,
    status: DependencyStatus,
    detail: impl Into<String>,
    optional: bool,
) -> DependencyReport {
    DependencyReport {
        id,
        status,
        detail: detail.into(),
        optional,
    }
}

fn probe_ssh_agent() -> DependencyReport {
    let id = DependencyId::SshAgent;
    #[cfg(windows)]
    {
        // Pageant or the OpenSSH agent service; both expose a named pipe.
        let pipe = Path::new(r"\\.\pipe\openssh-ssh-agent");
        return if pipe.exists() {
            report(
                id,
                DependencyStatus::Available,
                pipe.display().to_string(),
                true,
            )
        } else {
            report(
                id,
                DependencyStatus::Missing,
                "OpenSSH agent pipe not found",
                true,
            )
        };
    }
    #[cfg(not(windows))]
    {
        match std::env::var_os("SSH_AUTH_SOCK") {
            Some(value) => {
                let path = Path::new(&value);
                if path.exists() {
                    report(
                        id,
                        DependencyStatus::Available,
                        path.display().to_string(),
                        true,
                    )
                } else {
                    report(
                        id,
                        DependencyStatus::Degraded,
                        format!(
                            "SSH_AUTH_SOCK points at a missing socket: {}",
                            path.display()
                        ),
                        true,
                    )
                }
            }
            None => report(
                id,
                DependencyStatus::Missing,
                "SSH_AUTH_SOCK is not set; key authentication will need a passphrase",
                true,
            ),
        }
    }
}

fn probe_secret_store() -> DependencyReport {
    let id = DependencyId::SecretStore;
    #[cfg(windows)]
    {
        return report(
            id,
            DependencyStatus::Available,
            "Windows DPAPI (user scope)",
            true,
        );
    }
    #[cfg(target_os = "macos")]
    {
        return report(id, DependencyStatus::Available, "macOS Keychain", true);
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        return match which("secret-tool") {
            Some(path) => {
                let writable = std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some();
                if writable {
                    report(
                        id,
                        DependencyStatus::Available,
                        path.display().to_string(),
                        true,
                    )
                } else {
                    report(
                        id,
                        DependencyStatus::Degraded,
                        format!(
                            "{} is installed but no D-Bus session bus is available",
                            path.display()
                        ),
                        true,
                    )
                }
            }
            None => report(
                id,
                DependencyStatus::Missing,
                "secret-tool (libsecret) not found; RDT will use its encrypted vault",
                true,
            ),
        };
    }
}

fn probe_service_manager() -> DependencyReport {
    #[cfg(windows)]
    {
        return report(
            DependencyId::WindowsScm,
            DependencyStatus::Available,
            "service control manager",
            true,
        );
    }
    #[cfg(not(windows))]
    {
        let id = DependencyId::Systemd;
        if Path::new("/run/systemd/system").is_dir() {
            match which("systemctl") {
                Some(path) => report(
                    id,
                    DependencyStatus::Available,
                    path.display().to_string(),
                    true,
                ),
                None => report(
                    id,
                    DependencyStatus::Degraded,
                    "systemd runs but systemctl is missing",
                    true,
                ),
            }
        } else {
            report(
                id,
                DependencyStatus::Missing,
                "systemd is not the active init system; install the agent under your own supervisor",
                true,
            )
        }
    }
}

fn probe_clipboard() -> DependencyReport {
    let id = DependencyId::Clipboard;
    #[cfg(windows)]
    {
        return report(id, DependencyStatus::Available, "Win32 clipboard", true);
    }
    #[cfg(not(windows))]
    {
        let wayland = std::env::var_os("WAYLAND_DISPLAY").is_some();
        let x11 = std::env::var_os("DISPLAY").is_some();
        if wayland {
            let copy = which("wl-copy");
            let paste = which("wl-paste");
            return match (copy, paste) {
                (Some(copy), Some(_)) => report(
                    id,
                    DependencyStatus::Available,
                    copy.display().to_string(),
                    true,
                ),
                _ => report(
                    id,
                    DependencyStatus::Missing,
                    "install wl-clipboard (wl-copy/wl-paste) for RDP clipboard sharing",
                    true,
                ),
            };
        }
        if x11 {
            for tool in ["xclip", "xsel"] {
                if let Some(path) = which(tool) {
                    return report(
                        id,
                        DependencyStatus::Available,
                        path.display().to_string(),
                        true,
                    );
                }
            }
            return report(
                id,
                DependencyStatus::Missing,
                "install xclip or xsel for RDP clipboard sharing",
                true,
            );
        }
        report(
            id,
            DependencyStatus::Missing,
            "no graphical session detected",
            true,
        )
    }
}

fn probe_known_hosts(paths: &crate::AppPaths) -> DependencyReport {
    let id = DependencyId::KnownHosts;
    let file = paths.known_hosts_file();
    if file.exists() {
        match std::fs::OpenOptions::new().append(true).open(&file) {
            Ok(_) => report(
                id,
                DependencyStatus::Available,
                file.display().to_string(),
                false,
            ),
            Err(error) => report(
                id,
                DependencyStatus::Degraded,
                format!("{} is not writable: {error}", file.display()),
                false,
            ),
        }
    } else if let Some(parent) = file.parent() {
        match std::fs::create_dir_all(parent) {
            Ok(()) => report(
                id,
                DependencyStatus::Available,
                format!("{} (will be created)", file.display()),
                false,
            ),
            Err(error) => report(
                id,
                DependencyStatus::Degraded,
                format!("cannot create {}: {error}", parent.display()),
                false,
            ),
        }
    } else {
        report(id, DependencyStatus::Degraded, "no parent directory", false)
    }
}

fn probe_vault(paths: &crate::AppPaths) -> DependencyReport {
    let id = DependencyId::Vault;
    let file = paths.vault_file();
    if file.exists() {
        return report(
            id,
            DependencyStatus::Available,
            file.display().to_string(),
            true,
        );
    }
    match file.parent().map(std::fs::create_dir_all) {
        Some(Ok(())) => report(
            id,
            DependencyStatus::Available,
            format!("{} (will be created on first use)", file.display()),
            true,
        ),
        Some(Err(error)) => report(
            id,
            DependencyStatus::Degraded,
            format!("cannot create the vault directory: {error}"),
            true,
        ),
        None => report(id, DependencyStatus::Degraded, "no parent directory", true),
    }
}

/// Locates an executable on `PATH`.
pub fn which(program: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(program);
        if candidate.is_file() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(metadata) = std::fs::metadata(&candidate) {
                    if metadata.permissions().mode() & 0o111 != 0 {
                        return Some(candidate);
                    }
                    continue;
                }
            }
            #[cfg(not(unix))]
            {
                return Some(candidate);
            }
        }
        #[cfg(windows)]
        {
            for extension in ["exe", "cmd", "bat"] {
                let candidate = dir.join(format!("{program}.{extension}"));
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
    }
    None
}

/// Runs a program and returns its trimmed standard output.
pub fn run_capture(program: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|error| format!("cannot execute {program}: {error}"))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_returns_a_report_for_every_dependency() {
        let paths = crate::AppPaths::new(
            std::env::temp_dir().join("rdt-probe-config"),
            std::env::temp_dir().join("rdt-probe-data"),
            std::env::temp_dir().join("rdt-probe-log"),
            std::env::temp_dir().join("rdt-probe-run"),
        );
        std::fs::create_dir_all(&paths.data_dir).expect("create data dir");
        let suite = probe_dependencies(&paths);
        assert!(suite.reports.len() >= 5);
        for report in &suite.reports {
            assert!(!report.detail.is_empty(), "{:?}", report.id);
        }
        let known = suite
            .reports
            .iter()
            .find(|report| report.id == DependencyId::KnownHosts)
            .expect("known hosts report");
        assert!(known.available(), "{known:?}");
        std::fs::remove_dir_all(&paths.data_dir).ok();
    }

    #[test]
    fn which_finds_the_shell() {
        let found = which("sh").or_else(|| which("bash"));
        if cfg!(unix) {
            assert!(found.is_some(), "a POSIX shell should be on PATH");
        }
    }

    #[test]
    fn which_rejects_missing_programs() {
        assert!(which("definitely-not-a-real-program-xyz").is_none());
    }

    #[test]
    fn run_capture_reports_failures() {
        if cfg!(unix) {
            assert!(run_capture("sh", &["-c", "echo hi"]).is_ok());
            assert!(run_capture("definitely-not-a-real-program-xyz", &[]).is_err());
        }
    }

    #[test]
    fn reports_classify_problems() {
        let suite = DependencySuite {
            reports: vec![
                report(DependencyId::Vault, DependencyStatus::Missing, "gone", true),
                report(
                    DependencyId::KnownHosts,
                    DependencyStatus::Missing,
                    "gone",
                    false,
                ),
            ],
            ready: false,
        };
        assert_eq!(suite.problems().len(), 1);
        assert_eq!(suite.problems()[0].id, DependencyId::KnownHosts);
    }
}
