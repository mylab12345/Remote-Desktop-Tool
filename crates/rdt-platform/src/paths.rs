//! Filesystem locations used by RDT.
//!
//! Locations follow the platform conventions: XDG base directories on Linux,
//! `%APPDATA%` on Windows and `~/Library/Application Support` on macOS.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// All filesystem locations RDT reads from and writes to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppPaths {
    /// Directory holding configuration files.
    pub config_dir: PathBuf,
    /// Directory holding persistent application state (profiles, vault).
    pub data_dir: PathBuf,
    /// Directory holding log files.
    pub log_dir: PathBuf,
    /// Directory for temporary runtime files (sockets, lock files).
    pub runtime_dir: PathBuf,
}

impl AppPaths {
    /// Resolves the default locations for the current platform and user.
    ///
    /// `RDT_CONFIG_DIR`, `RDT_DATA_DIR`, `RDT_LOG_DIR` and `RDT_RUNTIME_DIR`
    /// override individual entries, which is what the test suite and the
    /// portable install mode rely on.
    pub fn detect() -> Self {
        let home = home_dir();
        let (default_config, default_data, default_log) = platform_dirs(&home);
        let runtime = std::env::temp_dir().join(format!("rdt-{}", user_token()));
        Self {
            config_dir: override_dir("RDT_CONFIG_DIR", default_config),
            data_dir: override_dir("RDT_DATA_DIR", default_data),
            log_dir: override_dir("RDT_LOG_DIR", default_log),
            runtime_dir: override_dir("RDT_RUNTIME_DIR", runtime),
        }
    }

    /// Builds a fully custom set of paths (used by the agent and by tests).
    pub fn new(
        config_dir: PathBuf,
        data_dir: PathBuf,
        log_dir: PathBuf,
        runtime_dir: PathBuf,
    ) -> Self {
        Self {
            config_dir,
            data_dir,
            log_dir,
            runtime_dir,
        }
    }

    /// Main configuration file.
    pub fn config_file(&self) -> PathBuf {
        self.config_dir.join("config.toml")
    }

    /// Connection profile store.
    pub fn profiles_file(&self) -> PathBuf {
        self.data_dir.join("profiles.toml")
    }

    /// Encrypted secret vault.
    pub fn vault_file(&self) -> PathBuf {
        self.data_dir.join("secrets.vault")
    }

    /// SSH known hosts database.
    pub fn known_hosts_file(&self) -> PathBuf {
        self.data_dir.join("known_hosts")
    }

    /// Application log file.
    pub fn log_file(&self) -> PathBuf {
        self.log_dir.join("rdt.log")
    }

    /// Audit trail (JSON lines).
    pub fn audit_file(&self) -> PathBuf {
        self.log_dir.join("audit.jsonl")
    }

    /// Local control socket of the agent daemon.
    pub fn agent_socket(&self) -> PathBuf {
        #[cfg(unix)]
        {
            self.runtime_dir.join("agent.sock")
        }
        #[cfg(windows)]
        {
            // Named pipes are addressed through \\.\pipe\, not the filesystem.
            PathBuf::from(r"\\.\pipe\rdt-agent")
        }
        #[cfg(not(any(unix, windows)))]
        {
            self.runtime_dir.join("agent.sock")
        }
    }

    /// Lock file that keeps two desktop clients from racing on the same state.
    pub fn lock_file(&self) -> PathBuf {
        self.runtime_dir.join("rdt.lock")
    }

    /// Creates every directory that RDT needs, with owner-only permissions.
    pub fn ensure(&self) -> std::io::Result<()> {
        for dir in [
            &self.config_dir,
            &self.data_dir,
            &self.log_dir,
            &self.runtime_dir,
        ] {
            std::fs::create_dir_all(dir)?;
            crate::platform_impl::restrict_dir_to_owner(dir)?;
        }
        Ok(())
    }
}

fn override_dir(variable: &str, fallback: PathBuf) -> PathBuf {
    std::env::var_os(variable)
        .map(PathBuf::from)
        .unwrap_or(fallback)
}

fn platform_dirs(home: &Path) -> (PathBuf, PathBuf, PathBuf) {
    #[cfg(target_os = "windows")]
    {
        let roaming = std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join("AppData").join("Roaming"));
        let local = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| roaming.join("Local"));
        return (
            roaming.join("RDT"),
            roaming.join("RDT"),
            local.join("RDT").join("logs"),
        );
    }
    #[cfg(target_os = "macos")]
    {
        let support = home.join("Library").join("Application Support");
        return (
            support.join("RDT"),
            support.join("RDT"),
            home.join("Library").join("Logs").join("RDT"),
        );
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        let config = xdg_dir("XDG_CONFIG_HOME", home.join(".config"));
        let data = xdg_dir("XDG_DATA_HOME", home.join(".local").join("share"));
        let state = xdg_dir("XDG_STATE_HOME", home.join(".local").join("state"));
        (
            config.join("rdt"),
            data.join("rdt"),
            state.join("rdt").join("log"),
        )
    }
}

fn xdg_dir(variable: &str, fallback: PathBuf) -> PathBuf {
    std::env::var_os(variable)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or(fallback)
}

fn home_dir() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME").filter(|value| !value.is_empty()) {
        return PathBuf::from(home);
    }
    if let Some(profile) = std::env::var_os("USERPROFILE").filter(|value| !value.is_empty()) {
        return PathBuf::from(profile);
    }
    PathBuf::from(".")
}

/// A stable per-user token used to scope runtime directories.
fn user_token() -> String {
    #[cfg(unix)]
    {
        // SAFETY: `getuid` takes no arguments and cannot fail.
        let uid = unsafe { libc::getuid() };
        return uid.to_string();
    }
    #[cfg(not(unix))]
    {
        let name = std::env::var("USERNAME").unwrap_or_else(|_| "user".to_owned());
        let mut hash = 0u64;
        for byte in name.bytes() {
            hash = hash.wrapping_mul(31).wrapping_add(byte as u64);
        }
        format!("{hash:016x}")
    }
}

/// Expands a leading `~` in a user supplied path.
pub fn expand_tilde(path: &Path) -> PathBuf {
    let Some(text) = path.to_str() else {
        return path.to_path_buf();
    };
    if text == "~" {
        return home_dir();
    }
    if let Some(rest) = text.strip_prefix("~/") {
        return home_dir().join(rest);
    }
    #[cfg(windows)]
    {
        if let Some(rest) = text.strip_prefix("~\\") {
            return home_dir().join(rest);
        }
    }
    path.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_derived_from_the_environment() {
        let config = std::env::temp_dir().join("rdt-test-config");
        let data = std::env::temp_dir().join("rdt-test-data");
        let paths = AppPaths::new(
            config.clone(),
            data.clone(),
            config.join("log"),
            config.join("run"),
        );
        assert_eq!(paths.config_file(), config.join("config.toml"));
        assert_eq!(paths.profiles_file(), data.join("profiles.toml"));
        assert_eq!(paths.vault_file(), data.join("secrets.vault"));
        assert_eq!(paths.known_hosts_file(), data.join("known_hosts"));
        assert!(paths
            .audit_file()
            .to_string_lossy()
            .ends_with("audit.jsonl"));
    }

    #[test]
    fn environment_overrides_win() {
        let dir = std::env::temp_dir().join("rdt-override-check");
        std::env::set_var("RDT_CONFIG_DIR", &dir);
        let paths = AppPaths::detect();
        assert_eq!(paths.config_dir, dir);
        std::env::remove_var("RDT_CONFIG_DIR");
    }

    #[test]
    fn ensure_creates_directories() {
        let root = std::env::temp_dir().join(format!("rdt-ensure-{}", std::process::id()));
        let paths = AppPaths::new(
            root.join("config"),
            root.join("data"),
            root.join("log"),
            root.join("run"),
        );
        paths.ensure().expect("create directories");
        assert!(paths.config_dir.is_dir());
        assert!(paths.runtime_dir.is_dir());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn tilde_expansion_uses_the_home_directory() {
        let expanded = expand_tilde(Path::new("~/.ssh/id_ed25519"));
        assert!(!expanded.to_string_lossy().starts_with('~'));
        assert!(expanded.to_string_lossy().ends_with(".ssh/id_ed25519"));
        let absolute = PathBuf::from("/etc/hosts");
        assert_eq!(expand_tilde(&absolute), absolute);
    }

    #[test]
    fn runtime_socket_path_is_platform_shaped() {
        let paths = AppPaths::detect();
        let socket = paths.agent_socket();
        if cfg!(windows) {
            assert!(socket.to_string_lossy().contains("pipe"));
        } else {
            assert!(socket.to_string_lossy().ends_with("agent.sock"));
        }
    }
}
