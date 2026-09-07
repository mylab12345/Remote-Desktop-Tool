//! Operating system detection.

use std::fmt;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// The operating system families RDT supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OsFamily {
    /// Windows 10, Windows 11 and Windows Server 2016 and newer.
    Windows,
    /// Any Linux distribution using systemd or OpenRC.
    Linux,
    /// macOS (development machines only; not a supported deployment target).
    Macos,
    /// Anything else.
    Other,
}

impl OsFamily {
    /// The family of the running operating system.
    pub const fn current() -> Self {
        #[cfg(target_os = "windows")]
        {
            Self::Windows
        }
        #[cfg(target_os = "linux")]
        {
            Self::Linux
        }
        #[cfg(target_os = "macos")]
        {
            Self::Macos
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            Self::Other
        }
    }

    /// Stable identifier used in logs and telemetry.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Windows => "windows",
            Self::Linux => "linux",
            Self::Macos => "macos",
            Self::Other => "other",
        }
    }

    /// Whether this family uses systemd as its service manager.
    pub const fn uses_systemd(self) -> bool {
        matches!(self, Self::Linux)
    }

    /// Whether this family uses the Windows service control manager.
    pub const fn uses_scm(self) -> bool {
        matches!(self, Self::Windows)
    }
}

impl fmt::Display for OsFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Linux distribution details parsed from `os-release`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DistroInfo {
    /// `ID` field, for example `ubuntu` or `rocky`.
    pub id: String,
    /// `NAME` field, for example `Ubuntu`.
    pub name: String,
    /// `VERSION_ID` field, for example `24.04`.
    pub version: String,
    /// `ID_LIKE` field, for example `rhel fedora`.
    pub like: Vec<String>,
}

impl DistroInfo {
    /// The RHEL derived families that RDT ships packages for.
    pub const RHEL_LIKE: &'static [&'static str] =
        &["rhel", "centos", "fedora", "rocky", "almalinux"];
    /// The Debian derived families that RDT ships packages for.
    pub const DEBIAN_LIKE: &'static [&'static str] = &["debian", "ubuntu"];

    /// Parses the content of an `os-release` file.
    pub fn parse(content: &str) -> Self {
        let mut info = Self::default();
        for line in content.lines() {
            let line = line.trim();
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let value = unquote(value.trim());
            match key.trim() {
                "ID" => info.id = value,
                "NAME" => info.name = value,
                "VERSION_ID" => info.version = value,
                "ID_LIKE" => info.like = value.split_whitespace().map(str::to_owned).collect(),
                _ => {}
            }
        }
        if info.name.is_empty() && !info.id.is_empty() {
            info.name = info.id.clone();
        }
        info
    }

    /// Reads `/etc/os-release` (or `/usr/lib/os-release`) from disk.
    pub fn from_system() -> Option<Self> {
        for candidate in ["/etc/os-release", "/usr/lib/os-release"] {
            if let Ok(content) = std::fs::read_to_string(candidate) {
                let info = Self::parse(&content);
                if !info.id.is_empty() {
                    return Some(info);
                }
            }
        }
        None
    }

    /// Whether this distribution is one of the supported RHEL derivatives.
    pub fn is_rhel_like(&self) -> bool {
        self.matches_family(Self::RHEL_LIKE)
    }

    /// Whether this distribution is one of the supported Debian derivatives.
    pub fn is_debian_like(&self) -> bool {
        self.matches_family(Self::DEBIAN_LIKE)
    }

    fn matches_family(&self, families: &[&str]) -> bool {
        families.iter().any(|family| {
            self.id.eq_ignore_ascii_case(family)
                || self
                    .like
                    .iter()
                    .any(|like| like.eq_ignore_ascii_case(family))
        })
    }

    /// Preferred package format for this distribution.
    pub fn package_format(&self) -> &'static str {
        if self.is_debian_like() {
            "deb"
        } else if self.is_rhel_like() {
            "rpm"
        } else {
            "tar.gz"
        }
    }
}

fn unquote(value: &str) -> String {
    value.trim().trim_matches('"').trim_matches('\'').to_owned()
}

/// Everything RDT needs to know about the machine it runs on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformInfo {
    /// Operating system family.
    pub os: OsFamily,
    /// Target architecture, for example `x86_64`.
    pub arch: &'static str,
    /// Kernel or OS version string.
    pub os_version: String,
    /// Machine name.
    pub hostname: String,
    /// Linux distribution details (empty on other platforms).
    pub distro: Option<DistroInfo>,
    /// Whether the process runs with administrator privileges.
    pub elevated: bool,
    /// Whether a graphical session appears to be available.
    pub graphical_session: bool,
    /// Whether systemd is the active init system.
    pub systemd_active: bool,
    /// Display server in use (`x11`, `wayland` or empty).
    pub display_server: String,
}

impl PlatformInfo {
    /// Collects platform information for the running system.
    pub fn detect() -> Self {
        Self {
            os: OsFamily::current(),
            arch: std::env::consts::ARCH,
            os_version: crate::platform_impl::os_version(),
            hostname: crate::platform_impl::hostname(),
            distro: if cfg!(target_os = "linux") {
                DistroInfo::from_system()
            } else {
                None
            },
            elevated: crate::platform_impl::is_elevated(),
            graphical_session: crate::platform_impl::graphical_session(),
            systemd_active: Path::new("/run/systemd/system").is_dir(),
            display_server: std::env::var("WAYLAND_DISPLAY")
                .ok()
                .filter(|value| !value.is_empty())
                .map_or_else(
                    || {
                        if std::env::var_os("DISPLAY").is_some() {
                            "x11".to_owned()
                        } else {
                            String::new()
                        }
                    },
                    |_| "wayland".to_owned(),
                ),
        }
    }

    /// One line summary suitable for the dashboard and `rdt doctor`.
    pub fn summary(&self) -> String {
        let distro = self
            .distro
            .as_ref()
            .map(|distro| {
                if distro.version.is_empty() {
                    distro.name.clone()
                } else {
                    format!("{} {}", distro.name, distro.version)
                }
            })
            .unwrap_or_else(|| self.os_version.clone());
        format!(
            "{} {} ({}) on {}",
            self.os, self.arch, distro, self.hostname
        )
    }

    /// Whether the platform is one RDT ships installers for.
    pub fn is_supported(&self) -> bool {
        match self.os {
            OsFamily::Windows => true,
            OsFamily::Linux => self
                .distro
                .as_ref()
                .is_some_and(|distro| distro.is_debian_like() || distro.is_rhel_like()),
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UBUNTU: &str = r#"PRETTY_NAME="Ubuntu 24.04.1 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
ID=ubuntu
ID_LIKE=debian
"#;

    const ROCKY: &str = r#"NAME="Rocky Linux"
VERSION_ID="9.4"
ID="rocky"
ID_LIKE="rhel centos fedora"
"#;

    #[test]
    fn parses_os_release_files() {
        let ubuntu = DistroInfo::parse(UBUNTU);
        assert_eq!(ubuntu.id, "ubuntu");
        assert_eq!(ubuntu.name, "Ubuntu");
        assert_eq!(ubuntu.version, "24.04");
        assert!(ubuntu.is_debian_like());
        assert!(!ubuntu.is_rhel_like());
        assert_eq!(ubuntu.package_format(), "deb");

        let rocky = DistroInfo::parse(ROCKY);
        assert_eq!(rocky.id, "rocky");
        assert!(rocky.is_rhel_like());
        assert_eq!(rocky.package_format(), "rpm");
    }

    #[test]
    fn rhel_derivatives_are_recognised_through_id_like() {
        let alma = DistroInfo::parse("ID=almalinux\nID_LIKE=\"rhel centos fedora\"\nNAME=\"AlmaLinux\"\nVERSION_ID=\"9.5\"\n");
        assert!(alma.is_rhel_like());
        let fedora = DistroInfo::parse("ID=fedora\nNAME=Fedora\nVERSION_ID=41\n");
        assert!(fedora.is_rhel_like());
    }

    #[test]
    fn unknown_distro_falls_back_to_tarball() {
        let other = DistroInfo::parse("ID=gentoo\nNAME=Gentoo\n");
        assert_eq!(other.package_format(), "tar.gz");
        assert!(!other.is_debian_like() && !other.is_rhel_like());
    }

    #[test]
    fn platform_detection_produces_a_summary() {
        let info = PlatformInfo::detect();
        assert!(!info.arch.is_empty());
        assert!(info.summary().contains(info.arch));
        assert_eq!(info.os, OsFamily::current());
    }
}
