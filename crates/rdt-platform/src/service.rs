//! Service integration: systemd units on Linux, the Windows SCM on Windows.
//!
//! Installing a service is the only operation in RDT that may need elevated
//! privileges.  Every function returns a typed error explaining exactly what is
//! missing when it does not have them.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use rdt_types::{ErrorCode, RdtError, RdtResult};

/// What the service should run and how it should be supervised.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceSpec {
    /// Service name (also the unit name on Linux).
    pub name: String,
    /// Description shown by the service manager.
    pub description: String,
    /// Absolute path of the executable.
    pub executable: PathBuf,
    /// Arguments passed to the executable.
    pub arguments: Vec<String>,
    /// Install for the whole machine instead of the current user.
    pub system_wide: bool,
    /// Start the service immediately after installing it.
    pub start_now: bool,
    /// Restart the service when it exits.
    pub restart_on_failure: bool,
    /// User the service should run as (Linux only; empty means the default).
    pub run_as_user: Option<String>,
}

impl ServiceSpec {
    /// Builds a spec for the RDT agent.
    pub fn agent(executable: impl Into<PathBuf>, system_wide: bool) -> Self {
        Self {
            name: "rdt-agent".to_owned(),
            description: "RDT unattended remote access agent".to_owned(),
            executable: executable.into(),
            arguments: vec!["agent".to_owned(), "run".to_owned()],
            system_wide,
            start_now: true,
            restart_on_failure: true,
            run_as_user: None,
        }
    }

    /// Validates the spec before touching the system.
    pub fn validate(&self) -> RdtResult<()> {
        if self.name.trim().is_empty() || self.name.contains(char::is_whitespace) {
            return Err(RdtError::new(
                ErrorCode::InvalidInput,
                "service name must be non-empty and free of whitespace",
            ));
        }
        if !self.executable.is_absolute() {
            return Err(RdtError::new(
                ErrorCode::InvalidInput,
                "service executable must be an absolute path",
            ));
        }
        Ok(())
    }
}

/// Arguments accepted by [`install_service`].
#[derive(Debug, Clone)]
pub struct ServiceInstallRequest {
    /// The service to install.
    pub spec: ServiceSpec,
    /// Paths used to locate the configuration the service should read.
    pub paths: crate::AppPaths,
}

/// Observed state of the service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceState {
    /// Not installed.
    NotInstalled,
    /// Installed and running.
    Running,
    /// Installed but stopped.
    Stopped,
    /// Installed and in the process of starting or stopping.
    Transitioning,
    /// The state could not be determined.
    Unknown,
}

impl ServiceState {
    /// Stable identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotInstalled => "not-installed",
            Self::Running => "running",
            Self::Stopped => "stopped",
            Self::Transitioning => "transitioning",
            Self::Unknown => "unknown",
        }
    }
}

/// Renders the systemd unit file for a spec.  Exposed for tests and for
/// `rdt service print-unit`.
pub fn render_systemd_unit(spec: &ServiceSpec, paths: &crate::AppPaths) -> String {
    let arguments = spec
        .arguments
        .iter()
        .map(|argument| shell_quote(argument))
        .collect::<Vec<_>>()
        .join(" ");
    let user = spec.run_as_user.clone().unwrap_or_else(|| {
        if spec.system_wide {
            "rdt".to_owned()
        } else {
            std::env::var("USER").unwrap_or_else(|_| "root".to_owned())
        }
    });
    let mut unit = String::new();
    unit.push_str("[Unit]\n");
    unit.push_str(&format!("Description={}\n", spec.description));
    unit.push_str("Documentation=https://github.com/mylab12345/Remote-Desktop-Tool\n");
    unit.push_str("After=network-online.target\n");
    unit.push_str("Wants=network-online.target\n\n");
    unit.push_str("[Service]\n");
    unit.push_str("Type=notify\n");
    unit.push_str(&format!(
        "ExecStart={} {}\n",
        shell_quote(&spec.executable.to_string_lossy()),
        arguments
    ));
    unit.push_str(&format!(
        "Environment=RDT_CONFIG_DIR={} RDT_DATA_DIR={} RDT_LOG_DIR={} RDT_RUNTIME_DIR={}\n",
        shell_quote(&paths.config_dir.to_string_lossy()),
        shell_quote(&paths.data_dir.to_string_lossy()),
        shell_quote(&paths.log_dir.to_string_lossy()),
        shell_quote(&paths.runtime_dir.to_string_lossy()),
    ));
    if spec.restart_on_failure {
        unit.push_str("Restart=on-failure\nRestartSec=5s\n");
    }
    unit.push_str(&format!("User={user}\n"));
    if spec.system_wide {
        // Least privilege: the agent only needs to read its own state directory
        // and open outbound connections.
        unit.push_str("NoNewPrivileges=true\n");
        unit.push_str("PrivateTmp=true\n");
        unit.push_str("ProtectSystem=strict\n");
        unit.push_str("ProtectHome=read-only\n");
        unit.push_str(&format!(
            "ReadWritePaths={} {} {}\n",
            shell_quote(&paths.data_dir.to_string_lossy()),
            shell_quote(&paths.log_dir.to_string_lossy()),
            shell_quote(&paths.runtime_dir.to_string_lossy()),
        ));
        unit.push_str("ProtectKernelTunables=true\n");
        unit.push_str("ProtectKernelModules=true\n");
        unit.push_str("ProtectControlGroups=true\n");
        unit.push_str("RestrictSUIDSGID=true\n");
        unit.push_str("RestrictNamespaces=true\n");
        unit.push_str("LockPersonality=true\n");
        unit.push_str("MemoryDenyWriteExecute=false\n");
        unit.push_str("SystemCallFilter=@system-service\n");
        unit.push_str("SystemCallFilter=~@privileged @resources\n");
    }
    unit.push_str("\n[Install]\n");
    unit.push_str("WantedBy=multi-user.target\n");
    unit
}

fn shell_quote(value: &str) -> String {
    if value.is_empty() {
        return "\"\"".to_owned();
    }
    if value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '/' | '.' | ':' | '=' | ','))
    {
        return value.to_owned();
    }
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Unit file location for a spec.
pub fn unit_path(spec: &ServiceSpec, paths: &crate::AppPaths) -> PathBuf {
    if spec.system_wide {
        PathBuf::from("/etc/systemd/system").join(format!("{}.service", spec.name))
    } else {
        paths
            .config_dir
            .join("systemd")
            .join("user")
            .join(format!("{}.service", spec.name))
    }
}

/// Installs (and optionally starts) the service.
pub fn install_service(request: &ServiceInstallRequest) -> RdtResult<()> {
    request.spec.validate()?;
    if !request.spec.executable.exists() {
        return Err(RdtError::new(
            ErrorCode::InvalidInput,
            format!(
                "executable {} does not exist",
                request.spec.executable.display()
            ),
        ));
    }
    #[cfg(windows)]
    {
        return windows::install(request);
    }
    #[cfg(not(windows))]
    {
        install_systemd(request)
    }
}

#[cfg(not(windows))]
fn install_systemd(request: &ServiceInstallRequest) -> RdtResult<()> {
    let spec = &request.spec;
    if !Path::new("/run/systemd/system").is_dir() {
        return Err(RdtError::new(
            ErrorCode::Service,
            "systemd is not the active init system; run the agent under your own supervisor instead",
        ));
    }
    if spec.system_wide && !crate::platform_impl::is_elevated() {
        return Err(RdtError::new(
            ErrorCode::Permission,
            "installing a system wide service requires root; re-run with sudo or use --user",
        ));
    }
    if spec.system_wide && spec.run_as_user.is_none() {
        ensure_service_user("rdt")?;
    }

    let unit = render_systemd_unit(spec, &request.paths);
    let target = unit_path(spec, &request.paths);
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&target, unit)?;

    systemctl(
        if spec.system_wide { &[] } else { &["--user"] },
        &["daemon-reload"],
    )?;
    systemctl(
        if spec.system_wide { &[] } else { &["--user"] },
        &["enable", &format!("{}.service", spec.name)],
    )?;
    if spec.start_now {
        systemctl(
            if spec.system_wide { &[] } else { &["--user"] },
            &["restart", &format!("{}.service", spec.name)],
        )?;
    }
    // removed: the caller logs the outcome(service = %spec.name, unit = %target.display(), "service installed");
    Ok(())
}

#[cfg(not(windows))]
fn ensure_service_user(name: &str) -> RdtResult<()> {
    if std::fs::read_to_string("/etc/passwd")
        .map(|content| {
            content
                .lines()
                .any(|line| line.starts_with(&format!("{name}:")))
        })
        .unwrap_or(false)
    {
        return Ok(());
    }
    let status = std::process::Command::new("useradd")
        .args([
            "--system",
            "--home-dir",
            "/var/lib/rdt",
            "--shell",
            "/usr/sbin/nologin",
            "--comment",
            "RDT remote access agent",
            name,
        ])
        .status()
        .map_err(|error| {
            RdtError::new(
                ErrorCode::Service,
                format!("cannot create the '{name}' service account: {error}"),
            )
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(RdtError::new(
            ErrorCode::Service,
            format!("useradd exited with {status}; create the '{name}' account manually"),
        ))
    }
}

#[cfg(not(windows))]
fn systemctl(scope: &[&str], args: &[&str]) -> RdtResult<()> {
    let output = std::process::Command::new("systemctl")
        .args(scope.iter().chain(args.iter()))
        .output()
        .map_err(|error| {
            RdtError::new(ErrorCode::Service, format!("cannot run systemctl: {error}"))
        })?;
    if output.status.success() {
        return Ok(());
    }
    Err(RdtError::new(
        ErrorCode::Service,
        format!(
            "systemctl {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ),
    ))
}

/// Removes a previously installed service.
pub fn uninstall_service(spec: &ServiceSpec, paths: &crate::AppPaths) -> RdtResult<()> {
    #[cfg(windows)]
    {
        return windows::uninstall(spec);
    }
    #[cfg(not(windows))]
    {
        let scope: &[&str] = if spec.system_wide { &[] } else { &["--user"] };
        if spec.system_wide && !crate::platform_impl::is_elevated() {
            return Err(RdtError::new(
                ErrorCode::Permission,
                "removing a system wide service requires root",
            ));
        }
        let name = format!("{}.service", spec.name);
        let _ = systemctl(scope, &["disable", "--now", &name]);
        let unit = unit_path(spec, paths);
        if unit.exists() {
            std::fs::remove_file(&unit)?;
        }
        let _ = systemctl(scope, &["daemon-reload"]);
        Ok(())
    }
}

/// Queries the current state of the service.
pub fn service_status(spec: &ServiceSpec, paths: &crate::AppPaths) -> RdtResult<ServiceState> {
    #[cfg(windows)]
    {
        return windows::status(spec);
    }
    #[cfg(not(windows))]
    {
        let unit = unit_path(spec, paths);
        if !unit.exists() {
            return Ok(ServiceState::NotInstalled);
        }
        let scope: &[&str] = if spec.system_wide { &[] } else { &["--user"] };
        let output = std::process::Command::new("systemctl")
            .args(
                scope
                    .iter()
                    .chain(["is-active", &format!("{}.service", spec.name)].iter()),
            )
            .output()
            .map_err(|error| {
                RdtError::new(ErrorCode::Service, format!("cannot run systemctl: {error}"))
            })?;
        let state = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        Ok(match state.as_str() {
            "active" => ServiceState::Running,
            "inactive" | "failed" => ServiceState::Stopped,
            "activating" | "deactivating" => ServiceState::Transitioning,
            _ => ServiceState::Unknown,
        })
    }
}

#[cfg(windows)]
mod windows {
    //! Windows SCM integration.
    #![allow(unsafe_code)] // windows-service is a safe wrapper; only the FFI entry points need it.

    use windows_service::service::{
        ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceState,
        ServiceType,
    };
    use windows_service::service_manager::{
        ServiceManager, ServiceManagerAccess, ServiceManagerDatabase,
    };

    use super::{ServiceInstallRequest, ServiceSpec, ServiceState as RdtServiceState};
    use rdt_types::{ErrorCode, RdtError, RdtResult};

    pub fn install(request: &ServiceInstallRequest) -> RdtResult<()> {
        let spec = &request.spec;
        let manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
        )
        .map_err(|error| RdtError::new(ErrorCode::Service, error.to_string()))?;

        let info = ServiceInfo {
            name: spec.name.clone().into(),
            display_name: spec.description.clone().into(),
            service_type: ServiceType::OWN_PROCESS,
            start_type: if spec.start_now {
                ServiceStartType::AutoStart
            } else {
                ServiceStartType::OnDemand
            },
            error_control: if spec.restart_on_failure {
                ServiceErrorControl::Normal
            } else {
                ServiceErrorControl::Ignore
            },
            executable_path: spec.executable.clone(),
            launch_arguments: spec
                .arguments
                .iter()
                .map(|arg| arg.clone().into())
                .collect(),
            dependencies: Vec::new(),
            account_name: None,
        };

        // A missing service is not an error: we are about to create it anyway.
        let _ = manager.delete_service(&spec.name.clone().into());
        manager
            .create_service(info, ServiceManagerDatabase::Current)
            .map_err(|error| RdtError::new(ErrorCode::Service, error.to_string()))?;
        Ok(())
    }

    pub fn uninstall(spec: &ServiceSpec) -> RdtResult<()> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(|error| RdtError::new(ErrorCode::Service, error.to_string()))?;
        manager
            .delete_service(&spec.name.clone().into())
            .map_err(|error| RdtError::new(ErrorCode::Service, error.to_string()))
    }

    pub fn status(spec: &ServiceSpec) -> RdtResult<RdtServiceState> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(|error| RdtError::new(ErrorCode::Service, error.to_string()))?;
        let service =
            match manager.open_service(&spec.name.clone().into(), ServiceAccess::QUERY_STATUS) {
                Ok(service) => service,
                Err(_) => return Ok(RdtServiceState::NotInstalled),
            };
        let status = service
            .query_status()
            .map_err(|error| RdtError::new(ErrorCode::Service, error.to_string()))?;
        Ok(match status.current_state {
            ServiceState::Running => RdtServiceState::Running,
            ServiceState::Stopped => RdtServiceState::Stopped,
            ServiceState::StartPending | ServiceState::StopPending => {
                RdtServiceState::Transitioning
            }
            _ => RdtServiceState::Unknown,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(system_wide: bool) -> ServiceSpec {
        ServiceSpec {
            executable: PathBuf::from("/usr/bin/rdt"),
            system_wide,
            ..ServiceSpec::agent("/usr/bin/rdt", system_wide)
        }
    }

    #[test]
    fn unit_file_contains_hardening_and_environment() {
        let paths = crate::AppPaths::new(
            PathBuf::from("/etc/rdt"),
            PathBuf::from("/var/lib/rdt"),
            PathBuf::from("/var/log/rdt"),
            PathBuf::from("/run/rdt"),
        );
        let unit = render_systemd_unit(&spec(true), &paths);
        assert!(unit.contains("[Unit]"));
        assert!(unit.contains("ExecStart=/usr/bin/rdt agent run"));
        assert!(unit.contains("NoNewPrivileges=true"));
        assert!(unit.contains("ProtectSystem=strict"));
        assert!(unit.contains("SystemCallFilter=@system-service"));
        assert!(unit.contains("RDT_DATA_DIR=/var/lib/rdt"));
        assert!(unit.contains("WantedBy=multi-user.target"));
    }

    #[test]
    fn user_units_skip_system_hardening() {
        let paths = crate::AppPaths::detect();
        let unit = render_systemd_unit(&spec(false), &paths);
        assert!(!unit.contains("ProtectSystem=strict"));
        assert!(unit.contains("User="));
    }

    #[test]
    fn spec_validation_rejects_relative_paths() {
        let mut broken = spec(true);
        broken.executable = PathBuf::from("rdt");
        assert_eq!(
            broken.validate().unwrap_err().code(),
            ErrorCode::InvalidInput
        );
        let mut no_name = spec(true);
        no_name.name = String::new();
        assert!(no_name.validate().is_err());
    }

    #[test]
    fn unit_path_depends_on_scope() {
        let paths = crate::AppPaths::detect();
        assert_eq!(
            unit_path(&spec(true), &paths),
            PathBuf::from("/etc/systemd/system/rdt-agent.service")
        );
        assert!(unit_path(&spec(false), &paths)
            .to_string_lossy()
            .contains("systemd/user/rdt-agent.service"));
    }

    #[test]
    fn shell_quoting_only_quotes_when_needed() {
        assert_eq!(shell_quote("/usr/bin/rdt"), "/usr/bin/rdt");
        assert_eq!(shell_quote("with space"), "\"with space\"");
        assert_eq!(shell_quote(""), "\"\"");
    }

    #[test]
    fn install_refuses_missing_executable() {
        let paths = crate::AppPaths::detect();
        let request = ServiceInstallRequest {
            spec: ServiceSpec {
                executable: PathBuf::from("/definitely/not/here"),
                ..spec(false)
            },
            paths,
        };
        let error = install_service(&request).unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidInput);
    }
}
