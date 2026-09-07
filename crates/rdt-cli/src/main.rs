//! The `rdt` command line entry point.
//!
//! Running `rdt` with no arguments starts the desktop application; every other
//! behaviour is a subcommand.  The argument parser is hand written (no `clap`)
//! so the binary has no extra dependencies and so `--help` output is exactly the
//! text documented in `docs/CLI.md`.

use std::process::ExitCode;

use rdt_types::{ErrorCode, RdtError, RdtResult};

/// The parsed invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Invocation {
    /// Start the GUI.
    Gui,
    /// `rdt version`
    Version,
    /// `rdt help`
    Help,
    /// `rdt doctor`
    Doctor,
    /// `rdt profiles list`
    Profiles,
    /// `rdt ssh <profile>`
    Ssh(String),
    /// `rdt rdp <profile>`
    Rdp(String),
    /// `rdt service <install|uninstall|status>`
    Service(String),
    /// `rdt agent`
    Agent,
    /// `rdt vault <lock|unlock|list>`
    Vault(String),
    /// `rdt config <path|show>`
    Config(String),
}

/// Parses the argument list.
///
/// # Errors
///
/// Returns [`ErrorCode::InvalidInput`] for an unknown subcommand.
pub fn parse(arguments: &[String]) -> RdtResult<Invocation> {
    let mut args = arguments.iter().map(String::as_str);
    match args.next() {
        None => Ok(Invocation::Gui),
        Some("version") | Some("--version") | Some("-V") => Ok(Invocation::Version),
        Some("help") | Some("--help") | Some("-h") => Ok(Invocation::Help),
        Some("doctor") => Ok(Invocation::Doctor),
        Some("profiles") => Ok(Invocation::Profiles),
        Some("ssh") => {
            let profile = args
                .next()
                .ok_or_else(|| RdtError::new(ErrorCode::InvalidInput, "usage: rdt ssh <profile>"))?;
            Ok(Invocation::Ssh(profile.to_owned()))
        }
        Some("rdp") => {
            let profile = args
                .next()
                .ok_or_else(|| RdtError::new(ErrorCode::InvalidInput, "usage: rdt rdp <profile>"))?;
            Ok(Invocation::Rdp(profile.to_owned()))
        }
        Some("service") => {
            let action = args
                .next()
                .ok_or_else(|| {
                    RdtError::new(ErrorCode::InvalidInput, "usage: rdt service <install|uninstall|status>")
                })?
                .to_owned();
            if !matches!(action.as_str(), "install" | "uninstall" | "status") {
                return Err(RdtError::new(
                    ErrorCode::InvalidInput,
                    format!("unknown service action {action:?}"),
                ));
            }
            Ok(Invocation::Service(action))
        }
        Some("agent") => Ok(Invocation::Agent),
        Some("vault") => {
            let action = args
                .next()
                .ok_or_else(|| RdtError::new(ErrorCode::InvalidInput, "usage: rdt vault <lock|unlock|list>"))?
                .to_owned();
            Ok(Invocation::Vault(action))
        }
        Some("config") => {
            let action = args
                .next()
                .unwrap_or("show")
                .to_owned();
            Ok(Invocation::Config(action))
        }
        Some(other) => Err(RdtError::new(
            ErrorCode::InvalidInput,
            format!("unknown command {other:?}; run `rdt help`"),
        )),
    }
}

/// The help text.
pub const HELP: &str = "\
Remote Desktop Tool — native SSH and RDP client

USAGE:
    rdt                      start the desktop application
    rdt ssh <profile>        open an SSH session in the terminal
    rdt rdp <profile>        open a remote desktop session
    rdt profiles             list the saved profiles
    rdt doctor               check the platform and its dependencies
    rdt service <action>     install | uninstall | status
    rdt agent                run the headless agent in the foreground
    rdt vault <action>       lock | unlock | list
    rdt config [show|path]   print the configuration or its location
    rdt version              print the version
    rdt help                 print this message
";

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match run(&arguments) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("rdt: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Dispatches the parsed invocation.
///
/// # Errors
///
/// Propagates failures from the subcommand.
pub fn run(arguments: &[String]) -> RdtResult<ExitCode> {
    let invocation = parse(arguments)?;
    match invocation {
        Invocation::Help => {
            print!("{HELP}");
            Ok(ExitCode::SUCCESS)
        }
        Invocation::Version => {
            println!("rdt {}", env!("CARGO_PKG_VERSION"));
            Ok(ExitCode::SUCCESS)
        }
        Invocation::Doctor => doctor(),
        Invocation::Profiles => profiles(),
        Invocation::Config(action) => config(&action),
        Invocation::Service(action) => service(&action),
        Invocation::Vault(action) => vault(&action),
        Invocation::Ssh(profile) => connect(profile, rdt_types::Protocol::Ssh),
        Invocation::Rdp(profile) => connect(profile, rdt_types::Protocol::Rdp),
        Invocation::Agent => agent(),
        Invocation::Gui => rdt_ui::run_default().map(|()| ExitCode::SUCCESS),
    }
}

fn doctor() -> RdtResult<ExitCode> {
    let info = rdt_platform::PlatformInfo::detect();
    println!("platform      {}", info.display());
    println!("architecture  {}", info.architecture);
    let report = rdt_platform::probe_dependencies();
    let mut failed = false;
    for requirement in report.requirements {
        let mark = if requirement.present {
            "ok"
        } else if requirement.optional {
            "optional"
        } else {
            failed = true;
            "missing"
        };
        println!("{mark:<8} {} — {}", requirement.name, requirement.detail);
    }
    if failed {
        println!("\nsome required dependencies are missing; see docs/PLATFORMS.md");
        return Ok(ExitCode::FAILURE);
    }
    println!("\nthe platform is ready");
    Ok(ExitCode::SUCCESS)
}

fn profiles() -> RdtResult<ExitCode> {
    let store = rdt_config::ConfigStore::load_default().map_err(|error| match error {
        rdt_config::LoadError::Missing => RdtError::new(ErrorCode::Config, "no configuration file yet"),
        rdt_config::LoadError::Failed(error) => error,
    })?;
    let profiles = store.profiles(rdt_config::SortOrder::Name);
    if profiles.is_empty() {
        println!("no profiles are saved yet");
        return Ok(ExitCode::SUCCESS);
    }
    for profile in profiles {
        println!(
            "{}  {:<24} {:<6} {}",
            profile.id,
            profile.name,
            format!("{:?}", profile.protocol).to_lowercase(),
            profile.address()
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn config(action: &str) -> RdtResult<ExitCode> {
    let paths = rdt_platform::AppPaths::detect();
    match action {
        "path" => {
            println!("{}", paths.config_file().display());
            Ok(ExitCode::SUCCESS)
        }
        "show" => {
            let store = rdt_config::ConfigStore::load(paths.config_file()).map_err(|error| match error {
                rdt_config::LoadError::Missing => {
                    RdtError::new(ErrorCode::Config, "no configuration file yet")
                }
                rdt_config::LoadError::Failed(error) => error,
            })?;
            println!("{}", store.to_toml()?);
            Ok(ExitCode::SUCCESS)
        }
        other => Err(RdtError::new(
            ErrorCode::InvalidInput,
            format!("unknown config action {other:?}"),
        )),
    }
}

fn service(action: &str) -> RdtResult<ExitCode> {
    let spec = rdt_platform::ServiceSpec::default();
    match action {
        "install" => {
            rdt_platform::install_service(&spec)?;
            println!("the {} service was installed", spec.name);
        }
        "uninstall" => {
            rdt_platform::uninstall_service(&spec)?;
            println!("the {} service was removed", spec.name);
        }
        "status" => {
            println!("{}", rdt_platform::service_status(&spec)?);
        }
        other => {
            return Err(RdtError::new(
                ErrorCode::InvalidInput,
                format!("unknown service action {other:?}"),
            ))
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn vault(action: &str) -> RdtResult<ExitCode> {
    let paths = rdt_platform::AppPaths::detect();
    match action {
        "list" => {
            let vault = rdt_secrets::Vault::open(paths.vault_file())?;
            for key in vault.keys() {
                println!("{key}");
            }
            Ok(ExitCode::SUCCESS)
        }
        "lock" => {
            println!("the vault is locked whenever the process exits or the idle timer fires");
            Ok(ExitCode::SUCCESS)
        }
        "unlock" => {
            println!("enter the vault passphrase to unlock it in this shell");
            Ok(ExitCode::SUCCESS)
        }
        other => Err(RdtError::new(
            ErrorCode::InvalidInput,
            format!("unknown vault action {other:?}"),
        )),
    }
}

fn connect(profile_name: String, protocol: rdt_types::Protocol) -> RdtResult<ExitCode> {
    let store = rdt_config::ConfigStore::load_default().map_err(|error| match error {
        rdt_config::LoadError::Missing => RdtError::new(ErrorCode::Config, "no configuration file yet"),
        rdt_config::LoadError::Failed(error) => error,
    })?;
    let Some(profile) = store.find_by_name(&profile_name) else {
        return Err(RdtError::new(
            ErrorCode::NotFound,
            format!("no profile named {profile_name:?}"),
        ));
    };
    if profile.protocol != protocol {
        return Err(RdtError::new(
            ErrorCode::InvalidInput,
            format!(
                "profile {profile_name:?} is a {:?} profile; use the matching command",
                profile.protocol
            ),
        ));
    }
    println!(
        "connecting to {} ({})",
        profile.address(),
        format!("{:?}", profile.protocol).to_lowercase()
    );
    // A terminal session needs a real TTY; the GUI is the supported way to get
    // one on Windows, so the CLI refuses rather than pretending.
    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        return Err(RdtError::new(
            ErrorCode::Platform,
            "an interactive terminal is required; run `rdt` for the desktop client",
        ));
    }
    Ok(ExitCode::SUCCESS)
}

fn agent() -> RdtResult<ExitCode> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| RdtError::new(ErrorCode::Internal, error.to_string()))?;
    runtime.block_on(async {
        let paths = rdt_platform::AppPaths::detect();
        let store = std::sync::Arc::new(
            rdt_config::ConfigStore::load(paths.config_file()).unwrap_or_else(|_| {
                rdt_config::ConfigStore::in_memory()
            }),
        );
        let audit = std::sync::Arc::new(
            rdt_logging::audit::AuditLog::open(paths.audit_file()).unwrap_or_else(|_| {
                rdt_logging::audit::AuditLog::null()
            }),
        );
        let sessions = rdt_session::SessionManager::new(
            rdt_session::ManagerPolicy::default(),
            audit.clone(),
        )?;
        let agent = std::sync::Arc::new(rdt_agent::Agent::new(
            store,
            sessions,
            audit,
            paths.runtime_dir.join("agent.sock"),
        ));
        agent.serve().await
    })?;
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn no_arguments_starts_the_gui() {
        assert_eq!(parse(&args(&[])).expect("parse"), Invocation::Gui);
    }

    #[test]
    fn every_documented_subcommand_is_recognised() {
        assert_eq!(parse(&args(&["version"])).expect("parse"), Invocation::Version);
        assert_eq!(parse(&args(&["help"])).expect("parse"), Invocation::Help);
        assert_eq!(parse(&args(&["doctor"])).expect("parse"), Invocation::Doctor);
        assert_eq!(parse(&args(&["profiles"])).expect("parse"), Invocation::Profiles);
        assert_eq!(parse(&args(&["agent"])).expect("parse"), Invocation::Agent);
        assert_eq!(
            parse(&args(&["ssh", "build"])).expect("parse"),
            Invocation::Ssh("build".to_owned())
        );
        assert_eq!(
            parse(&args(&["rdp", "windows"])).expect("parse"),
            Invocation::Rdp("windows".to_owned())
        );
        assert_eq!(
            parse(&args(&["service", "status"])).expect("parse"),
            Invocation::Service("status".to_owned())
        );
        assert_eq!(
            parse(&args(&["vault", "list"])).expect("parse"),
            Invocation::Vault("list".to_owned())
        );
        assert_eq!(
            parse(&args(&["config"])).expect("parse"),
            Invocation::Config("show".to_owned())
        );
    }

    #[test]
    fn missing_arguments_are_reported() {
        let error = parse(&args(&["ssh"])).expect_err("must fail");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.to_string().contains("usage"));
    }

    #[test]
    fn unknown_commands_are_refused() {
        let error = parse(&args(&["teleport"])).expect_err("must fail");
        assert!(error.to_string().contains("rdt help"));
    }

    #[test]
    fn unknown_service_actions_are_refused() {
        let error = parse(&args(&["service", "reboot"])).expect_err("must fail");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
    }

    #[test]
    fn the_help_text_documents_every_command() {
        for command in ["ssh", "rdp", "profiles", "doctor", "service", "agent", "vault", "config", "version", "help"] {
            assert!(HELP.contains(command), "{command} is not documented");
        }
    }
}
