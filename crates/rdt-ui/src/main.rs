//! The desktop application entry point.

use std::process::ExitCode;
use std::sync::Arc;

use parking_lot::Mutex;

use rdt_config::{ConfigStore, LoadError};
use rdt_logging::audit::AuditLog;
use rdt_session::{ManagerPolicy, SessionManager};
use rdt_types::{ErrorCode, RdtError, RdtResult};

/// Wires the application together and starts the window.
fn main() -> ExitCode {
    match rdt_logging::init(&rdt_logging::Options::default()) {
        Ok(_) => {}
        Err(error) => eprintln!("cannot initialise logging: {error}"),
    }

    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("rdt: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Builds the shared state and runs the UI.
///
/// # Errors
///
/// Returns the underlying failure when the configuration cannot be loaded or the
/// window cannot be created.
pub fn run() -> RdtResult<()> {
    let config = match ConfigStore::load_default() {
        Ok(config) => Arc::new(config),
        Err(LoadError::Missing) => Arc::new(ConfigStore::in_memory()),
        Err(LoadError::Failed(error)) => return Err(error),
    };

    let paths = rdt_platform::AppPaths::detect();
    let audit = Arc::new(AuditLog::open(paths.audit_file()).unwrap_or_else(|error| {
        eprintln!("cannot open the audit log: {error}");
        AuditLog::null()
    }));

    let settings = config.settings();
    let manager = SessionManager::new(
        ManagerPolicy {
            max_concurrent: settings.session.max_concurrent_sessions,
            audit: settings.session.audit_connections,
            ..ManagerPolicy::default()
        },
        audit,
    )?;

    let state = rdt_ui::AppState {
        config: Arc::clone(&config),
        sessions: manager,
        vault: Arc::new(Mutex::new(None)),
        logs: Arc::new(Mutex::new(rdt_logging::LogBuffer::new(1024))),
        commands: Arc::new(Mutex::new(Vec::new())),
        terminals: Arc::new(Mutex::new(std::collections::HashMap::new())),
        framebuffers: Arc::new(Mutex::new(std::collections::HashMap::new())),
        status: Arc::new(Mutex::new("ready".to_owned())),
    };

    rdt_ui::run(state).map_err(|error| {
        RdtError::new(ErrorCode::Platform, format!("cannot open the window: {error}"))
    })
}
