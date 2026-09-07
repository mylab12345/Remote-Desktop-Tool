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
    let paths = rdt_platform::AppPaths::detect();
    match rdt_logging::init(&paths, &rdt_logging::LogConfig::default()) {
        Ok(_handles) => {}
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

/// Starts the desktop application.
///
/// # Errors
///
/// Propagates configuration and window failures.
pub fn run() -> RdtResult<()> {
    rdt_ui::run_default()
}
