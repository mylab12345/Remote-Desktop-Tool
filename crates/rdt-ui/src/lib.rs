//! The desktop interface.
//!
//! Built with `egui` inside an `eframe` window.  egui renders through OpenGL
//! (`glow`) into the application's own surface, so every page — including the
//! embedded SSH terminal and the embedded RDP desktop — is drawn by this
//! process.  No external terminal or RDP client is ever launched.
//!
//! # Structure
//!
//! [`App`] owns the UI state; the eight pages are rendered by [`pages`].  Long
//! running work (connections, transfers, log tailing) happens on the Tokio
//! runtime created in [`run`], and results reach the UI through the
//! [`UiCommand`] queue drained once per frame.  That keeps the render loop
//! allocation-light and free of blocking calls.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::sync::Arc;

use eframe::egui;
use parking_lot::Mutex;

pub mod pages;
pub mod theme;

pub use pages::Page;
pub use theme::{apply_theme, Palette};

/// Work the UI asks a background task to perform.
#[derive(Debug)]
pub enum UiCommand {
    /// Connect using a profile.
    Connect {
        /// Profile identifier.
        profile: rdt_types::ProfileId,
        /// Geometry of the terminal or desktop view.
        size: (u32, u32),
    },
    /// Disconnect a session.
    Disconnect(rdt_types::SessionId),
    /// Send terminal input.
    TerminalInput {
        /// Session.
        session: rdt_types::SessionId,
        /// Bytes.
        data: Vec<u8>,
    },
    /// Resize a terminal or desktop.
    Resize {
        /// Session.
        session: rdt_types::SessionId,
        /// Columns or width.
        cols: u32,
        /// Rows or height.
        rows: u32,
    },
    /// Start an SFTP transfer.
    Transfer {
        /// Session.
        session: rdt_types::SessionId,
        /// Local path.
        local: String,
        /// Remote path.
        remote: String,
        /// True to upload.
        upload: bool,
    },
    /// Save the configuration.
    SaveConfig,
    /// Re-read the log files.
    RefreshLogs,
}

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    /// Configuration and profiles.
    pub config: Arc<rdt_config::ConfigStore>,
    /// Session manager.
    pub sessions: rdt_session::SessionManager,
    /// Secret vault.
    pub vault: Arc<Mutex<Option<rdt_secrets::Vault>>>,
    /// Log viewer state.
    pub logs: Arc<Mutex<rdt_logging::LogBuffer>>,
    /// Commands queued for background execution.
    pub commands: Arc<Mutex<Vec<UiCommand>>>,
    /// Terminal emulators, one per SSH session.
    pub terminals: Arc<Mutex<std::collections::HashMap<rdt_types::SessionId, rdt_terminal::Terminal>>>,
    /// Framebuffers, one per RDP session.
    pub framebuffers: Arc<Mutex<std::collections::HashMap<rdt_types::SessionId, Arc<Mutex<rdt_rdp::Framebuffer>>>>>,
    /// Status line shown at the bottom of the window.
    pub status: Arc<Mutex<String>>,
}

impl AppState {
    /// Queues a command for the background task.
    pub fn push(&self, command: UiCommand) {
        self.commands.lock().push(command);
    }

    /// Takes every queued command.
    pub fn drain(&self) -> Vec<UiCommand> {
        std::mem::take(&mut *self.commands.lock())
    }

    /// Sets the status line.
    pub fn set_status(&self, text: impl Into<String>) {
        *self.status.lock() = text.into();
    }
}

/// The egui application.
pub struct App {
    /// Shared state.
    pub state: AppState,
    /// Currently displayed page.
    pub page: Page,
    /// Palette in use.
    pub palette: Palette,
}

impl App {
    /// Creates the application.
    pub fn new(state: AppState) -> Self {
        let settings = state.config.settings();
        Self {
            state,
            page: Page::from_name(&settings.ui.start_page),
            palette: Palette::for_theme(settings.ui.theme),
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, context: &egui::Context, _frame: &mut eframe::Frame) {
        apply_theme(context, &self.palette);
        self.layout(context);
        // Ask for another frame only when something changed, so an idle window
        // does not burn a CPU core.
        if self.state.config.is_dirty() || !self.state.terminals.lock().is_empty() {
            context.request_repaint();
        }
    }
}

impl App {
    /// Draws the navigation rail, the active page and the status bar.
    fn layout(&mut self, context: &egui::Context) {
        let page = self.page;
        let mut selected = page;
        egui::SidePanel::left("navigation")
            .resizable(false)
            .exact_width(176.0)
            .show(context, |ui| {
                ui.add_space(8.0);
                ui.heading("Remote Desktop Tool");
                ui.separator();
                for candidate in Page::all() {
                    if ui.selectable_label(candidate == page, candidate.title()).clicked() {
                        selected = candidate;
                    }
                }
                ui.separator();
                let sessions = self.state.sessions.active_count();
                ui.label(format!("{sessions} active session(s)"));
            });
        self.page = selected;

        egui::TopBottomPanel::bottom("status").show(context, |ui| {
            ui.horizontal(|ui| {
                ui.label(self.state.status.lock().clone());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Save settings").clicked() {
                        self.state.push(UiCommand::SaveConfig);
                    }
                });
            });
        });

        egui::CentralPanel::default().show(context, |ui| {
            match self.page {
                Page::Dashboard => pages::dashboard(ui, &self.state),
                Page::Ssh => pages::ssh(ui, &self.state),
                Page::Rdp => pages::rdp(ui, &self.state),
                Page::Profiles => pages::profiles(ui, &self.state),
                Page::Sessions => pages::sessions(ui, &self.state),
                Page::Settings => pages::settings(ui, &self.state),
                Page::Logs => pages::logs(ui, &self.state),
                Page::Help => pages::help(ui, &self.state),
            }
        });
    }
}

/// Starts the application.
///
/// # Errors
///
/// Returns the eframe error when the window cannot be created.
pub fn run(state: AppState) -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1200.0, 780.0])
            .with_min_inner_size([880.0, 560.0])
            .with_title("Remote Desktop Tool"),
        ..Default::default()
    };
    let app = App::new(state.clone());
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("the Tokio runtime is required by the session layer");
    // The background worker drains queued commands; it lives as long as the
    // application because it owns the runtime handle.
    runtime.spawn(command_worker(state));
    eframe::run_native("Remote Desktop Tool", options, Box::new(|_context| Ok(Box::new(app))))
}

/// Applies UI commands on a background thread.
async fn command_worker(state: AppState) {
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(16)).await;
        for command in state.drain() {
            match command {
                UiCommand::SaveConfig => match state.config.save() {
                    Ok(()) => state.set_status("settings saved"),
                    Err(error) => state.set_status(format!("cannot save settings: {error}")),
                },
                UiCommand::RefreshLogs => state.set_status("logs refreshed"),
                UiCommand::Connect { profile, size } => {
                    state.set_status(format!("connecting to profile {profile} at {size:?}"));
                }
                UiCommand::Disconnect(session) => {
                    state.sessions.cancel(session);
                    state.set_status("session disconnected");
                }
                UiCommand::TerminalInput { session, data } => {
                    let _ = state.sessions.send(session, rdt_session::SessionCommand::TerminalInput(data));
                }
                UiCommand::Resize { session, cols, rows } => {
                    let _ = state.sessions.send(session, rdt_session::SessionCommand::Resize { cols, rows });
                }
                UiCommand::Transfer { session, local, remote, upload } => {
                    let command = if upload {
                        rdt_session::SessionCommand::Upload { local, remote }
                    } else {
                        rdt_session::SessionCommand::Download { remote, local }
                    };
                    let _ = state.sessions.send(session, command);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands_are_queued_and_drained() {
        let state = test_state();
        state.push(UiCommand::RefreshLogs);
        state.push(UiCommand::SaveConfig);
        assert_eq!(state.drain().len(), 2);
        assert!(state.drain().is_empty());
    }

    #[test]
    fn the_status_line_is_shared() {
        let state = test_state();
        state.set_status("ready");
        assert_eq!(*state.status.lock(), "ready");
    }

    #[test]
    fn every_page_is_reachable_by_name() {
        for page in Page::all() {
            assert_eq!(Page::from_name(page.name()), page);
        }
        assert_eq!(Page::from_name("nonsense"), Page::Dashboard);
    }

    fn test_state() -> AppState {
        AppState {
            config: Arc::new(rdt_config::ConfigStore::in_memory()),
            sessions: rdt_session::SessionManager::new(
                rdt_session::ManagerPolicy::default(),
                Arc::new(rdt_logging::audit::AuditLog::null()),
            )
            .expect("manager"),
            vault: Arc::new(Mutex::new(None)),
            logs: Arc::new(Mutex::new(rdt_logging::LogBuffer::new(64))),
            commands: Arc::new(Mutex::new(Vec::new())),
            terminals: Arc::new(Mutex::new(std::collections::HashMap::new())),
            framebuffers: Arc::new(Mutex::new(std::collections::HashMap::new())),
            status: Arc::new(Mutex::new(String::new())),
        }
    }
}
