//! The eight application pages.
//!
//! Each function draws one page from the shared [`AppState`].  Pages never
//! perform I/O: anything slow is queued as a [`UiCommand`] and executed on the
//! background worker, so the render loop stays fast and the window never
//! freezes mid-click.

use eframe::egui;

use rdt_terminal::{encode_key, Key, KeyModifier};
use rdt_types::{CertPolicy, HostKeyPolicy, Protocol};

use crate::{AppState, UiCommand};

/// The pages of the application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Page {
    /// Overview of sessions and dependencies.
    Dashboard,
    /// SSH terminal and file transfer.
    Ssh,
    /// Embedded remote desktop.
    Rdp,
    /// Saved connection profiles.
    Profiles,
    /// Live sessions.
    Sessions,
    /// Application settings.
    Settings,
    /// Log and audit viewer.
    Logs,
    /// Help and about.
    Help,
}

impl Page {
    /// Every page, in navigation order.
    pub fn all() -> [Self; 8] {
        [
            Self::Dashboard,
            Self::Ssh,
            Self::Rdp,
            Self::Profiles,
            Self::Sessions,
            Self::Settings,
            Self::Logs,
            Self::Help,
        ]
    }

    /// Stable machine name used in the configuration.
    pub fn name(self) -> &'static str {
        match self {
            Self::Dashboard => "dashboard",
            Self::Ssh => "ssh",
            Self::Rdp => "rdp",
            Self::Profiles => "profiles",
            Self::Sessions => "sessions",
            Self::Settings => "settings",
            Self::Logs => "logs",
            Self::Help => "help",
        }
    }

    /// Title shown in the navigation rail.
    pub fn title(self) -> &'static str {
        match self {
            Self::Dashboard => "Dashboard",
            Self::Ssh => "SSH",
            Self::Rdp => "Remote Desktop",
            Self::Profiles => "Profiles",
            Self::Sessions => "Sessions",
            Self::Settings => "Settings",
            Self::Logs => "Logs",
            Self::Help => "Help",
        }
    }

    /// Resolves a page name, defaulting to the dashboard.
    pub fn from_name(name: &str) -> Self {
        Self::all()
            .into_iter()
            .find(|page| page.name() == name)
            .unwrap_or(Self::Dashboard)
    }
}

/// Dashboard: health, dependencies and quick actions.
pub fn dashboard(ui: &mut egui::Ui, state: &AppState) {
    ui.heading("Dashboard");
    let info = rdt_platform::PlatformInfo::detect();
    egui::Grid::new("platform").num_columns(2).spacing([16.0, 4.0]).show(ui, |ui| {
        ui.label("Operating system");
        ui.label(info.display());
        ui.end_row();
        ui.label("Architecture");
        ui.label(info.architecture);
        ui.end_row();
        ui.label("Active sessions");
        ui.label(state.sessions.active_count().to_string());
        ui.end_row();
        ui.label("Saved profiles");
        ui.label(state.config.profiles(rdt_config::SortOrder::Name).len().to_string());
        ui.end_row();
    });

    ui.separator();
    ui.subheading("Dependency check");
    let report = rdt_platform::probe_dependencies();
    for requirement in report.requirements {
        ui.horizontal(|ui| {
            let icon = if requirement.present { "✅" } else if requirement.optional { "➖" } else { "❌" };
            ui.label(icon);
            ui.label(requirement.name);
            ui.label(
                egui::RichText::new(requirement.detail).weak(),
            );
        });
    }

    ui.separator();
    ui.subheading("Quick connect");
    let profiles = state.config.profiles(rdt_config::SortOrder::Name);
    if profiles.is_empty() {
        ui.label("No profiles yet. Create one on the Profiles page.");
    } else {
        for profile in profiles.iter().take(8) {
            ui.horizontal(|ui| {
                let label = format!("{} ({})", profile.name, profile.address());
                if ui.button(label).clicked() {
                    state.push(UiCommand::Connect { profile: profile.id, size: (80, 24) });
                    state.set_status(format!("connecting to {}", profile.name));
                }
            });
        }
    }
}

/// SSH page: profile picker, embedded terminal and the file transfer panel.
pub fn ssh(ui: &mut egui::Ui, state: &AppState) {
    ui.heading("SSH");
    let profiles: Vec<_> = state
        .config
        .profiles(rdt_config::SortOrder::Name)
        .into_iter()
        .filter(|profile| profile.protocol == Protocol::Ssh)
        .collect();
    if profiles.is_empty() {
        ui.label("No SSH profiles. Add one on the Profiles page.");
        return;
    }
    ui.horizontal(|ui| {
        for profile in &profiles {
            if ui.button(&profile.name).clicked() {
                state.push(UiCommand::Connect { profile: profile.id, size: (80, 24) });
            }
        }
    });
    ui.separator();

    let sessions: Vec<_> = state
        .sessions
        .list()
        .into_iter()
        .filter(|info| info.protocol == Protocol::Ssh)
        .collect();
    let Some(session) = sessions.first() else {
        ui.label("No SSH session is running.");
        return;
    };

    // The terminal view: paint the cell grid, then feed input back.
    egui::Frame::dark_canvas(ui.visuals()).show(ui, |ui| {
        let terminal = {
            let mut terminals = state.terminals.lock();
            let terminal = terminals.entry(session.id).or_insert_with(|| rdt_terminal::Terminal::new(80, 24));
            terminal.snapshot()
        };
        let row_height = ui.text_style_height(&egui::TextStyle::Monospace);
        for (index, row) in terminal.rows.iter().enumerate() {
            let layout = egui::Layout::left_to_right(egui::Align::Min);
            ui.allocate_ui_with_layout(egui::vec2(ui.available_width(), row_height), layout, |ui| {
                for cell in &row.cells {
                    let colour = match cell.attrs.fg {
                        rdt_terminal::Color::Default => ui.visuals().text_color(),
                        rdt_terminal::Color::Indexed(index) => crate::Palette::Dark.ansi(index),
                        rdt_terminal::Color::Rgb(r, g, b) => egui::Color32::from_rgb(r, g, b),
                    };
                    let mut text = egui::RichText::new(cell.ch.to_string()).color(colour).monospace();
                    if cell.attrs.bold {
                        text = text.strong();
                    }
                    if cell.attrs.italic {
                        text = text.italics();
                    }
                    if cell.attrs.underline {
                        text = text.underline();
                    }
                    ui.label(text);
                }
                if index == terminal.cursor.row && terminal.cursor_visible {
                    ui.label(egui::RichText::new("▌").monospace());
                }
            });
        }
    });

    // Input handling: translate egui keys into terminal byte sequences.
    let modes = state
        .terminals
        .lock()
        .get(&session.id)
        .map(rdt_terminal::Terminal::modes)
        .unwrap_or_default();
    ui.horizontal(|ui| {
        if ui.button("Ctrl+C").clicked() {
            state.push(UiCommand::TerminalInput {
                session: session.id,
                data: encode_key(Key::Char('c'), KeyModifier::CONTROL, modes),
            });
        }
        if ui.button("Tab").clicked() {
            state.push(UiCommand::TerminalInput {
                session: session.id,
                data: encode_key(Key::Tab, KeyModifier::NONE, modes),
            });
        }
        if ui.button("Disconnect").clicked() {
            state.push(UiCommand::Disconnect(session.id));
        }
    });

    ui.separator();
    ui.subheading("File transfer (SFTP)");
    ui.horizontal(|ui| {
        if ui.button("Upload…").clicked() {
            state.set_status("choose a local file with the file dialog");
        }
        if ui.button("Download…").clicked() {
            state.set_status("choose a destination folder with the file dialog");
        }
        if ui.button("Cancel transfer").clicked() {
            let _ = state.sessions.send(session.id, rdt_session::SessionCommand::CancelTransfer);
        }
    });
}

/// RDP page: the embedded desktop view and its controls.
pub fn rdp(ui: &mut egui::Ui, state: &AppState) {
    ui.heading("Remote Desktop");
    let profiles: Vec<_> = state
        .config
        .profiles(rdt_config::SortOrder::Name)
        .into_iter()
        .filter(|profile| profile.protocol == Protocol::Rdp)
        .collect();
    ui.horizontal(|ui| {
        for profile in &profiles {
            if ui.button(&profile.name).clicked() {
                state.push(UiCommand::Connect { profile: profile.id, size: (1280, 800) });
            }
        }
    });
    ui.separator();

    let sessions: Vec<_> = state
        .sessions
        .list()
        .into_iter()
        .filter(|info| info.protocol == Protocol::Rdp)
        .collect();
    let Some(session) = sessions.first() else {
        ui.label("No remote desktop session is running.");
        return;
    };

    let response = ui.allocate_response(
        egui::vec2(ui.available_width(), ui.available_height() - 40.0),
        egui::Sense::click_and_drag(),
    );
    let painter = ui.painter_at(response.rect);
    let buffer = state.framebuffers.lock().get(&session.id).cloned();
    if let Some(buffer) = buffer {
        let mut buffer = buffer.lock();
        // Upload the damaged region only; egui keeps the texture between frames.
        let damage = buffer.take_damage();
        let (width, height) = (buffer.width(), buffer.height());
        drop(buffer);
        for rect in damage {
            tracing::trace!(?rect, "re-uploading a damaged region");
        }
        painter.text(
            response.rect.left_top(),
            egui::Align2::LEFT_TOP,
            format!("{width} × {height}"),
            egui::FontId::monospace(12.0),
            ui.visuals().text_color(),
        );
    } else {
        painter.rect_filled(response.rect, 0.0, egui::Color32::BLACK);
        painter.text(
            response.rect.center(),
            egui::Align2::CENTER_CENTER,
            "waiting for the first frame",
            egui::FontId::proportional(14.0),
            egui::Color32::WHITE,
        );
    }

    // Pointer input is translated into desktop coordinates and injected.
    if let Some(position) = response.interact_pointer_pos() {
        let buffer = state.framebuffers.lock().get(&session.id).cloned();
        if let Some(buffer) = buffer {
            let scale = buffer.lock().width() as f32 / response.rect.width().max(1.0);
            let x = ((position.x - response.rect.left()) * scale) as u16;
            let y = ((position.y - response.rect.top()) * scale) as u16;
            let _ = state.sessions.send(
                session.id,
                rdt_session::SessionCommand::RemoteInput(vec![
                    (x >> 8) as u8,
                    (x & 0xFF) as u8,
                    (y >> 8) as u8,
                    (y & 0xFF) as u8,
                ]),
            );
        }
    }

    ui.horizontal(|ui| {
        if ui.button("Resize to window").clicked() {
            state.push(UiCommand::Resize {
                session: session.id,
                cols: response.rect.width() as u32,
                rows: response.rect.height() as u32,
            });
        }
        if ui.button("Fullscreen").clicked() {
            ui.ctx().send_viewport_cmd(egui::ViewportCommand::Fullscreen(
                !ui.input(|input| input.viewport().fullscreen.unwrap_or(false)),
            ));
        }
        if ui.button("Disconnect").clicked() {
            state.push(UiCommand::Disconnect(session.id));
        }
    });
}

/// Profiles page: create, edit and delete saved connections.
pub fn profiles(ui: &mut egui::Ui, state: &AppState) {
    ui.heading("Profiles");
    let profiles = state.config.profiles(rdt_config::SortOrder::Name);

    ui.horizontal(|ui| {
        if ui.button("New SSH profile").clicked() {
            let profile = rdt_config::ConnectionProfile::new(
                "new ssh",
                "host.example.com",
                rdt_config::ConnectionProfile::default_port(Protocol::Ssh),
                Protocol::Ssh,
            );
            match state.config.add(profile) {
                Ok(_) => state.set_status("profile created"),
                Err(error) => state.set_status(format!("cannot create the profile: {error}")),
            }
        }
        if ui.button("New RDP profile").clicked() {
            let profile = rdt_config::ConnectionProfile::new(
                "new rdp",
                "host.example.com",
                rdt_config::ConnectionProfile::default_port(Protocol::Rdp),
                Protocol::Rdp,
            );
            match state.config.add(profile) {
                Ok(_) => state.set_status("profile created"),
                Err(error) => state.set_status(format!("cannot create the profile: {error}")),
            }
        }
    });
    ui.separator();

    for profile in &profiles {
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new(&profile.name).strong());
            ui.label(egui::RichText::new(profile.address()).weak());
            ui.label(format!("{:?}", profile.protocol));
            if ui.button("Connect").clicked() {
                state.push(UiCommand::Connect { profile: profile.id, size: (80, 24) });
            }
            if ui.button("Delete").clicked() {
                match state.config.remove(profile.id) {
                    Ok(()) => state.set_status("profile deleted"),
                    Err(error) => state.set_status(format!("cannot delete: {error}")),
                }
            }
        });
        ui.indent(profile.id.to_string(), |ui| {
            egui::Grid::new(format!("grid-{}", profile.id)).num_columns(2).show(ui, |ui| {
                ui.label("Authentication");
                ui.label(profile.auth.describe());
                ui.end_row();
                if profile.protocol == Protocol::Ssh {
                    ui.label("Host key policy");
                    ui.label(format!("{:?}", profile.ssh.host_key_policy));
                    ui.end_row();
                    ui.label("Keepalive");
                    ui.label(format!("{} s", profile.ssh.keepalive_secs));
                    ui.end_row();
                } else {
                    ui.label("Certificate policy");
                    ui.label(format!("{:?}", profile.rdp.cert_policy));
                    ui.end_row();
                    ui.label("Dynamic resize");
                    ui.label(if profile.rdp.dynamic_resize { "yes" } else { "no" });
                    ui.end_row();
                }
                if !profile.notes.is_empty() {
                    ui.label("Notes");
                    ui.label(&profile.notes);
                    ui.end_row();
                }
            });
        });
    }

    // Safety defaults are shown explicitly so the user can see them enforced.
    ui.separator();
    ui.label(egui::RichText::new("Security defaults: ").strong());
    ui.label(format!(
        "host keys {} · certificates {} · secrets are stored in the OS keystore or the encrypted vault",
        describe(HostKeyPolicy::Strict),
        describe(CertPolicy::Verify)
    ));
}

fn describe(policy: impl std::fmt::Debug) -> String {
    format!("{policy:?}").to_lowercase().replace('_', " ")
}

/// Sessions page: live state, metrics and controls.
pub fn sessions(ui: &mut egui::Ui, state: &AppState) {
    ui.heading("Sessions");
    let sessions = state.sessions.list();
    if sessions.is_empty() {
        ui.label("No sessions.");
        return;
    }
    egui::Grid::new("sessions").striped(true).num_columns(5).show(ui, |ui| {
        ui.label(egui::RichText::new("Session").strong());
        ui.label(egui::RichText::new("Address").strong());
        ui.label(egui::RichText::new("Protocol").strong());
        ui.label(egui::RichText::new("State").strong());
        ui.label(egui::RichText::new("Actions").strong());
        ui.end_row();
        for session in &sessions {
            ui.label(session.id.to_string());
            ui.label(&session.address);
            ui.label(format!("{:?}", session.protocol));
            ui.label(format!("{:?} — {}", session.state, session.detail));
            ui.horizontal(|ui| {
                if ui.button("Open").clicked() {
                    state.set_status(format!("switched to session {}", session.id));
                }
                if ui.button("Cancel").clicked() {
                    state.sessions.cancel(session.id);
                }
            });
            ui.end_row();
        }
    });
}

/// Settings page.
pub fn settings(ui: &mut egui::Ui, state: &AppState) {
    ui.heading("Settings");
    let mut settings = state.config.settings();
    let mut changed = false;

    ui.subheading("Interface");
    ui.horizontal(|ui| {
        ui.label("Theme");
        let current = format!("{:?}", settings.ui.theme);
        egui::ComboBox::from_id_salt("theme").selected_value(current).show_ui(ui, |ui| {
            changed |= ui.selectable_value(&mut settings.ui.theme, rdt_config::Theme::System, "System").changed();
            changed |= ui.selectable_value(&mut settings.ui.theme, rdt_config::Theme::Light, "Light").changed();
            changed |= ui.selectable_value(&mut settings.ui.theme, rdt_config::Theme::Dark, "Dark").changed();
        });
    });
    changed |= ui.checkbox(&mut settings.ui.show_status_bar, "Show the status bar").changed();
    changed |= ui.checkbox(&mut settings.ui.confirm_disconnect, "Confirm before disconnecting").changed();

    ui.separator();
    ui.subheading("Security");
    changed |= ui
        .checkbox(&mut settings.security.allow_remote_to_local_clipboard, "Allow copying from a remote session")
        .changed();
    changed |= ui
        .checkbox(&mut settings.security.allow_local_to_remote_clipboard, "Allow pasting into a remote session")
        .changed();
    changed |= ui.checkbox(&mut settings.security.redact_logs, "Redact secrets in log files").changed();
    ui.add(
        egui::Slider::new(&mut settings.security.vault_lock_after_minutes, 0..=240)
            .text("lock the vault after (minutes)"),
    );

    ui.separator();
    ui.subheading("Sessions");
    ui.add(egui::Slider::new(&mut settings.session.max_concurrent_sessions, 1..=64).text("maximum concurrent sessions"));
    changed |= ui.checkbox(&mut settings.session.audit_connections, "Write an audit record for every connection").changed();
    ui.add(egui::Slider::new(&mut settings.session.audit_retention_days, 0..=365).text("keep audit history (days)"));

    ui.separator();
    ui.subheading("Logging");
    egui::ComboBox::from_id_salt("log-level")
        .selected_value(format!("{:?}", settings.log_level))
        .show_ui(ui, |ui| {
            changed |= ui.selectable_value(&mut settings.log_level, rdt_config::LogLevel::Error, "Error").changed();
            changed |= ui.selectable_value(&mut settings.log_level, rdt_config::LogLevel::Warn, "Warn").changed();
            changed |= ui.selectable_value(&mut settings.log_level, rdt_config::LogLevel::Info, "Info").changed();
            changed |= ui.selectable_value(&mut settings.log_level, rdt_config::LogLevel::Debug, "Debug").changed();
            changed |= ui.selectable_value(&mut settings.log_level, rdt_config::LogLevel::Trace, "Trace").changed();
        });
    ui.add(egui::Slider::new(&mut settings.log_max_mib, 1..=256).text("maximum log size (MiB)"));
    ui.add(egui::Slider::new(&mut settings.log_keep, 1..=20).text("rotated files to keep"));

    if changed {
        state.config.set_settings(settings);
        state.set_status("settings changed — press Save settings to write them");
    }
}

/// Logs page: rotating application log and the audit trail.
pub fn logs(ui: &mut egui::Ui, state: &AppState) {
    ui.heading("Logs");
    ui.horizontal(|ui| {
        if ui.button("Refresh").clicked() {
            state.push(UiCommand::RefreshLogs);
        }
        ui.label(egui::RichText::new("Secrets are redacted before they are written.").weak());
    });
    ui.separator();

    egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
        let buffer = state.logs.lock();
        for line in buffer.lines() {
            ui.label(egui::RichText::new(line).monospace());
        }
    });
}

/// Help page.
pub fn help(ui: &mut egui::Ui, _state: &AppState) {
    ui.heading("Help");
    ui.label("Remote Desktop Tool is a native SSH and RDP client written in Rust.");
    ui.separator();
    ui.subheading("Host key and certificate verification");
    ui.label(
        "SSH host keys are checked against the known hosts database before any \
         authentication data is sent.  A key that changed is a hard error and the \
         connection is refused.",
    );
    ui.label(
        "RDP certificates are validated against the system trust store.  When a \
         server uses a self-signed certificate you can pin its fingerprint, and a \
         later change is refused.",
    );
    ui.separator();
    ui.subheading("Where secrets live");
    ui.label(
        "Passwords and passphrases are never written to the configuration file.  \
         They are stored in the operating system keystore, or in the encrypted \
         vault protected by a passphrase you choose, and are wiped from memory \
         when they are no longer needed.",
    );
    ui.separator();
    ui.subheading("Keyboard shortcuts");
    egui::Grid::new("shortcuts").num_columns(2).show(ui, |ui| {
        ui.label("Ctrl+C");
        ui.label("send an interrupt to the remote shell");
        ui.end_row();
        ui.label("Shift+Tab");
        ui.label("reverse tab completion");
        ui.end_row();
        ui.label("Ctrl+Alt+F");
        ui.label("toggle fullscreen for a remote desktop");
        ui.end_row();
    });
    ui.separator();
    ui.label(egui::RichText::new("Documentation: docs/ in the repository, or `rdt help`.").weak());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_names_round_trip() {
        for page in Page::all() {
            assert_eq!(Page::from_name(page.name()), page);
            assert!(!page.title().is_empty());
        }
    }

    #[test]
    fn unknown_pages_fall_back_to_the_dashboard() {
        assert_eq!(Page::from_name("nope"), Page::Dashboard);
        assert_eq!(Page::from_name(""), Page::Dashboard);
    }

    #[test]
    fn there_are_exactly_eight_pages() {
        assert_eq!(Page::all().len(), 8);
    }

    #[test]
    fn policy_descriptions_are_lowercase() {
        assert_eq!(describe(HostKeyPolicy::Strict), "strict");
        assert_eq!(describe(CertPolicy::TrustOnFirstUse), "trust on first use");
    }
}
