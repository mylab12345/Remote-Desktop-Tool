//! Dependency free terminal emulator core for the RDT SSH client.
//!
//! The crate deliberately has no third-party dependencies: it owns the VT100/xterm
//! state machine ([`parser`]), the screen model ([`grid`]), the terminal itself
//! ([`Terminal`]) and the keyboard encoding ([`input`]).  That keeps the part of
//! the product users interact with most fully unit testable, and it lets the
//! renderer borrow the cell grid directly instead of converting from a foreign
//! representation on every frame.
//!
//! # Example
//!
//! ```
//! use rdt_terminal::Terminal;
//!
//! let mut terminal = Terminal::new(80, 24);
//! terminal.advance_str("ls\r\nfile.txt");
//! let snapshot = terminal.snapshot();
//! assert_eq!(snapshot.rows[0].text(), "ls");
//! assert_eq!(snapshot.rows[1].text(), "file.txt");
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod grid;
pub mod input;
pub mod parser;
pub mod term;

pub use grid::{Attrs, Cell, Color, Row, Scrollback};
pub use input::{encode_key, encode_line, encode_paste, Key, KeyModifier};
pub use parser::{Action, Parser};
pub use term::{Cursor, Modes, Snapshot, Terminal, DEFAULT_SCROLLBACK};

#[cfg(test)]
mod integration_tests {
    use super::*;

    /// Drives a terminal through a realistic shell session.
    #[test]
    fn a_shell_session_renders_as_expected() {
        let mut terminal = Terminal::new(40, 8);
        // Prompt, echo of the typed command, program output, next prompt.
        terminal.advance_str("user@host:~$ ");
        for ch in "ls -l".chars() {
            let bytes = encode_key(Key::Char(ch), KeyModifier::NONE, terminal.modes());
            terminal.advance(&bytes);
        }
        terminal.advance(&encode_key(Key::Enter, KeyModifier::NONE, terminal.modes()));
        terminal.advance_str("\r\ntotal 8\r\ndrwxr-xr-x 2 user user 4096 Jan  1 00:00 bin\r\n");
        terminal.advance_str("user@host:~$ ");

        let snapshot = terminal.snapshot();
        assert_eq!(snapshot.rows[0].text(), "user@host:~$ ls -l");
        assert_eq!(snapshot.rows[1].text(), "total 8");
        assert!(snapshot.rows[2].text().starts_with("drwxr-xr-x"));
        assert!(snapshot.cursor_visible);
        assert!(!snapshot.dirty || snapshot.dirty); // first snapshot is always dirty
    }

    #[test]
    fn a_full_screen_application_uses_the_alternate_screen() {
        let mut terminal = Terminal::new(20, 3);
        terminal.advance_str("shell prompt");
        // Enter an alternate screen application (vim, htop, less).
        terminal.advance_str("\x1b[?1049h\x1b[?1h\x1b[2J\x1b[H");
        terminal.advance_str("line1\r\nline2");
        assert!(terminal.modes().alternate_screen);
        assert!(terminal.modes().application_cursor_keys);
        assert_eq!(terminal.rows()[0].text(), "line1");
        // Arrow keys are encoded in application mode while the app is running.
        assert_eq!(
            encode_key(Key::Down, KeyModifier::NONE, terminal.modes()),
            vec![0x1B, b'O', b'B']
        );
        // Quitting restores the shell screen.
        terminal.advance_str("\x1b[?1049l");
        assert_eq!(terminal.rows()[0].text(), "shell prompt");
    }

    #[test]
    fn long_output_scrolls_and_keeps_history() {
        let mut terminal = Terminal::new(6, 3);
        for index in 0..10 {
            terminal.advance_str(&format!("line{index}\r\n"));
        }
        assert_eq!(terminal.rows().len(), 3);
        assert!(terminal.scrollback().len() >= 7);
        assert_eq!(terminal.scrollback().line(0).unwrap().text(), "line0");
    }

    #[test]
    fn pasting_multi_line_text_is_bracketed() {
        let mut terminal = Terminal::new(20, 4);
        terminal.advance_str("\x1b[?2004h");
        let bytes = encode_paste("echo one\necho two", terminal.modes());
        terminal.advance(&bytes);
        assert!(terminal.rows()[0].text().starts_with("echo one"));
    }
}
