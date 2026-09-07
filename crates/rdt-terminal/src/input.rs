//! Keyboard input encoding for the terminal.
//!
//! The mapping follows the conventions documented in the xterm ctlseqs
//! reference: modified function keys use the `1;modifier` parameter form, the
//! cursor keys switch between `ESC [ A` and `ESC O A` depending on the
//! application cursor key mode, and bracketed paste wraps pasted text.

use crate::term::Modes;

/// A keyboard key, in terminal terms.
///
/// The UI layer maps toolkit key events onto this model so the encoding logic
/// stays toolkit independent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Key {
    /// A printable character.
    Char(char),
    /// Enter / return.
    Enter,
    /// Backspace.
    Backspace,
    /// Tab.
    Tab,
    /// Escape.
    Escape,
    /// Arrow up.
    Up,
    /// Arrow down.
    Down,
    /// Arrow right.
    Right,
    /// Arrow left.
    Left,
    /// Home.
    Home,
    /// End.
    End,
    /// Page up.
    PageUp,
    /// Page down.
    PageDown,
    /// Insert.
    Insert,
    /// Delete.
    Delete,
    /// Function key 1-12 (and beyond, which are ignored).
    F(u8),
}

/// Modifier keys held during a press.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct KeyModifier(u8);

impl KeyModifier {
    /// No modifiers.
    pub const NONE: Self = Self(0);
    /// Shift.
    pub const SHIFT: Self = Self(1);
    /// Alt / meta.
    pub const ALT: Self = Self(2);
    /// Control.
    pub const CONTROL: Self = Self(4);

    /// Combines two modifier sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// True when the given modifier is held.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    /// The xterm modifier parameter value (1 based).
    #[must_use]
    pub const fn xterm_parameter(self) -> u8 {
        self.0 + 1
    }
}

/// Encodes a key press into the byte sequence to send to the remote side.
pub fn encode_key(key: Key, modifiers: KeyModifier, modes: Modes) -> Vec<u8> {
    let mut out = Vec::with_capacity(8);
    let modifier = modifiers.0;

    match key {
        Key::Char(ch) => {
            // Control combinations for plain letters.
            if modifiers.contains(KeyModifier::CONTROL) && ch.is_ascii_lowercase() {
                out.push(ch as u8 - b'a' + 1);
                return out;
            }
            if modifiers.contains(KeyModifier::CONTROL) && ch.is_ascii_uppercase() {
                out.push(ch as u8 - b'A' + 1);
                return out;
            }
            if modifiers.contains(KeyModifier::CONTROL) && ch == ' ' {
                out.push(0);
                return out;
            }
            let mut buffer = [0u8; 4];
            out.extend_from_slice(ch.encode_utf8(&mut buffer).as_bytes());
            out
        }
        Key::Enter => vec![b'\r'],
        Key::Backspace => {
            if modifiers.contains(KeyModifier::ALT) {
                vec![0x1B, 0x7F]
            } else {
                vec![0x7F]
            }
        }
        Key::Tab => {
            if modifiers.contains(KeyModifier::SHIFT) {
                vec![0x1B, b'[', b'Z']
            } else {
                vec![b'\t']
            }
        }
        Key::Escape => vec![0x1B],
        Key::Up | Key::Down | Key::Right | Key::Left => {
            let letter = match key {
                Key::Up => b'A',
                Key::Down => b'B',
                Key::Right => b'C',
                _ => b'D',
            };
            if modifier == 0 {
                if modes.application_cursor_keys {
                    vec![0x1B, b'O', letter]
                } else {
                    vec![0x1B, b'[', letter]
                }
            } else {
                vec![0x1B, b'[', b'1', b';', b'0' + modifier + 1, letter]
            }
        }
        Key::Home | Key::End => {
            let letter = if key == Key::Home { b'H' } else { b'F' };
            if modifier == 0 {
                vec![0x1B, b'[', letter]
            } else {
                vec![0x1B, b'[', b'1', b';', b'0' + modifier + 1, letter]
            }
        }
        Key::PageUp | Key::PageDown | Key::Insert | Key::Delete => {
            let number: &[u8] = match key {
                Key::PageUp => b"5",
                Key::PageDown => b"6",
                Key::Insert => b"2",
                _ => b"3",
            };
            if modifier == 0 {
                let mut bytes = vec![0x1B, b'['];
                bytes.extend_from_slice(number);
                bytes.push(b'~');
                bytes
            } else {
                let mut bytes = vec![0x1B, b'['];
                bytes.extend_from_slice(number);
                bytes.extend_from_slice(b";");
                bytes.push(b'0' + modifier + 1);
                bytes.push(b'~');
                bytes
            }
        }
        Key::F(n) => encode_function_key(n, modifier),
    }
}

/// The xterm function key table.
///
/// F1-F4 use the short `ESC O <letter>` form, F5-F12 use `ESC [ <number> ~`,
/// and any modified function key uses the `ESC [ 1 ; <mod> <final>` form.
fn encode_function_key(number: u8, modifier: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(8);
    match number {
        1..=4 => {
            if modifier == 0 {
                let letter = match number {
                    1 => b'P',
                    2 => b'Q',
                    3 => b'R',
                    _ => b'S',
                };
                return vec![0x1B, b'O', letter];
            }
            out.extend_from_slice(&[0x1B, b'[', b'1', b';', b'0' + modifier + 1]);
            out.push(match number {
                1 => b'P',
                2 => b'Q',
                3 => b'R',
                _ => b'S',
            });
        }
        5..=12 => {
            let number_code: &[u8] = match number {
                5 => b"15",
                6 => b"17",
                7 => b"18",
                8 => b"19",
                9 => b"20",
                10 => b"21",
                11 => b"23",
                _ => b"24",
            };
            out.extend_from_slice(&[0x1B, b'[']);
            if modifier != 0 {
                out.extend_from_slice(&[b'1', b';', b'0' + modifier + 1, b';']);
            }
            out.extend_from_slice(number_code);
            out.push(b'~');
        }
        _ => return Vec::new(),
    }
    out
}

/// Encodes pasted text, wrapping it when bracketed paste is enabled.
pub fn encode_paste(text: &str, modes: Modes) -> Vec<u8> {
    if !modes.bracketed_paste {
        return text.as_bytes().to_vec();
    }
    let mut out = Vec::with_capacity(text.len() + 12);
    out.extend_from_slice(b"\x1b[200~");
    out.extend_from_slice(text.as_bytes());
    out.extend_from_slice(b"\x1b[201~");
    out
}

/// Encodes a command followed by Enter, as typed into the prompt.
pub fn encode_line(command: &str, modes: Modes) -> Vec<u8> {
    let mut out = encode_paste(command, modes);
    out.push(b'\r');
    out
}

#[cfg(test)]
mod tests {
    use super::KeyModifier as M;

    use super::*;

    fn plain() -> Modes {
        Modes {
            cursor_visible: true,
            auto_wrap: true,
            ..Modes::default()
        }
    }

    fn app_cursor() -> Modes {
        Modes {
            application_cursor_keys: true,
            ..plain()
        }
    }

    #[test]
    fn printable_text_is_sent_verbatim() {
        assert_eq!(encode_key(Key::Char('a'), M::NONE, plain()), b"a");
        assert_eq!(encode_key(Key::Char('€'), M::NONE, plain()), "€".as_bytes());
    }

    #[test]
    fn control_combinations_map_to_control_codes() {
        assert_eq!(encode_key(Key::Char('c'), M::CONTROL, plain()), vec![0x03]);
        assert_eq!(encode_key(Key::Char('d'), M::CONTROL, plain()), vec![0x04]);
        assert_eq!(encode_key(Key::Char('z'), M::CONTROL, plain()), vec![0x1A]);
        assert_eq!(encode_key(Key::Char(' '), M::CONTROL, plain()), vec![0x00]);
        assert_eq!(encode_key(Key::Char('C'), M::CONTROL, plain()), vec![0x03]);
    }

    #[test]
    fn enter_and_backspace_match_the_terminal_convention() {
        assert_eq!(encode_key(Key::Enter, M::NONE, plain()), vec![b'\r']);
        assert_eq!(encode_key(Key::Backspace, M::NONE, plain()), vec![0x7F]);
        assert_eq!(
            encode_key(Key::Backspace, M::ALT, plain()),
            vec![0x1B, 0x7F]
        );
    }

    #[test]
    fn shift_tab_sends_the_reverse_sequence() {
        assert_eq!(encode_key(Key::Tab, M::NONE, plain()), vec![b'\t']);
        assert_eq!(
            encode_key(Key::Tab, M::SHIFT, plain()),
            vec![0x1B, b'[', b'Z']
        );
    }

    #[test]
    fn cursor_keys_respect_application_mode() {
        assert_eq!(
            encode_key(Key::Up, M::NONE, plain()),
            vec![0x1B, b'[', b'A']
        );
        assert_eq!(
            encode_key(Key::Up, M::NONE, app_cursor()),
            vec![0x1B, b'O', b'A']
        );
        assert_eq!(
            encode_key(Key::Left, M::NONE, app_cursor()),
            vec![0x1B, b'O', b'D']
        );
    }

    #[test]
    fn modified_cursor_keys_use_the_parameter_form() {
        assert_eq!(
            encode_key(Key::Right, M::SHIFT, plain()),
            vec![0x1B, b'[', b'1', b';', b'2', b'C']
        );
        assert_eq!(
            encode_key(Key::Down, M::CONTROL, plain()),
            vec![0x1B, b'[', b'1', b';', b'5', b'B']
        );
        assert_eq!(
            encode_key(Key::Home, M::ALT, plain()),
            vec![0x1B, b'[', b'1', b';', b'3', b'H']
        );
    }

    #[test]
    fn paging_keys_use_the_tilde_form() {
        assert_eq!(
            encode_key(Key::PageUp, M::NONE, plain()),
            vec![0x1B, b'[', b'5', b'~']
        );
        assert_eq!(
            encode_key(Key::Delete, M::NONE, plain()),
            vec![0x1B, b'[', b'3', b'~']
        );
        assert_eq!(
            encode_key(Key::PageDown, M::CONTROL, plain()),
            vec![0x1B, b'[', b'6', b';', b'5', b'~']
        );
    }

    #[test]
    fn function_keys_follow_the_xterm_table() {
        assert_eq!(
            encode_key(Key::F(1), M::NONE, plain()),
            vec![0x1B, b'O', b'P']
        );
        assert_eq!(
            encode_key(Key::F(4), M::NONE, plain()),
            vec![0x1B, b'O', b'S']
        );
        assert_eq!(
            encode_key(Key::F(5), M::NONE, plain()),
            vec![0x1B, b'[', b'1', b'5', b'~']
        );
        assert_eq!(
            encode_key(Key::F(12), M::NONE, plain()),
            vec![0x1B, b'[', b'2', b'4', b'~']
        );
        assert!(encode_key(Key::F(13), M::NONE, plain()).is_empty());
    }

    #[test]
    fn paste_is_wrapped_only_in_bracketed_mode() {
        let mut modes = plain();
        assert_eq!(encode_paste("ls", modes), b"ls");
        modes.bracketed_paste = true;
        assert_eq!(encode_paste("ls", modes), b"\x1b[200~ls\x1b[201~");
        assert_eq!(encode_line("ls", modes), b"\x1b[200~ls\x1b[201~\r");
        assert_eq!(encode_line("ls", plain()), b"ls\r");
    }
}
