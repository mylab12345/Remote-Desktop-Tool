//! Byte oriented VT100/xterm escape sequence parser.
//!
//! The parser is a state machine over the input byte stream, modelled on the
//! state diagram published by Paul Flo Williams for `vttest` compatibility.  It
//! emits [`Action`] values and owns no screen state, which keeps the terminal
//! behaviour itself independently testable.

use std::fmt;

/// One parsed event from the input stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// A printable character.
    Print(char),
    /// A C0/C1 control code (BEL, BS, HT, LF, VT, FF, CR).
    Execute(u8),
    /// A complete CSI sequence: `CSI params ; intermediates action`.
    Csi {
        /// Numeric parameters, with defaults already resolved to `0`.
        params: Vec<u16>,
        /// Private marker bytes such as `?`, `>`, `<`, `=`.
        intermediates: Vec<u8>,
        /// True when the sequence was malformed and should be ignored.
        ignore: bool,
        /// The final byte identifying the operation.
        action: u8,
    },
    /// A complete escape sequence (two or three bytes).
    Esc {
        /// Intermediate bytes, if any.
        intermediates: Vec<u8>,
        /// True when the sequence was malformed and should be ignored.
        ignore: bool,
        /// The final byte.
        action: u8,
    },
    /// A complete operating system command: `OSC 0 ; title ST`.
    Osc {
        /// The `;` separated parameters.
        params: Vec<String>,
        /// True when terminated by BEL instead of ST.
        bell_terminated: bool,
    },
    /// The start of a device control string.
    DcsStart {
        /// Numeric parameters.
        params: Vec<u16>,
        /// Private marker bytes.
        intermediates: Vec<u8>,
        /// The final byte identifying the operation.
        action: u8,
    },
    /// Data belonging to the current device control string.
    DcsData(Vec<u8>),
    /// The end of the current device control string.
    DcsEnd,
}

/// Parser states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Ground,
    Escape,
    EscapeIntermediate,
    CsiEntry,
    CsiParam,
    CsiIntermediate,
    CsiIgnore,
    DcsEntry,
    DcsParam,
    DcsIntermediate,
    DcsPassthrough,
    DcsIgnore,
    OscString,
    SosPmApcString,
}

/// The VT parser.
///
/// Feed bytes with [`Parser::advance`]; it returns every action produced.
#[derive(Debug, Clone)]
pub struct Parser {
    state: State,
    params: Vec<u16>,
    current_param: Option<u16>,
    intermediates: Vec<u8>,
    ignore: bool,
    osc_buffer: String,
    dcs_buffer: Vec<u8>,
    utf8: [u8; 4],
    utf8_len: usize,
    utf8_expected: usize,
    pending_dcs_start: Option<(Vec<u16>, Vec<u8>, u8)>,
}

impl Default for Parser {
    fn default() -> Self {
        Self::new()
    }
}

impl Parser {
    /// Creates a parser positioned at the start of the stream.
    pub fn new() -> Self {
        Self {
            state: State::Ground,
            params: Vec::new(),
            current_param: None,
            intermediates: Vec::new(),
            ignore: false,
            osc_buffer: String::new(),
            dcs_buffer: Vec::new(),
            utf8: [0; 4],
            utf8_len: 0,
            utf8_expected: 0,
            pending_dcs_start: None,
        }
    }

    /// Feeds one byte and returns every action it produced.
    pub fn advance_byte(&mut self, byte: u8) -> Vec<Action> {
        let mut out = Vec::new();
        self.step(byte, &mut out);
        out
    }

    /// Feeds a slice and returns every action it produced.
    pub fn advance(&mut self, bytes: &[u8]) -> Vec<Action> {
        let mut out = Vec::with_capacity(bytes.len());
        for byte in bytes {
            self.step(*byte, &mut out);
        }
        out
    }

    /// Discards any partially parsed sequence (used after a reconnect).
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    // -- internals ---------------------------------------------------------

    fn step(&mut self, byte: u8, out: &mut Vec<Action>) {
        // Anywhere transitions, checked before the per-state table.
        match byte {
            0x18 | 0x1A => {
                // CAN / SUB abort the current sequence.
                self.clear();
                self.state = State::Ground;
                out.push(Action::Execute(byte));
                return;
            }
            0x1B => {
                // Inside a string sequence ESC is the first byte of the string
                // terminator (ST), so those states handle it themselves.
                if !matches!(
                    self.state,
                    State::OscString | State::DcsPassthrough | State::SosPmApcString
                ) {
                    self.clear();
                    self.state = State::Escape;
                    return;
                }
            }
            _ => {}
        }

        match self.state {
            State::Ground => self.ground(byte, out),
            State::Escape => self.escape(byte, out),
            State::EscapeIntermediate => self.escape_intermediate(byte, out),
            State::CsiEntry => self.csi_entry(byte, out),
            State::CsiParam => self.csi_param(byte, out),
            State::CsiIntermediate => self.csi_intermediate(byte, out),
            State::CsiIgnore => self.csi_ignore(byte, out),
            State::DcsEntry => self.dcs_entry(byte),
            State::DcsParam => self.dcs_param(byte),
            State::DcsIntermediate => self.dcs_intermediate(byte),
            State::DcsPassthrough => self.dcs_passthrough(byte, out),
            State::DcsIgnore => self.dcs_ignore(byte),
            State::OscString => self.osc_string(byte, out),
            State::SosPmApcString => self.sos_pm_apc(byte),
        }
    }

    fn clear(&mut self) {
        self.params.clear();
        self.current_param = None;
        self.intermediates.clear();
        self.ignore = false;
        self.osc_buffer.clear();
        self.dcs_buffer.clear();
        self.utf8_len = 0;
        self.utf8_expected = 0;
    }

    fn push_param(&mut self) {
        self.params.push(self.current_param.take().unwrap_or(0));
    }

    fn ground(&mut self, byte: u8, out: &mut Vec<Action>) {
        // A byte that interrupts a partially received UTF-8 sequence must be
        // handed to the decoder so the broken sequence is reported.
        if self.utf8_len > 0 && byte < 0x80 {
            self.utf8(byte, out);
            return;
        }
        match byte {
            0x00..=0x17 | 0x19 | 0x1C..=0x1F => out.push(Action::Execute(byte)),
            0x20..=0x7F => out.push(Action::Print(byte as char)),
            _ => self.utf8(byte, out),
        }
    }

    /// Minimal UTF-8 decoder for the ground state.
    fn utf8(&mut self, byte: u8, out: &mut Vec<Action>) {
        if self.utf8_len == 0 {
            self.utf8_expected = match byte {
                0xC0..=0xDF => 2,
                0xE0..=0xEF => 3,
                0xF0..=0xF7 => 4,
                _ => {
                    out.push(Action::Print(char::REPLACEMENT_CHARACTER));
                    return;
                }
            };
            self.utf8[0] = byte;
            self.utf8_len = 1;
            return;
        }
        if byte & 0xC0 != 0x80 {
            // Invalid continuation: emit a replacement and reprocess the byte.
            self.utf8_len = 0;
            self.utf8_expected = 0;
            out.push(Action::Print(char::REPLACEMENT_CHARACTER));
            self.ground(byte, out);
            return;
        }
        self.utf8[self.utf8_len] = byte;
        self.utf8_len += 1;
        if self.utf8_len == self.utf8_expected {
            let decoded = std::str::from_utf8(&self.utf8[..self.utf8_len])
                .ok()
                .and_then(|text| text.chars().next());
            out.push(Action::Print(
                decoded.unwrap_or(char::REPLACEMENT_CHARACTER),
            ));
            self.utf8_len = 0;
            self.utf8_expected = 0;
        }
    }

    fn escape(&mut self, byte: u8, out: &mut Vec<Action>) {
        match byte {
            b'[' => self.state = State::CsiEntry,
            b']' => {
                self.osc_buffer.clear();
                self.state = State::OscString;
            }
            b'P' => self.state = State::DcsEntry,
            b'X' | b'^' | b'_' => self.state = State::SosPmApcString,
            // `ESC \` is the string terminator (ST): nothing to dispatch.
            b'\\' => self.state = State::Ground,
            0x20..=0x2F => {
                self.intermediates.push(byte);
                self.state = State::EscapeIntermediate;
            }
            0x30..=0x7E => {
                let action = byte;
                let intermediates = std::mem::take(&mut self.intermediates);
                self.state = State::Ground;
                out.push(Action::Esc {
                    intermediates,
                    ignore: false,
                    action,
                });
            }
            _ => self.state = State::Ground,
        }
    }

    fn escape_intermediate(&mut self, byte: u8, out: &mut Vec<Action>) {
        match byte {
            0x20..=0x2F => self.intermediates.push(byte),
            0x30..=0x7E => {
                let action = byte;
                let intermediates = std::mem::take(&mut self.intermediates);
                self.state = State::Ground;
                out.push(Action::Esc {
                    intermediates,
                    ignore: false,
                    action,
                });
            }
            _ => self.state = State::Ground,
        }
    }

    fn csi_entry(&mut self, byte: u8, out: &mut Vec<Action>) {
        match byte {
            b'0'..=b'9' => {
                self.current_param = Some(u16::from(byte - b'0'));
                self.state = State::CsiParam;
            }
            b';' => {
                self.push_param();
                self.state = State::CsiParam;
            }
            b':' => {
                // Sub-parameters (used by modern SGR underline styles): collapse
                // to the first value, which is what terminals display.
                self.push_param();
                self.state = State::CsiIgnore;
            }
            0x3C..=0x3F => {
                self.intermediates.push(byte);
                self.state = State::CsiParam;
            }
            0x20..=0x2F => {
                self.intermediates.push(byte);
                self.state = State::CsiIntermediate;
            }
            0x40..=0x7E => self.csi_dispatch(byte, out),
            _ => {}
        }
    }

    fn csi_param(&mut self, byte: u8, out: &mut Vec<Action>) {
        match byte {
            b'0'..=b'9' => {
                let digit = (byte - b'0') as u16;
                let next = self
                    .current_param
                    .unwrap_or(0)
                    .saturating_mul(10)
                    .saturating_add(digit);
                self.current_param = Some(next.min(u16::MAX));
            }
            b';' => self.push_param(),
            b':' => {
                self.push_param();
                self.state = State::CsiIgnore;
            }
            0x20..=0x2F => {
                self.intermediates.push(byte);
                self.state = State::CsiIntermediate;
            }
            0x40..=0x7E => self.csi_dispatch(byte, out),
            0x3C..=0x3F => {
                // A private marker after parameters makes the sequence invalid.
                self.ignore = true;
                self.state = State::CsiIgnore;
            }
            _ => {}
        }
    }

    fn csi_intermediate(&mut self, byte: u8, out: &mut Vec<Action>) {
        match byte {
            0x20..=0x2F => self.intermediates.push(byte),
            0x30..=0x3F => {
                self.ignore = true;
                self.state = State::CsiIgnore;
            }
            0x40..=0x7E => self.csi_dispatch(byte, out),
            _ => {}
        }
    }

    fn csi_ignore(&mut self, byte: u8, out: &mut Vec<Action>) {
        match byte {
            0x40..=0x7E => {
                let params = std::mem::take(&mut self.params);
                let intermediates = std::mem::take(&mut self.intermediates);
                self.ignore = false;
                self.current_param = None;
                self.state = State::Ground;
                out.push(Action::Csi {
                    params,
                    intermediates,
                    ignore: true,
                    action: byte,
                });
            }
            0x20..=0x3F => {}
            _ => {}
        }
    }

    fn csi_dispatch(&mut self, byte: u8, out: &mut Vec<Action>) {
        self.push_param();
        let params = std::mem::take(&mut self.params);
        let intermediates = std::mem::take(&mut self.intermediates);
        let ignore = self.ignore;
        self.ignore = false;
        self.current_param = None;
        self.state = State::Ground;
        out.push(Action::Csi {
            params,
            intermediates,
            ignore,
            action: byte,
        });
    }

    fn dcs_entry(&mut self, byte: u8) {
        match byte {
            b'0'..=b'9' => {
                self.current_param = Some(u16::from(byte - b'0'));
                self.state = State::DcsParam;
            }
            b';' => {
                self.push_param();
                self.state = State::DcsParam;
            }
            0x3C..=0x3F => {
                self.intermediates.push(byte);
                self.state = State::DcsParam;
            }
            0x20..=0x2F => {
                self.intermediates.push(byte);
                self.state = State::DcsIntermediate;
            }
            0x40..=0x7E => self.dcs_dispatch_start(byte),
            _ => {}
        }
    }

    fn dcs_param(&mut self, byte: u8) {
        match byte {
            b'0'..=b'9' => {
                let digit = (byte - b'0') as u16;
                let next = self
                    .current_param
                    .unwrap_or(0)
                    .saturating_mul(10)
                    .saturating_add(digit);
                self.current_param = Some(next.min(u16::MAX));
            }
            b';' => self.push_param(),
            0x3C..=0x3F => self.state = State::DcsIgnore,
            0x20..=0x2F => {
                self.intermediates.push(byte);
                self.state = State::DcsIntermediate;
            }
            0x40..=0x7E => self.dcs_dispatch_start(byte),
            _ => {}
        }
    }

    fn dcs_intermediate(&mut self, byte: u8) {
        match byte {
            0x20..=0x2F => self.intermediates.push(byte),
            0x30..=0x3F => self.state = State::DcsIgnore,
            0x40..=0x7E => self.dcs_dispatch_start(byte),
            _ => {}
        }
    }

    fn dcs_dispatch_start(&mut self, byte: u8) {
        self.push_param();
        let params = std::mem::take(&mut self.params);
        let intermediates = std::mem::take(&mut self.intermediates);
        self.current_param = None;
        self.dcs_buffer.clear();
        self.state = State::DcsPassthrough;
        self.pending_dcs_start = Some((params, intermediates, byte));
    }

    fn dcs_passthrough(&mut self, byte: u8, out: &mut Vec<Action>) {
        if let Some((params, intermediates, action)) = self.pending_dcs_start.take() {
            out.push(Action::DcsStart {
                params,
                intermediates,
                action,
            });
        }
        match byte {
            0x00..=0x17 | 0x19 | 0x1C..=0x7E => self.dcs_buffer.push(byte),
            0x7F => {}
            0x1B => {
                // ESC starts the string terminator; the following `\` is
                // consumed by the escape state as a no-op.
                if !self.dcs_buffer.is_empty() {
                    out.push(Action::DcsData(std::mem::take(&mut self.dcs_buffer)));
                }
                out.push(Action::DcsEnd);
                self.clear();
                self.state = State::Escape;
            }
            _ => {
                if !self.dcs_buffer.is_empty() {
                    out.push(Action::DcsData(std::mem::take(&mut self.dcs_buffer)));
                }
                out.push(Action::DcsEnd);
                self.state = State::Ground;
            }
        }
    }

    fn dcs_ignore(&mut self, _byte: u8) {}

    fn osc_string(&mut self, byte: u8, out: &mut Vec<Action>) {
        match byte {
            0x07 => {
                let params = split_osc(&self.osc_buffer);
                self.osc_buffer.clear();
                self.state = State::Ground;
                out.push(Action::Osc {
                    params,
                    bell_terminated: true,
                });
            }
            0x1B => {
                // ST is ESC \ : emit the OSC now and treat ESC as a new sequence.
                let params = split_osc(&self.osc_buffer);
                self.osc_buffer.clear();
                self.state = State::Escape;
                out.push(Action::Osc {
                    params,
                    bell_terminated: false,
                });
            }
            0x20..=0x7F => self.osc_buffer.push(byte as char),
            _ => {}
        }
    }

    fn sos_pm_apc(&mut self, byte: u8) {
        if byte == 0x07 {
            self.state = State::Ground;
        }
    }
}

fn split_osc(buffer: &str) -> Vec<String> {
    buffer.split(';').map(str::to_owned).collect()
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Print(ch) => write!(f, "print {ch:?}"),
            Self::Execute(code) => write!(f, "execute 0x{code:02X}"),
            Self::Csi { action, .. } => write!(f, "csi {action:?}"),
            Self::Esc { action, .. } => write!(f, "esc {action:?}"),
            Self::Osc { params, .. } => write!(f, "osc {params:?}"),
            Self::DcsStart { action, .. } => write!(f, "dcs {action:?}"),
            Self::DcsData(data) => write!(f, "dcs-data {} bytes", data.len()),
            Self::DcsEnd => f.write_str("dcs-end"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(input: &str) -> Vec<Action> {
        Parser::new().advance(input.as_bytes())
    }

    fn csi(input: &str) -> Action {
        parse(input).into_iter().next().expect("an action")
    }

    #[test]
    fn plain_text_is_printed_one_character_at_a_time() {
        assert_eq!(parse("ab"), vec![Action::Print('a'), Action::Print('b')]);
    }

    #[test]
    fn control_codes_are_executed() {
        assert_eq!(
            parse("\r\n\t"),
            vec![
                Action::Execute(0x0D),
                Action::Execute(0x0A),
                Action::Execute(0x09)
            ]
        );
    }

    #[test]
    fn utf8_sequences_decode_to_one_character() {
        assert_eq!(parse("é"), vec![Action::Print('é')]);
        assert_eq!(parse("漢"), vec![Action::Print('漢')]);
        assert_eq!(parse("🎉"), vec![Action::Print('🎉')]);
    }

    #[test]
    fn invalid_utf8_becomes_a_replacement_character() {
        let actions = Parser::new().advance(&[0xFF]);
        assert_eq!(actions, vec![Action::Print(char::REPLACEMENT_CHARACTER)]);
        // A truncated sequence followed by ASCII recovers.
        let actions = Parser::new().advance(&[0xC3, b'a']);
        assert_eq!(
            actions,
            vec![
                Action::Print(char::REPLACEMENT_CHARACTER),
                Action::Print('a')
            ]
        );
    }

    #[test]
    fn cursor_movement_parameters_are_parsed() {
        assert_eq!(
            csi("\x1b[12;34H"),
            Action::Csi {
                params: vec![12, 34],
                intermediates: vec![],
                ignore: false,
                action: b'H',
            }
        );
    }

    #[test]
    fn missing_parameters_default_to_zero() {
        assert_eq!(
            csi("\x1b[H"),
            Action::Csi {
                params: vec![0],
                intermediates: vec![],
                ignore: false,
                action: b'H',
            }
        );
        assert_eq!(
            csi("\x1b[;5H"),
            Action::Csi {
                params: vec![0, 5],
                intermediates: vec![],
                ignore: false,
                action: b'H',
            }
        );
    }

    #[test]
    fn private_modes_carry_their_marker() {
        assert_eq!(
            csi("\x1b[?25l"),
            Action::Csi {
                params: vec![25],
                intermediates: vec![b'?'],
                ignore: false,
                action: b'l',
            }
        );
    }

    #[test]
    fn parameters_clamp_instead_of_overflowing() {
        let action = csi("\x1b[999999999H");
        match action {
            Action::Csi { params, .. } => assert_eq!(params, vec![u16::MAX]),
            other => panic!("unexpected {other}"),
        }
    }

    #[test]
    fn sub_parameters_collapse_to_the_first_value() {
        // CSI 4:3 m (curly underline) is rendered as a plain underline.
        match csi("\x1b[4:3m") {
            Action::Csi { params, .. } => assert_eq!(params, vec![4]),
            other => panic!("unexpected {other}"),
        }
    }

    #[test]
    fn a_private_marker_after_parameters_invalidates_the_sequence() {
        match csi("\x1b[1?H") {
            Action::Csi { ignore, .. } => assert!(ignore),
            other => panic!("unexpected {other}"),
        }
    }

    #[test]
    fn escape_sequences_are_dispatched_with_intermediates() {
        assert_eq!(
            csi("\x1b(B"),
            Action::Esc {
                intermediates: vec![b'('],
                ignore: false,
                action: b'B',
            }
        );
        assert_eq!(
            csi("\x1bM"),
            Action::Esc {
                intermediates: vec![],
                ignore: false,
                action: b'M',
            }
        );
    }

    #[test]
    fn osc_sequences_are_split_on_semicolons() {
        assert_eq!(
            csi("\x1b]0;user@host: ~\x07"),
            Action::Osc {
                params: vec!["0".to_owned(), "user@host: ~".to_owned()],
                bell_terminated: true,
            }
        );
        assert_eq!(
            csi("\x1b]2;title\x1b\\"),
            Action::Osc {
                params: vec!["2".to_owned(), "title".to_owned()],
                bell_terminated: false,
            }
        );
    }

    #[test]
    fn cancel_aborts_a_partial_sequence() {
        let actions = parse("\x1b[12\x18H");
        assert!(actions.contains(&Action::Execute(0x18)));
        // The trailing H must be plain text, not a CSI action.
        assert!(actions.contains(&Action::Print('H')));
        assert!(!actions
            .iter()
            .any(|action| matches!(action, Action::Csi { .. })));
    }

    #[test]
    fn device_control_strings_are_framed() {
        // DCS 1 $ r <data> ST : `$` is the intermediate, `r` the final byte.
        let actions = parse("\x1bP1$r1;1H\x1b\\");
        assert!(
            matches!(
                &actions[0],
                Action::DcsStart {
                    action: b'r',
                    intermediates,
                    params,
                } if intermediates == &vec![b'$'] && params == &vec![1u16]
            ),
            "unexpected first action: {:?}",
            actions.first()
        );
        assert!(actions
            .iter()
            .any(|action| matches!(action, Action::DcsData(_))));
        assert_eq!(actions.last(), Some(&Action::DcsEnd));
    }

    #[test]
    fn unknown_sos_and_apc_strings_are_swallowed() {
        let actions = parse("\x1b_garbage\x07done");
        assert!(actions.contains(&Action::Print('d')));
        assert!(!actions
            .iter()
            .any(|action| matches!(action, Action::Print('g'))));
    }

    #[test]
    fn reset_clears_partial_state() {
        let mut parser = Parser::new();
        parser.advance(b"\x1b[12");
        parser.reset();
        assert_eq!(parser.advance(b"H"), vec![Action::Print('H')]);
    }

    #[test]
    fn actions_render_readably() {
        assert_eq!(Action::Print('a').to_string(), "print 'a'");
        assert_eq!(Action::Execute(0x0A).to_string(), "execute 0x0A");
        assert_eq!(Action::DcsEnd.to_string(), "dcs-end");
    }
}
