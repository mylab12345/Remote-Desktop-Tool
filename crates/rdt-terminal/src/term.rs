//! The terminal state machine: applies parsed actions to the screen model.

use crate::grid::{Attrs, Cell, Color, Row, Scrollback};
use crate::parser::{Action, Parser};

/// Terminal modes that change how input and output behave.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Modes {
    /// Cursor visible (private mode 25).
    pub cursor_visible: bool,
    /// Application cursor keys (private mode 1): arrows send `ESC O A`.
    pub application_cursor_keys: bool,
    /// Application keypad (private mode 66).
    pub application_keypad: bool,
    /// Bracketed paste (private mode 2004).
    pub bracketed_paste: bool,
    /// Origin mode (private mode 6): cursor addressing is relative to the region.
    pub origin: bool,
    /// Auto-wrap (private mode 7).
    pub auto_wrap: bool,
    /// Alternate screen buffer (private modes 47/1047/1049).
    pub alternate_screen: bool,
    /// Insert/replace mode (private mode 4).
    pub insert: bool,
}

/// Cursor position and saved state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cursor {
    /// Zero based row.
    pub row: usize,
    /// Zero based column.
    pub col: usize,
    /// Attributes applied to the next printed character.
    pub attrs: Attrs,
}

impl Default for Cursor {
    fn default() -> Self {
        Self {
            row: 0,
            col: 0,
            attrs: Attrs::plain(),
        }
    }
}

/// A snapshot of the visible screen plus the information the renderer needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// Visible rows, top to bottom.
    pub rows: Vec<Row>,
    /// Cursor position (only meaningful when the cursor is visible).
    pub cursor: Cursor,
    /// Whether to draw the cursor.
    pub cursor_visible: bool,
    /// The window title requested by the remote side.
    pub title: String,
    /// Number of lines held in scrollback.
    pub scrollback_lines: usize,
    /// True when the screen changed since the previous snapshot.
    pub dirty: bool,
}

/// A VT100/xterm terminal emulator.
///
/// Feed it raw bytes from the remote shell with [`Terminal::advance`] and read
/// the resulting screen with [`Terminal::snapshot`].
#[derive(Debug)]
pub struct Terminal {
    cols: usize,
    rows: usize,
    screen: Vec<Row>,
    saved_screen: Option<Vec<Row>>,
    saved_cursor: Option<Cursor>,
    scrollback: Scrollback,
    cursor: Cursor,
    modes: Modes,
    region_top: usize,
    region_bottom: usize,
    title: String,
    dirty: bool,
    parser: Parser,
    wrap_pending: bool,
    bell_count: u64,
}

/// Default scrollback depth.
pub const DEFAULT_SCROLLBACK: usize = 10_000;

impl Terminal {
    /// Creates a terminal of the given size.
    pub fn new(cols: usize, rows: usize) -> Self {
        let cols = cols.clamp(1, 500);
        let rows = rows.clamp(1, 200);
        Self {
            cols,
            rows,
            screen: vec![Row::blank(cols); rows],
            saved_screen: None,
            saved_cursor: None,
            scrollback: Scrollback::new(DEFAULT_SCROLLBACK),
            cursor: Cursor::default(),
            modes: Modes {
                cursor_visible: true,
                auto_wrap: true,
                ..Modes::default()
            },
            region_top: 0,
            region_bottom: rows,
            title: String::new(),
            dirty: true,
            parser: Parser::new(),
            wrap_pending: false,
            bell_count: 0,
        }
    }

    /// Feeds raw bytes and updates the screen.
    pub fn advance(&mut self, data: &[u8]) {
        for action in self.parser.advance(data) {
            self.apply(action);
        }
    }

    /// Feeds a UTF-8 string.
    pub fn advance_str(&mut self, data: &str) {
        self.advance(data.as_bytes());
    }

    /// Current terminal size.
    pub fn size(&self) -> (usize, usize) {
        (self.cols, self.rows)
    }

    /// Active modes.
    pub fn modes(&self) -> Modes {
        self.modes
    }

    /// Window title requested by the remote side.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Number of BEL characters received (used for attention indicators).
    pub fn bell_count(&self) -> u64 {
        self.bell_count
    }

    /// Scrollback contents, oldest first.
    pub fn scrollback(&self) -> &Scrollback {
        &self.scrollback
    }

    /// Visible screen rows.
    pub fn rows(&self) -> &[Row] {
        &self.screen
    }

    /// Cursor state.
    pub fn cursor(&self) -> Cursor {
        self.cursor
    }

    /// Takes a snapshot, clearing the dirty flag.
    pub fn snapshot(&mut self) -> Snapshot {
        let snapshot = Snapshot {
            rows: self.screen.clone(),
            cursor: self.cursor,
            cursor_visible: self.modes.cursor_visible && !self.modes.alternate_screen,
            title: self.title.clone(),
            scrollback_lines: self.scrollback.len(),
            dirty: std::mem::take(&mut self.dirty),
        };
        snapshot
    }

    /// Resizes, reflowing nothing (like xterm) but preserving content.
    pub fn resize(&mut self, cols: usize, rows: usize) {
        let cols = cols.clamp(1, 500);
        let rows = rows.clamp(1, 200);
        if cols == self.cols && rows == self.rows {
            return;
        }
        self.cols = cols;
        for row in &mut self.screen {
            row.cells.resize(cols, Cell::empty());
        }
        if rows > self.rows {
            self.screen.resize(rows, Row::blank(cols));
        } else {
            let removed = self.rows - rows;
            let overflow: Vec<Row> = self.screen.drain(0..removed).collect();
            for row in overflow {
                self.scrollback.push(row);
            }
        }
        self.rows = rows;
        self.region_top = 0;
        self.region_bottom = rows;
        self.cursor.row = self.cursor.row.min(rows - 1);
        self.cursor.col = self.cursor.col.min(cols - 1);
        self.dirty = true;
    }

    /// Clears the screen and scrollback.
    pub fn clear_all(&mut self) {
        for row in &mut self.screen {
            for cell in &mut row.cells {
                *cell = Cell::empty();
            }
            row.wrapped = false;
        }
        self.scrollback.clear();
        self.cursor = Cursor::default();
        self.dirty = true;
    }

    /// Discards partial escape state after a reconnect.
    pub fn reset_parser(&mut self) {
        self.parser.reset();
        self.wrap_pending = false;
    }

    // -- action handling ---------------------------------------------------

    fn apply(&mut self, action: Action) {
        match action {
            Action::Print(ch) => self.print(ch),
            Action::Execute(code) => self.execute(code),
            Action::Csi {
                params,
                intermediates,
                ignore,
                action,
            } => {
                if !ignore {
                    self.csi(&params, &intermediates, action);
                }
            }
            Action::Esc {
                intermediates,
                ignore,
                action,
            } => {
                if !ignore {
                    self.esc(&intermediates, action);
                }
            }
            Action::Osc { params, .. } => self.osc(&params),
            Action::DcsStart { .. } | Action::DcsData(_) | Action::DcsEnd => {
                // Device control strings (DECRQSS and friends) are accepted and
                // ignored: nothing in RDT queries the terminal state.
            }
        }
    }

    fn print(&mut self, ch: char) {
        if self.wrap_pending {
            self.line_feed();
            self.cursor.col = 0;
            self.wrap_pending = false;
        }
        if self.modes.insert {
            // Insert mode (IRM) shifts the rest of the line right, dropping
            // whatever falls off the right margin.
            let width = if crate::grid::is_wide(ch) { 2 } else { 1 };
            let row = &mut self.screen[self.cursor.row];
            for _ in 0..width {
                let at = self.cursor.col.min(row.cells.len());
                row.cells.insert(at, Cell::empty());
                row.cells.truncate(self.cols);
            }
        }
        self.put_char(ch);
    }

    fn put_char(&mut self, ch: char) {
        let cell = Cell::new(ch, self.cursor.attrs);
        let row = self.cursor.row;
        let col = self.cursor.col;
        if col >= self.cols {
            return;
        }
        self.screen[row].cells[col] = cell;
        if cell.width == 2 && col + 1 < self.cols {
            self.screen[row].cells[col + 1] = Cell {
                ch: ' ',
                attrs: cell.attrs,
                width: 1,
            };
        }
        self.cursor.col += cell.width as usize;
        if self.cursor.col >= self.cols {
            if self.modes.auto_wrap {
                self.cursor.col = self.cols;
                self.wrap_pending = true;
            } else {
                self.cursor.col = self.cols - 1;
            }
        }
        self.dirty = true;
    }

    fn execute(&mut self, code: u8) {
        match code {
            0x07 => self.bell_count += 1,
            0x08 => self.backspace(),
            0x09 => self.tab(),
            0x0A | 0x0B | 0x0C => self.line_feed(),
            0x0D => {
                self.cursor.col = 0;
                self.wrap_pending = false;
            }
            _ => {}
        }
        self.dirty = true;
    }

    fn backspace(&mut self) {
        self.cursor.col = self.cursor.col.saturating_sub(1);
        self.wrap_pending = false;
    }

    fn tab(&mut self) {
        let next = (self.cursor.col / 8 + 1) * 8;
        self.cursor.col = next.min(self.cols - 1);
    }

    fn line_feed(&mut self) {
        self.wrap_pending = false;
        if self.cursor.row + 1 == self.region_bottom {
            self.scroll_up(1);
        } else if self.cursor.row + 1 < self.rows {
            self.cursor.row += 1;
        }
    }

    fn reverse_index(&mut self) {
        if self.cursor.row == self.region_top {
            self.scroll_down(1);
        } else {
            self.cursor.row = self.cursor.row.saturating_sub(1);
        }
    }

    fn scroll_up(&mut self, lines: usize) {
        for _ in 0..lines {
            let removed = self.screen.remove(self.region_top);
            if self.region_top == 0 && self.region_bottom == self.rows {
                self.scrollback.push(removed);
            }
            self.screen
                .insert(self.region_bottom.saturating_sub(1), Row::blank(self.cols));
        }
        self.dirty = true;
    }

    fn scroll_down(&mut self, lines: usize) {
        for _ in 0..lines {
            if self.region_bottom <= self.screen.len() {
                self.screen.remove(self.region_bottom - 1);
            }
            self.screen.insert(self.region_top, Row::blank(self.cols));
        }
        self.dirty = true;
    }

    fn csi(&mut self, params: &[u16], intermediates: &[u8], action: u8) {
        let private = intermediates.contains(&b'?');
        let param = |index: usize, default: u16| -> u16 {
            match params.get(index) {
                Some(0) | None => default,
                Some(value) => *value,
            }
        };

        if private {
            self.set_private_mode(param(0, 0), action == b'h');
            return;
        }

        match action {
            b'A' => self.move_cursor_up(param(0, 1) as usize),
            b'B' | b'e' => self.move_cursor_down(param(0, 1) as usize),
            b'C' | b'a' => self.move_cursor_right(param(0, 1) as usize),
            b'D' => self.move_cursor_left(param(0, 1) as usize),
            b'E' => {
                self.move_cursor_down(param(0, 1) as usize);
                self.cursor.col = 0;
            }
            b'F' => {
                self.move_cursor_up(param(0, 1) as usize);
                self.cursor.col = 0;
            }
            b'G' | b'`' => {
                self.cursor.col = (param(0, 1) as usize).saturating_sub(1).min(self.cols - 1)
            }
            b'H' | b'f' => {
                let row = (param(0, 1) as usize).saturating_sub(1);
                let col = (param(1, 1) as usize).saturating_sub(1);
                self.cursor.row = self.clamp_row(row);
                self.cursor.col = col.min(self.cols - 1);
                self.wrap_pending = false;
            }
            b'd' => {
                self.cursor.row = self.clamp_row((param(0, 1) as usize).saturating_sub(1));
            }
            b'J' => self.erase_display(param(0, 0)),
            b'K' => self.erase_line(param(0, 0)),
            b'L' => self.insert_lines(param(0, 1) as usize),
            b'M' => self.delete_lines(param(0, 1) as usize),
            b'P' => self.delete_chars(param(0, 1) as usize),
            b'@' => self.insert_chars(param(0, 1) as usize),
            b'X' => self.erase_chars(param(0, 1) as usize),
            b'S' => self.scroll_up(param(0, 1) as usize),
            b'T' => self.scroll_down(param(0, 1) as usize),
            b'r' => {
                let top = (param(0, 1) as usize).saturating_sub(1);
                let bottom = param(1, self.rows as u16) as usize;
                if top < bottom && bottom <= self.rows {
                    self.region_top = top;
                    self.region_bottom = bottom;
                    self.cursor.row = if self.modes.origin { top } else { 0 };
                    self.cursor.col = 0;
                }
            }
            b's' => self.saved_cursor = Some(self.cursor),
            b'u' => {
                if let Some(cursor) = self.saved_cursor {
                    self.cursor = cursor;
                }
            }
            b'm' => self.sgr(params),
            b'g' => {
                // Tab stops are fixed at every 8 columns; clearing is a no-op.
            }
            b'n' | b'c' | b't' | b'q' | b'b' => {
                // Device status, device attributes, window manipulation, cursor
                // shape and repeat: accepted, nothing to render.
            }
            b'h' => {
                if param(0, 0) == 4 {
                    self.modes.insert = true;
                }
            }
            b'l' => {
                if param(0, 0) == 4 {
                    self.modes.insert = false;
                }
            }
            _ => {}
        }
        self.dirty = true;
    }

    fn esc(&mut self, intermediates: &[u8], action: u8) {
        match action {
            b'7' => self.saved_cursor = Some(self.cursor),
            b'8' => {
                if let Some(cursor) = self.saved_cursor {
                    self.cursor = cursor;
                }
            }
            b'D' => self.line_feed(),
            b'M' => self.reverse_index(),
            b'E' => {
                self.cursor.col = 0;
                self.line_feed();
            }
            b'c' => {
                *self = Self::new(self.cols, self.rows);
            }
            b'=' => self.modes.application_keypad = true,
            b'>' => self.modes.application_keypad = false,
            _ => {
                // Charset designations (`ESC ( B`) select ASCII or a DEC
                // supplemental set; both render identically here.
                let _ = intermediates;
            }
        }
        self.dirty = true;
    }

    fn osc(&mut self, params: &[String]) {
        let Some(kind) = params.first() else {
            return;
        };
        match kind.as_str() {
            "0" | "1" | "2" => {
                if let Some(title) = params.get(1) {
                    self.title = title.clone();
                }
            }
            _ => {}
        }
    }

    fn set_private_mode(&mut self, mode: u16, enable: bool) {
        match mode {
            1 => self.modes.application_cursor_keys = enable,
            4 => self.modes.insert = enable,
            6 => {
                self.modes.origin = enable;
                self.cursor.row = if enable { self.region_top } else { 0 };
                self.cursor.col = 0;
            }
            7 => self.modes.auto_wrap = enable,
            25 => self.modes.cursor_visible = enable,
            47 | 1047 | 1049 => self.switch_screen(enable),
            1048 => {
                if enable {
                    self.saved_cursor = Some(self.cursor);
                } else if let Some(cursor) = self.saved_cursor {
                    self.cursor = cursor;
                }
            }
            2004 => self.modes.bracketed_paste = enable,
            _ => {}
        }
        self.dirty = true;
    }

    fn switch_screen(&mut self, alternate: bool) {
        if alternate == self.modes.alternate_screen {
            return;
        }
        if alternate {
            self.saved_screen = Some(std::mem::replace(
                &mut self.screen,
                vec![Row::blank(self.cols); self.rows],
            ));
            self.saved_cursor = Some(self.cursor);
            self.cursor = Cursor::default();
        } else if let Some(screen) = self.saved_screen.take() {
            self.screen = screen;
            if let Some(cursor) = self.saved_cursor {
                self.cursor = cursor;
            }
        }
        self.modes.alternate_screen = alternate;
        self.dirty = true;
    }

    fn sgr(&mut self, params: &[u16]) {
        if params.is_empty() {
            self.cursor.attrs = Attrs::plain();
            return;
        }
        let mut index = 0;
        while index < params.len() {
            let code = params[index];
            index += 1;
            match code {
                0 => self.cursor.attrs = Attrs::plain(),
                1 => self.cursor.attrs.bold = true,
                2 => self.cursor.attrs.dim = true,
                3 => self.cursor.attrs.italic = true,
                4 => self.cursor.attrs.underline = true,
                5 | 6 => self.cursor.attrs.blink = true,
                7 => self.cursor.attrs.inverse = true,
                8 => self.cursor.attrs.hidden = true,
                9 => self.cursor.attrs.strikethrough = true,
                21 => self.cursor.attrs.bold = false,
                22 => {
                    self.cursor.attrs.bold = false;
                    self.cursor.attrs.dim = false;
                }
                23 => self.cursor.attrs.italic = false,
                24 => self.cursor.attrs.underline = false,
                25 => self.cursor.attrs.blink = false,
                27 => self.cursor.attrs.inverse = false,
                28 => self.cursor.attrs.hidden = false,
                29 => self.cursor.attrs.strikethrough = false,
                30..=37 => self.cursor.attrs.fg = Color::normal((code - 30) as u8),
                39 => self.cursor.attrs.fg = Color::Default,
                40..=47 => self.cursor.attrs.bg = Color::normal((code - 40) as u8),
                49 => self.cursor.attrs.bg = Color::Default,
                90..=97 => self.cursor.attrs.fg = Color::bright((code - 90) as u8),
                100..=107 => self.cursor.attrs.bg = Color::bright((code - 100) as u8),
                38 => {
                    if let Some(color) = self.take_extended_color(params, &mut index) {
                        self.cursor.attrs.fg = color;
                    }
                }
                48 => {
                    if let Some(color) = self.take_extended_color(params, &mut index) {
                        self.cursor.attrs.bg = color;
                    }
                }
                _ => {}
            }
        }
    }

    fn take_extended_color(&self, params: &[u16], index: &mut usize) -> Option<Color> {
        let kind = *params.get(*index)?;
        *index += 1;
        match kind {
            5 => {
                let value = *params.get(*index)? as u8;
                *index += 1;
                Some(Color::Indexed(value))
            }
            2 => {
                let r = *params.get(*index)? as u8;
                let g = *params.get(*index + 1)? as u8;
                let b = *params.get(*index + 2)? as u8;
                *index += 3;
                Some(Color::Rgb(r, g, b))
            }
            _ => None,
        }
    }

    fn erase_display(&mut self, mode: u16) {
        match mode {
            0 => {
                self.erase_line_part(self.cursor.col, self.cols);
                for row in self.cursor.row + 1..self.rows {
                    self.clear_row(row);
                }
            }
            1 => {
                for row in 0..self.cursor.row {
                    self.clear_row(row);
                }
                self.erase_line_part(0, self.cursor.col + 1);
            }
            _ => {
                for row in 0..self.rows {
                    self.clear_row(row);
                }
                self.scrollback.clear();
                self.cursor = Cursor::default();
            }
        }
    }

    fn erase_line(&mut self, mode: u16) {
        match mode {
            0 => self.erase_line_part(self.cursor.col, self.cols),
            1 => self.erase_line_part(0, self.cursor.col + 1),
            _ => self.erase_line_part(0, self.cols),
        }
    }

    fn erase_line_part(&mut self, from: usize, to: usize) {
        let row = self.cursor.row;
        let to = to.min(self.cols);
        for col in from.min(self.cols)..to {
            self.screen[row].cells[col] = Cell::new(' ', self.cursor.attrs);
        }
    }

    fn clear_row(&mut self, row: usize) {
        for cell in &mut self.screen[row].cells {
            *cell = Cell::empty();
        }
        self.screen[row].wrapped = false;
    }

    fn insert_lines(&mut self, count: usize) {
        if self.cursor.row < self.region_top || self.cursor.row >= self.region_bottom {
            return;
        }
        for _ in 0..count {
            if self.region_bottom <= self.screen.len() {
                self.screen.remove(self.region_bottom - 1);
            }
            self.screen.insert(self.cursor.row, Row::blank(self.cols));
        }
        self.cursor.col = 0;
    }

    fn delete_lines(&mut self, count: usize) {
        if self.cursor.row < self.region_top || self.cursor.row >= self.region_bottom {
            return;
        }
        for _ in 0..count {
            self.screen.remove(self.cursor.row);
            self.screen
                .insert(self.region_bottom.saturating_sub(1), Row::blank(self.cols));
        }
        self.cursor.col = 0;
    }

    fn delete_chars(&mut self, count: usize) {
        let row = self.cursor.row;
        for _ in 0..count {
            if self.cursor.col < self.screen[row].cells.len() {
                self.screen[row].cells.remove(self.cursor.col);
            }
            self.screen[row].cells.push(Cell::empty());
        }
    }

    fn insert_chars(&mut self, count: usize) {
        let row = self.cursor.row;
        for _ in 0..count {
            let at = self
                .cursor
                .col
                .min(self.screen[row].cells.len().saturating_sub(1));
            self.screen[row].cells.insert(at, Cell::empty());
            self.screen[row].cells.truncate(self.cols);
        }
    }

    fn erase_chars(&mut self, count: usize) {
        let row = self.cursor.row;
        for offset in 0..count {
            let col = self.cursor.col + offset;
            if col < self.cols {
                self.screen[row].cells[col] = Cell::new(' ', self.cursor.attrs);
            }
        }
    }

    fn move_cursor_up(&mut self, count: usize) {
        self.cursor.row = self.cursor.row.saturating_sub(count).max(self.region_top);
        self.wrap_pending = false;
    }

    fn move_cursor_down(&mut self, count: usize) {
        self.cursor.row = (self.cursor.row + count).min(self.rows - 1);
        self.wrap_pending = false;
    }

    fn move_cursor_right(&mut self, count: usize) {
        self.cursor.col = (self.cursor.col + count).min(self.cols - 1);
        self.wrap_pending = false;
    }

    fn move_cursor_left(&mut self, count: usize) {
        self.cursor.col = self.cursor.col.saturating_sub(count);
        self.wrap_pending = false;
    }

    fn clamp_row(&self, row: usize) -> usize {
        if self.modes.origin {
            (row + self.region_top).min(self.rows - 1)
        } else {
            row.min(self.rows - 1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn term() -> Terminal {
        Terminal::new(10, 4)
    }

    fn text(terminal: &Terminal) -> Vec<String> {
        terminal.rows().iter().map(Row::text).collect()
    }

    #[test]
    fn text_is_placed_at_the_cursor() {
        let mut terminal = term();
        terminal.advance_str("hello");
        assert_eq!(text(&terminal)[0], "hello");
        assert_eq!(terminal.cursor().col, 5);
    }

    #[test]
    fn carriage_return_and_line_feed_move_the_cursor() {
        let mut terminal = term();
        terminal.advance_str("ab\r\ncd");
        assert_eq!(text(&terminal), vec!["ab", "cd", "", ""]);
    }

    #[test]
    fn output_scrolls_and_fills_scrollback() {
        let mut terminal = term();
        terminal.advance_str("1\r\n2\r\n3\r\n4\r\n5");
        assert_eq!(text(&terminal), vec!["2", "3", "4", "5"]);
        assert_eq!(terminal.scrollback().len(), 1);
        assert_eq!(terminal.scrollback().line(0).unwrap().text(), "1");
    }

    #[test]
    fn cursor_addressing_is_one_based() {
        let mut terminal = term();
        terminal.advance_str("\x1b[3;4HX");
        assert_eq!(text(&terminal)[2], "   X");
        assert_eq!(
            terminal.cursor(),
            Cursor {
                row: 2,
                col: 4,
                attrs: Attrs::plain()
            }
        );
    }

    #[test]
    fn erase_line_modes_work() {
        let mut terminal = term();
        terminal.advance_str("abcdefg\x1b[1;4H\x1b[K");
        assert_eq!(text(&terminal)[0], "abc");
        let mut terminal = term();
        terminal.advance_str("abcdefg\x1b[1;4H\x1b[1K");
        assert_eq!(text(&terminal)[0].trim_start(), "efg");
    }

    #[test]
    fn erase_display_clears_the_screen_and_history() {
        let mut terminal = term();
        terminal.advance_str("a\r\nb\x1b[3J");
        assert!(text(&terminal).iter().all(String::is_empty));
        assert_eq!(terminal.scrollback().len(), 0);
        assert_eq!(terminal.cursor().row, 0);
    }

    #[test]
    fn sgr_sets_and_resets_attributes() {
        let mut terminal = term();
        terminal.advance_str("\x1b[1;31mX\x1b[0mY");
        let row = &terminal.rows()[0];
        assert!(row.cells[0].attrs.bold);
        assert_eq!(row.cells[0].attrs.fg, Color::Indexed(1));
        assert!(row.cells[1].attrs.is_plain());
    }

    #[test]
    fn extended_colours_are_parsed() {
        let mut terminal = term();
        terminal.advance_str("\x1b[38;5;202mX\x1b[48;2;1;2;3mY");
        let row = &terminal.rows()[0];
        assert_eq!(row.cells[0].attrs.fg, Color::Indexed(202));
        assert_eq!(row.cells[1].attrs.bg, Color::Rgb(1, 2, 3));
    }

    #[test]
    fn titles_are_captured_from_osc_sequences() {
        let mut terminal = term();
        terminal.advance_str("\x1b]0;deploy@host: /srv\x07");
        assert_eq!(terminal.title(), "deploy@host: /srv");
    }

    #[test]
    fn alternate_screen_switches_buffers_and_restores_them() {
        let mut terminal = term();
        terminal.advance_str("normal");
        terminal.advance_str("\x1b[?1049h");
        assert!(terminal.modes().alternate_screen);
        terminal.advance_str("alt");
        assert_eq!(text(&terminal)[0], "alt");
        terminal.advance_str("\x1b[?1049l");
        assert_eq!(text(&terminal)[0], "normal");
        assert!(!terminal.modes().alternate_screen);
    }

    #[test]
    fn private_modes_toggle() {
        let mut terminal = term();
        terminal.advance_str("\x1b[?25l");
        assert!(!terminal.modes().cursor_visible);
        terminal.advance_str("\x1b[?25h");
        assert!(terminal.modes().cursor_visible);
        terminal.advance_str("\x1b[?2004h");
        assert!(terminal.modes().bracketed_paste);
        terminal.advance_str("\x1b[?1h");
        assert!(terminal.modes().application_cursor_keys);
    }

    #[test]
    fn scroll_regions_confine_scrolling() {
        let mut terminal = Terminal::new(4, 5);
        terminal.advance_str("a\r\nb\r\nc\r\nd\r\ne");
        terminal.advance_str("\x1b[2;4r\x1b[2;1H");
        terminal.advance_str("X\r\nY\r\nZ\r\nW");
        assert_eq!(text(&terminal)[0], "a");
        assert_eq!(text(&terminal)[4], "e");
        assert_eq!(terminal.scrollback().len(), 0);
    }

    #[test]
    fn resizing_preserves_content_and_clamps_the_cursor() {
        let mut terminal = Terminal::new(10, 4);
        terminal.advance_str("one\r\ntwo\r\nthree\r\nfour");
        terminal.resize(6, 2);
        assert_eq!(terminal.size(), (6, 2));
        // The two topmost lines were pushed into history by the shrink.
        assert_eq!(terminal.scrollback().len(), 2);
        assert_eq!(terminal.scrollback().line(0).unwrap().text(), "one");
        assert_eq!(text(&terminal), vec!["three", "four"]);
        assert!(terminal.cursor().row < 2);
        assert!(terminal.cursor().col < 6);
    }

    #[test]
    fn wrapping_breaks_lines_at_the_right_margin() {
        let mut terminal = Terminal::new(4, 3);
        terminal.advance_str("abcdefgh");
        assert_eq!(text(&terminal), vec!["abcd", "efgh", ""]);
    }

    #[test]
    fn tabs_advance_to_the_next_stop() {
        let mut terminal = term();
        terminal.advance_str("ab\tc");
        assert_eq!(text(&terminal)[0], "ab      c");
    }

    #[test]
    fn backspace_moves_left_without_erasing() {
        let mut terminal = term();
        terminal.advance_str("ab\x08c");
        assert_eq!(text(&terminal)[0], "ac");
    }

    #[test]
    fn bells_are_counted_not_rendered() {
        let mut terminal = term();
        terminal.advance_str("a\x07\x07");
        assert_eq!(terminal.bell_count(), 2);
        assert_eq!(text(&terminal)[0], "a");
    }

    #[test]
    fn snapshots_report_dirty_once() {
        let mut terminal = term();
        terminal.advance_str("x");
        assert!(terminal.snapshot().dirty);
        assert!(!terminal.snapshot().dirty);
        terminal.advance_str("y");
        assert!(terminal.snapshot().dirty);
    }

    #[test]
    fn insert_mode_shifts_text_right() {
        let mut terminal = term();
        terminal.advance_str("ac\x1b[1;2H\x1b[4hb");
        assert_eq!(text(&terminal)[0], "abc");
    }

    #[test]
    fn delete_and_insert_lines_stay_inside_the_region() {
        let mut terminal = Terminal::new(4, 4);
        terminal.advance_str("1\r\n2\r\n3\r\n4");
        terminal.advance_str("\x1b[2;1H\x1b[M");
        assert_eq!(text(&terminal), vec!["1", "3", "4", ""]);
    }

    #[test]
    fn clear_all_resets_everything() {
        let mut terminal = term();
        terminal.advance_str("abc\r\ndef");
        terminal.clear_all();
        assert!(text(&terminal).iter().all(String::is_empty));
        assert_eq!(terminal.cursor(), Cursor::default());
    }

    #[test]
    fn a_full_reset_restores_defaults() {
        let mut terminal = term();
        terminal.advance_str("\x1b[?25l\x1b[1;31mx");
        terminal.advance_str("\x1bc");
        assert!(terminal.modes().cursor_visible);
        assert!(text(&terminal).iter().all(String::is_empty));
    }
}
