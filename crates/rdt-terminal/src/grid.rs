//! Screen model: colours, text attributes and the cell grid with scrollback.
//!
//! The grid is a plain vector of rows so the renderer can borrow it directly,
//! while scrolled-out lines move into a bounded scrollback buffer.

use std::fmt;

use serde::{Deserialize, Serialize};

/// A terminal colour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum Color {
    /// The theme default (index 0..15 semantics are handled by the renderer).
    #[default]
    Default,
    /// One of the 256 indexed palette entries.
    Indexed(u8),
    /// True colour.
    Rgb(u8, u8, u8),
}

impl Color {
    /// The 8 normal ANSI colours (indices 0-7).
    pub const fn normal(index: u8) -> Self {
        Self::Indexed(index)
    }

    /// The 8 bright ANSI colours (indices 8-15).
    pub const fn bright(index: u8) -> Self {
        Self::Indexed(index + 8)
    }
}

/// SGR text attributes carried by every cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct Attrs {
    /// Foreground colour.
    pub fg: Color,
    /// Background colour.
    pub bg: Color,
    /// Bold / increased intensity.
    pub bold: bool,
    /// Dim / decreased intensity.
    pub dim: bool,
    /// Italic.
    pub italic: bool,
    /// Underlined.
    pub underline: bool,
    /// Blinking.
    pub blink: bool,
    /// Foreground and background swapped.
    pub inverse: bool,
    /// Not rendered.
    pub hidden: bool,
    /// Struck through.
    pub strikethrough: bool,
}

impl Attrs {
    /// Attributes with no styling at all.
    pub const fn plain() -> Self {
        Self {
            fg: Color::Default,
            bg: Color::Default,
            bold: false,
            dim: false,
            italic: false,
            underline: false,
            blink: false,
            inverse: false,
            hidden: false,
            strikethrough: false,
        }
    }

    /// True when every attribute is at its default.
    pub fn is_plain(self) -> bool {
        self == Self::plain()
    }
}

/// A single terminal cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cell {
    /// The character shown, or a space for continuation cells of a wide glyph.
    pub ch: char,
    /// Text attributes.
    pub attrs: Attrs,
    /// Number of columns the glyph occupies (1 or 2).
    pub width: u8,
}

impl Cell {
    /// An empty cell.
    pub fn empty() -> Self {
        Self {
            ch: ' ',
            attrs: Attrs::plain(),
            width: 1,
        }
    }

    /// A cell holding one character with the given attributes.
    pub fn new(ch: char, attrs: Attrs) -> Self {
        Self {
            ch,
            attrs,
            width: if is_wide(ch) { 2 } else { 1 },
        }
    }

    /// True when the cell is blank and unstyled.
    pub fn is_empty(&self) -> bool {
        *self == Self::empty()
    }
}

impl Default for Cell {
    fn default() -> Self {
        Self::empty()
    }
}

/// A row of cells.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Row {
    /// Cells in the row, left to right.
    pub cells: Vec<Cell>,
    /// True when the remote side marked the line as wrapped.
    pub wrapped: bool,
}

impl Row {
    /// A row of `cols` empty cells.
    pub fn blank(cols: usize) -> Self {
        Self {
            cells: vec![Cell::empty(); cols],
            wrapped: false,
        }
    }

    /// The printable text of the row with trailing blanks removed.
    pub fn text(&self) -> String {
        let mut out = String::with_capacity(self.cells.len());
        for cell in &self.cells {
            out.push(cell.ch);
        }
        let trimmed = out.trim_end();
        trimmed.to_owned()
    }
}

/// Returns true for characters that occupy two columns (East Asian wide).
///
/// A small, explicit table is enough for terminal rendering and keeps the
/// crate dependency free.
pub fn is_wide(ch: char) -> bool {
    let c = ch as u32;
    matches!(c,
        0x1100..=0x115F          // Hangul Jamo init. consonants
        | 0x2E80..=0x303E        // CJK radicals, Kangxi, CJK symbols
        | 0x3041..=0x33FF        // Hiragana..CJK compatibility
        | 0x3400..=0x4DBF        // CJK ext A
        | 0x4E00..=0x9FFF        // CJK unified
        | 0xA000..=0xA4CF        // Yi
        | 0xAC00..=0xD7A3        // Hangul syllables
        | 0xF900..=0xFAFF        // CJK compatibility ideographs
        | 0xFE30..=0xFE6F        // CJK compatibility forms
        | 0xFF00..=0xFF60        // fullwidth forms
        | 0xFFE0..=0xFFE6
        | 0x1F300..=0x1F64F      // emoji
        | 0x1F900..=0x1F9FF
        | 0x20000..=0x2FFFD
        | 0x30000..=0x3FFFD
    )
}

/// The scrollback ring buffer.
#[derive(Debug)]
pub struct Scrollback {
    limit: usize,
    lines: std::collections::VecDeque<Row>,
}

impl Scrollback {
    /// Creates a scrollback holding at most `limit` lines.
    pub fn new(limit: usize) -> Self {
        Self {
            limit,
            lines: std::collections::VecDeque::new(),
        }
    }

    /// Number of lines currently held.
    pub fn len(&self) -> usize {
        self.lines.len()
    }

    /// True when no lines are held.
    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    /// Configured maximum.
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// Pushes a line, dropping the oldest when full.
    pub fn push(&mut self, row: Row) {
        if self.limit == 0 {
            return;
        }
        if self.lines.len() == self.limit {
            self.lines.pop_front();
        }
        self.lines.push_back(row);
    }

    /// Line `index` lines from the oldest retained line.
    pub fn line(&self, index: usize) -> Option<&Row> {
        self.lines.get(index)
    }

    /// Drops every retained line.
    pub fn clear(&mut self) {
        self.lines.clear();
    }

    /// Changes the maximum, trimming from the oldest end.
    pub fn set_limit(&mut self, limit: usize) {
        self.limit = limit;
        while self.lines.len() > self.limit {
            self.lines.pop_front();
        }
    }
}

impl fmt::Display for Row {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blank_rows_hold_only_empty_cells() {
        let row = Row::blank(4);
        assert_eq!(row.cells.len(), 4);
        assert!(row.cells.iter().all(Cell::is_empty));
        assert_eq!(row.text(), "");
    }

    #[test]
    fn wide_characters_report_two_columns() {
        assert!(is_wide('漢'));
        assert!(is_wide('🎉'));
        assert!(!is_wide('a'));
        assert!(!is_wide('é'));
        assert_eq!(Cell::new('漢', Attrs::plain()).width, 2);
        assert_eq!(Cell::new('a', Attrs::plain()).width, 1);
    }

    #[test]
    fn attribute_equality_is_structural() {
        let mut a = Attrs::plain();
        a.bold = true;
        assert!(!a.is_plain());
        assert_ne!(a, Attrs::plain());
        let b = Attrs {
            fg: Color::Indexed(3),
            ..Attrs::plain()
        };
        assert_ne!(b, Attrs::plain());
    }

    #[test]
    fn scrollback_drops_the_oldest_lines() {
        let mut back = Scrollback::new(3);
        for i in 0..5 {
            let mut row = Row::blank(1);
            row.cells[0].ch = char::from_digit(i, 10).unwrap();
            back.push(row);
        }
        assert_eq!(back.len(), 3);
        assert_eq!(back.line(0).unwrap().cells[0].ch, '2');
        assert_eq!(back.line(2).unwrap().cells[0].ch, '4');
    }

    #[test]
    fn shrinking_the_limit_trims_from_the_top() {
        let mut back = Scrollback::new(5);
        for _ in 0..5 {
            back.push(Row::blank(1));
        }
        back.set_limit(2);
        assert_eq!(back.len(), 2);
    }

    #[test]
    fn a_zero_limit_keeps_nothing() {
        let mut back = Scrollback::new(0);
        back.push(Row::blank(1));
        assert!(back.is_empty());
        assert_eq!(back.limit(), 0);
    }

    #[test]
    fn row_text_trims_trailing_blanks() {
        let mut row = Row::blank(6);
        for (i, ch) in "hi".chars().enumerate() {
            row.cells[i].ch = ch;
        }
        assert_eq!(row.text(), "hi");
        assert_eq!(row.to_string(), "hi");
    }
}
