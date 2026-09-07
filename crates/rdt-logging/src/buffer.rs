//! In-memory ring buffer of recent log lines, backing the Logs page.

use std::collections::VecDeque;

use rdt_types::UtcStamp;
use serde::{Deserialize, Serialize};

/// One captured log line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEntry {
    /// When the line was produced.
    pub stamp: UtcStamp,
    /// Severity (`TRACE`, `DEBUG`, `INFO`, `WARN`, `ERROR`).
    pub level: String,
    /// Tracing target, usually the module path.
    pub target: String,
    /// Message text (already redacted).
    pub message: String,
}

/// Fixed capacity buffer of recent entries.
#[derive(Debug, Clone)]
pub struct LogBuffer {
    entries: VecDeque<LogEntry>,
    capacity: usize,
    dropped: u64,
}

impl LogBuffer {
    /// Creates a buffer holding at most `capacity` entries; a capacity of zero
    /// disables buffering (used by the file sink, which does not need it).
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: VecDeque::with_capacity(capacity.min(8192)),
            capacity,
            dropped: 0,
        }
    }

    /// Appends an entry, dropping the oldest one when full.
    pub fn push(&mut self, entry: LogEntry) {
        if self.capacity == 0 {
            return;
        }
        while self.entries.len() >= self.capacity {
            self.entries.pop_front();
            self.dropped += 1;
        }
        self.entries.push_back(entry);
    }

    /// Every buffered entry, oldest first.
    pub fn entries(&self) -> Vec<LogEntry> {
        self.entries.iter().cloned().collect()
    }

    /// Entries whose text contains `needle` (case insensitive) and whose level
    /// is at least `min_level`.
    pub fn filter(&self, needle: &str, min_level: Level) -> Vec<LogEntry> {
        let needle = needle.trim();
        self.entries
            .iter()
            .filter(|entry| level_rank(&entry.level) >= level_rank(min_level.as_str()))
            .filter(|entry| {
                needle.is_empty()
                    || entry.message.to_ascii_lowercase().contains(&needle.to_ascii_lowercase())
                    || entry.target.to_ascii_lowercase().contains(&needle.to_ascii_lowercase())
            })
            .cloned()
            .collect()
    }

    /// Number of buffered entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// How many entries were discarded because the buffer was full.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Removes every entry.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

/// Severity levels understood by the log viewer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    /// Everything.
    Trace,
    /// Debugging output.
    Debug,
    /// Normal operation.
    Info,
    /// Something needs attention.
    Warn,
    /// Failures.
    Error,
}

impl Level {
    /// Stable lowercase name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}

impl Default for Level {
    fn default() -> Self {
        Self::Info
    }
}

fn level_rank(level: &str) -> u8 {
    match level.to_ascii_lowercase().as_str() {
        "trace" => 0,
        "debug" => 1,
        "info" => 2,
        "warn" => 3,
        "error" => 4,
        _ => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(level: &str, message: &str) -> LogEntry {
        LogEntry {
            stamp: rdt_types::utc_now(),
            level: level.to_uppercase(),
            target: "rdt_test".to_owned(),
            message: message.to_owned(),
        }
    }

    #[test]
    fn buffer_drops_the_oldest_entries() {
        let mut buffer = LogBuffer::new(2);
        buffer.push(entry("info", "one"));
        buffer.push(entry("info", "two"));
        buffer.push(entry("info", "three"));
        let entries = buffer.entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].message, "two");
        assert_eq!(entries[1].message, "three");
        assert_eq!(buffer.dropped(), 1);
    }

    #[test]
    fn zero_capacity_buffers_nothing() {
        let mut buffer = LogBuffer::new(0);
        buffer.push(entry("info", "ignored"));
        assert!(buffer.is_empty());
    }

    #[test]
    fn filtering_matches_text_and_level() {
        let mut buffer = LogBuffer::new(10);
        buffer.push(entry("info", "connected to db01"));
        buffer.push(entry("warn", "keepalive delayed"));
        buffer.push(entry("error", "host key mismatch"));
        buffer.push(entry("debug", "password=hunter2"));

        assert_eq!(buffer.filter("", Level::Info).len(), 3);
        assert_eq!(buffer.filter("host key", Level::Trace).len(), 1);
        assert_eq!(buffer.filter("", Level::Error).len(), 1);
        assert_eq!(buffer.filter("rdt_test", Level::Trace).len(), 4);
        buffer.clear();
        assert!(buffer.is_empty());
    }

    #[test]
    fn level_names_are_stable() {
        assert_eq!(Level::Warn.as_str(), "warn");
        assert_eq!(Level::default(), Level::Info);
    }
}
