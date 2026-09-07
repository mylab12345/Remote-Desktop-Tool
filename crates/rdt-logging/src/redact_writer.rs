//! A `MakeWriter` adapter that redacts secrets and mirrors lines into the UI
//! buffer before they reach the real sink.

use std::io;
use std::sync::Arc;

use parking_lot::Mutex;
use rdt_types::{Redactor, UtcStamp};
use tracing::Metadata;
use tracing_subscriber::fmt::MakeWriter;

use crate::buffer::{LogBuffer, LogEntry};

/// Wraps a writer with redaction and buffer mirroring.
#[derive(Debug)]
pub struct RedactingWriter<W> {
    inner: W,
    redactor: Redactor,
    buffer: Arc<Mutex<LogBuffer>>,
    pending: Arc<Mutex<String>>,
    level: Option<String>,
    target: Option<String>,
}

impl<W> Clone for RedactingWriter<W>
where
    W: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            redactor: self.redactor.clone(),
            buffer: Arc::clone(&self.buffer),
            pending: Arc::clone(&self.pending),
            level: self.level.clone(),
            target: self.target.clone(),
        }
    }
}

impl<W> RedactingWriter<W> {
    /// Wraps `inner`.
    pub fn new(inner: W, redactor: Redactor, buffer: Arc<Mutex<LogBuffer>>) -> Self {
        Self {
            inner,
            redactor,
            buffer,
            pending: Arc::new(Mutex::new(String::new())),
            level: None,
            target: None,
        }
    }

    fn with_meta(mut self, metadata: &Metadata<'_>) -> Self {
        self.level = Some(metadata.level().to_string());
        self.target = Some(metadata.target().to_owned());
        self
    }

    /// Redacts a single line and mirrors it into the buffer.
    ///
    /// A zero capacity buffer silently drops the entry (the file sink uses one).
    pub fn redact_line(&self, line: &str) -> String {
        let redacted = self.redactor.redact(line);
        self.buffer.lock().push(LogEntry {
            stamp: UtcStamp::now(),
            level: self.level.clone().unwrap_or_else(|| "INFO".to_owned()),
            target: self.target.clone().unwrap_or_else(|| "rdt".to_owned()),
            message: redacted.clone(),
        });
        redacted
    }
}

impl<W: io::Write> io::Write for RedactingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let text = String::from_utf8_lossy(buf);
        let mut pending = self.pending.lock();
        pending.push_str(&text);
        while let Some(position) = pending.find('\n') {
            let line: String = pending.drain(..=position).collect();
            let trimmed = line.trim_end_matches(['\n', '\r']);
            if trimmed.is_empty() {
                self.inner.write_all(b"\n")?;
                continue;
            }
            let redacted = self.redact_line(trimmed);
            self.inner.write_all(redacted.as_bytes())?;
            self.inner.write_all(b"\n")?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut pending = self.pending.lock();
        if !pending.is_empty() {
            let text = std::mem::take(&mut *pending);
            let redacted = self.redact_line(text.trim_end_matches(['\n', '\r']));
            self.inner.write_all(redacted.as_bytes())?;
        }
        self.inner.flush()
    }
}

impl<'a, W> MakeWriter<'a> for RedactingWriter<W>
where
    W: Clone + 'a,
{
    type Writer = RedactingWriter<W>;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }

    fn make_writer_for(&'a self, meta: &Metadata<'_>) -> Self::Writer {
        self.clone().with_meta(meta)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn writer() -> RedactingWriter<Vec<u8>> {
        RedactingWriter::new(
            Vec::new(),
            Redactor::new().with_secret("hunter2"),
            Arc::new(Mutex::new(LogBuffer::new(16))),
        )
    }

    #[test]
    fn complete_lines_are_redacted_and_buffered() {
        use std::io::Write;
        let mut handle = writer();
        handle.write_all(b"password=hunter2 accepted\n").expect("write");
        handle.flush().expect("flush");
        let entries = handle.buffer.lock().entries();
        assert_eq!(entries.len(), 1);
        assert!(!entries[0].message.contains("hunter2"), "{:?}", entries[0]);
        assert!(entries[0].message.contains("<redacted>"));
    }

    #[test]
    fn partial_lines_are_assembled_before_redaction() {
        use std::io::Write;
        let mut handle = writer();
        handle.write_all(b"using pass").expect("write");
        handle.write_all(b"word=hunter2 now\n").expect("write");
        let entries = handle.buffer.lock().entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].message, "password=<redacted> now");
    }
}
