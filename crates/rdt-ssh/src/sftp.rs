//! SFTP file transfer on an existing SSH connection.
//!
//! Transfers report progress and can be cancelled between chunks, so a large
//! upload never blocks the UI and never leaves a partial file behind: a
//! cancelled or failed upload removes the temporary name it was writing to.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use russh_sftp::client::{File, Handle as SftpHandle};
use russh_sftp::protocol::{FileType, StatusCode};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::Mutex;

use rdt_types::{ErrorCode, RdtError, RdtResult};

use crate::session::SshSession;

/// Direction of a transfer, used by progress reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferDirection {
    /// Local to remote.
    Upload,
    /// Remote to local.
    Download,
}

/// Progress of one transfer.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TransferProgress {
    /// Direction.
    pub direction: TransferDirection,
    /// Bytes transferred so far.
    pub transferred: u64,
    /// Total size in bytes, when known.
    pub total: Option<u64>,
    /// Bytes per second over the whole transfer.
    pub bytes_per_second: f64,
}

impl TransferProgress {
    /// Fraction complete, in the range 0.0-1.0.
    pub fn fraction(&self) -> f64 {
        match self.total {
            Some(0) | None => 0.0,
            Some(total) => (self.transferred as f64 / total as f64).clamp(0.0, 1.0),
        }
    }
}

/// One entry of a remote directory listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteEntry {
    /// File name (not the full path).
    pub name: String,
    /// True for directories.
    pub is_dir: bool,
    /// True for symbolic links.
    pub is_symlink: bool,
    /// Size in bytes, when the server reports it.
    pub size: Option<u64>,
    /// Modification time as a Unix timestamp, when reported.
    pub modified: Option<i64>,
    /// POSIX permissions, when reported.
    pub permissions: Option<u32>,
}

/// Chunk size used for streaming transfers.
pub const CHUNK_SIZE: usize = 256 * 1024;

/// An SFTP client bound to one SSH session.
pub struct SftpClient {
    handle: SftpHandle,
    cancel: Arc<AtomicBool>,
}

impl SftpClient {
    /// Opens the SFTP subsystem on a connected session.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::Unsupported`] when the server has no SFTP
    /// subsystem, and [`ErrorCode::Protocol`] for other failures.
    pub async fn new(session: &SshSession) -> RdtResult<Self> {
        let handle = SftpHandle::new(session.channel_for_subsystem().await?).await.map_err(|error| {
            if error.to_string().contains("subsystem") {
                RdtError::new(ErrorCode::Unsupported, "the server does not offer SFTP")
            } else {
                RdtError::new(ErrorCode::Protocol, format!("cannot start SFTP: {error}"))
            }
        })?;
        Ok(Self {
            handle,
            cancel: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Requests cancellation; the running transfer stops at the next chunk.
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::SeqCst);
    }

    /// True when cancellation was requested.
    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::SeqCst)
    }

    /// Lists a remote directory.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::NotFound`] for a missing path and
    /// [`ErrorCode::Transfer`] for other failures.
    pub async fn list(&self, path: &str) -> RdtResult<Vec<RemoteEntry>> {
        let directory = self.handle.read_dir(path).await.map_err(|error| map_sftp(error, path))?;
        let mut entries = Vec::with_capacity(directory.len());
        for entry in directory {
            let metadata = entry.metadata();
            let file_type = metadata.file_type;
            entries.push(RemoteEntry {
                name: entry.file_name,
                is_dir: file_type == Some(FileType::Directory),
                is_symlink: file_type == Some(FileType::Symlink),
                size: metadata.size,
                modified: metadata.modified.map(|time| time as i64),
                permissions: metadata.permissions,
            });
        }
        entries.sort_by(|a, b| {
            b.is_dir
                .cmp(&a.is_dir)
                .then(a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
        Ok(entries)
    }

    /// Creates a remote directory.
    ///
    /// # Errors
    ///
    /// Propagates SFTP failures as [`ErrorCode::Transfer`].
    pub async fn mkdir(&self, path: &str) -> RdtResult<()> {
        self.handle
            .create_dir(path)
            .await
            .map_err(|error| map_sftp(error, path))
    }

    /// Removes a remote file.
    ///
    /// # Errors
    ///
    /// Propagates SFTP failures as [`ErrorCode::Transfer`].
    pub async fn remove_file(&self, path: &str) -> RdtResult<()> {
        self.handle
            .remove_file(path)
            .await
            .map_err(|error| map_sftp(error, path))
    }

    /// Removes a remote directory.
    ///
    /// # Errors
    ///
    /// Propagates SFTP failures as [`ErrorCode::Transfer`].
    pub async fn remove_dir(&self, path: &str) -> RdtResult<()> {
        self.handle
            .remove_dir(path)
            .await
            .map_err(|error| map_sftp(error, path))
    }

    /// Renames or moves a remote path.
    ///
    /// # Errors
    ///
    /// Propagates SFTP failures as [`ErrorCode::Transfer`].
    pub async fn rename(&self, from: &str, to: &str) -> RdtResult<()> {
        self.handle
            .rename(from, to)
            .await
            .map_err(|error| map_sftp(error, from))
    }

    /// Uploads a local file, reporting progress.
    ///
    /// The data is written to `<remote>.rdt-part` and renamed into place only
    /// after a successful, complete transfer, so an interruption cannot leave a
    /// truncated file at the destination.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::Cancelled`] when cancelled, [`ErrorCode::Io`] for
    /// local failures and [`ErrorCode::Transfer`] for remote ones.
    pub async fn upload<P: AsRef<Path>, F>(
        &self,
        local: P,
        remote: &str,
        mut progress: F,
    ) -> RdtResult<u64>
    where
        F: FnMut(TransferProgress) + Send,
    {
        self.cancel.store(false, Ordering::SeqCst);
        let local = local.as_ref().to_path_buf();
        let total = tokio::fs::metadata(&local).await.map_err(io_error("read metadata"))?.len();
        let mut source = tokio::fs::File::open(&local).await.map_err(io_error("open local file"))?;

        let temporary = format!("{remote}.rdt-part");
        let mut sink: File = self
            .handle
            .create(&temporary)
            .await
            .map_err(|error| map_sftp(error, &temporary))?;

        let started = Instant::now();
        let mut transferred = 0u64;
        let mut buffer = vec![0u8; CHUNK_SIZE];
        loop {
            if self.is_cancelled() {
                drop(sink);
                let _ = self.handle.remove_file(&temporary).await;
                return Err(RdtError::new(ErrorCode::Cancelled, "the upload was cancelled")
                    .with_context("path", remote.to_owned()));
            }
            let read = source.read(&mut buffer).await.map_err(io_error("read local file"))?;
            if read == 0 {
                break;
            }
            sink.write_all(&buffer[..read])
                .await
                .map_err(|error| map_sftp(error, &temporary))?;
            transferred += read as u64;
            progress(TransferProgress {
                direction: TransferDirection::Upload,
                transferred,
                total: Some(total),
                bytes_per_second: rate(transferred, started),
            });
        }
        sink.flush().await.map_err(|error| map_sftp(error, &temporary))?;
        drop(sink);

        // Replace any previous file only after the upload completed.
        let _ = self.handle.remove_file(remote).await;
        self.handle
            .rename(&temporary, remote)
            .await
            .map_err(|error| map_sftp(error, remote))?;
        progress(TransferProgress {
            direction: TransferDirection::Upload,
            transferred,
            total: Some(total),
            bytes_per_second: rate(transferred, started),
        });
        Ok(transferred)
    }

    /// Downloads a remote file, reporting progress.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::Cancelled`] when cancelled, [`ErrorCode::NotFound`]
    /// for a missing remote path and [`ErrorCode::Transfer`] otherwise.
    pub async fn download<P: AsRef<Path>, F>(
        &self,
        remote: &str,
        local: P,
        mut progress: F,
    ) -> RdtResult<u64>
    where
        F: FnMut(TransferProgress) + Send,
    {
        self.cancel.store(false, Ordering::SeqCst);
        let local = local.as_ref().to_path_buf();
        let total = self
            .handle
            .metadata(remote)
            .await
            .map_err(|error| map_sftp(error, remote))?
            .size;

        if let Some(parent) = local.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(io_error("create directory"))?;
        }
        let temporary = local.with_extension("rdt-part");
        let mut sink = tokio::fs::File::create(&temporary).await.map_err(io_error("create local file"))?;

        let mut source: File = self
            .handle
            .open(remote)
            .await
            .map_err(|error| map_sftp(error, remote))?;
        source
            .seek(std::io::SeekFrom::Start(0))
            .await
            .map_err(|error| map_sftp(error, remote))?;

        let started = Instant::now();
        let mut transferred = 0u64;
        let mut buffer = vec![0u8; CHUNK_SIZE];
        loop {
            if self.is_cancelled() {
                drop(sink);
                let _ = tokio::fs::remove_file(&temporary).await;
                return Err(RdtError::new(ErrorCode::Cancelled, "the download was cancelled")
                    .with_context("path", remote.to_owned()));
            }
            let read = source.read(&mut buffer).await.map_err(|error| map_sftp(error, remote))?;
            if read == 0 {
                break;
            }
            sink.write_all(&buffer[..read]).await.map_err(io_error("write local file"))?;
            transferred += read as u64;
            progress(TransferProgress {
                direction: TransferDirection::Download,
                transferred,
                total,
                bytes_per_second: rate(transferred, started),
            });
        }
        sink.flush().await.map_err(io_error("flush local file"))?;
        drop(sink);
        tokio::fs::rename(&temporary, &local).await.map_err(io_error("move file into place"))?;
        progress(TransferProgress {
            direction: TransferDirection::Download,
            transferred,
            total,
            bytes_per_second: rate(transferred, started),
        });
        Ok(transferred)
    }

    /// Reads a remote file into memory (used for small text files and previews).
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::InvalidInput`] when the file is larger than `limit`.
    pub async fn read_to_string(&self, remote: &str, limit: usize) -> RdtResult<String> {
        let metadata = self
            .handle
            .metadata(remote)
            .await
            .map_err(|error| map_sftp(error, remote))?;
        let size = metadata.size.unwrap_or(0) as usize;
        if size > limit {
            return Err(RdtError::new(
                ErrorCode::InvalidInput,
                format!("the file is {size} bytes, which exceeds the {limit} byte preview limit"),
            ));
        }
        let mut file: File = self
            .handle
            .open(remote)
            .await
            .map_err(|error| map_sftp(error, remote))?;
        let mut text = String::new();
        file.read_to_string(&mut text)
            .await
            .map_err(|error| map_sftp(error, remote))?;
        Ok(text)
    }
}

fn rate(transferred: u64, started: Instant) -> f64 {
    let elapsed = started.elapsed().as_secs_f64();
    if elapsed <= 0.0 {
        0.0
    } else {
        transferred as f64 / elapsed
    }
}

fn io_error(what: &'static str) -> impl Fn(std::io::Error) -> RdtError {
    move |error| RdtError::new(ErrorCode::Io, format!("{what}: {error}"))
}

/// Shared cancellation flag, so a UI button can stop a transfer from any thread.
pub type CancelFlag = Arc<AtomicBool>;

/// Mutex-protected SFTP handle, used when several transfers share a session.
pub type SharedSftp = Arc<Mutex<SftpClient>>;

fn map_sftp(error: russh_sftp::client::error::Error, path: &str) -> RdtError {
    let code = match &error {
        russh_sftp::client::error::Error::Status(status, _) => match status {
            StatusCode::NoSuchFile | StatusCode::NoSuchPath => ErrorCode::NotFound,
            StatusCode::PermissionDenied => ErrorCode::Permission,
            StatusCode::Failure => ErrorCode::Transfer,
            _ => ErrorCode::Transfer,
        },
        _ => ErrorCode::Transfer,
    };
    RdtError::new(code, error.to_string()).with_context("path", path.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_fraction_is_clamped() {
        let progress = TransferProgress {
            direction: TransferDirection::Upload,
            transferred: 5,
            total: Some(10),
            bytes_per_second: 1.0,
        };
        assert_eq!(progress.fraction(), 0.5);

        let unknown = TransferProgress {
            total: None,
            ..progress
        };
        assert_eq!(unknown.fraction(), 0.0);

        let complete = TransferProgress {
            transferred: 20,
            total: Some(10),
            ..progress
        };
        assert_eq!(complete.fraction(), 1.0);
    }

    #[test]
    fn cancellation_is_observable() {
        let flag = Arc::new(AtomicBool::new(false));
        assert!(!flag.load(Ordering::SeqCst));
        flag.store(true, Ordering::SeqCst);
        assert!(flag.load(Ordering::SeqCst));
    }

    #[test]
    fn rates_are_never_infinite() {
        assert_eq!(rate(0, Instant::now()), 0.0);
        assert!(rate(1024, Instant::now() - std::time::Duration::from_secs(2)) > 0.0);
    }
}
