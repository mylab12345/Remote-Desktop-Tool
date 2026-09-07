//! Clipboard bridging between the remote desktop and the local machine.
//!
//! On Windows the native clipboard API is used directly.  On Linux the
//! clipboard is owned by another process (a clipboard manager or the
//! compositor), so the well known helpers are used: `wl-copy`/`wl-paste` under
//! Wayland and `xclip`/`xsel` under X11.  This is a *clipboard* integration, not
//! a remote desktop one: no part of the RDP session is delegated to another
//! application.

use std::process::Stdio;

use rdt_types::{ErrorCode, RdtError, RdtResult};

/// A clipboard format negotiated with the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardFormat {
    /// UTF-8 text.
    Text,
    /// A list of file names.
    FileList,
    /// An image in PNG encoding.
    Png,
}

/// A clipboard operation to apply locally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClipboardOperation {
    /// Put this text on the local clipboard.
    SetText(String),
    /// Read the local clipboard as text.
    GetText,
}

/// Which clipboard helper is used on Unix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnixClipboard {
    /// Wayland.
    Wayland,
    /// X11.
    X11,
    /// No helper available.
    None,
}

/// Bridges the remote and local clipboards.
#[derive(Debug, Clone)]
pub struct ClipboardBridge {
    remote_to_local: bool,
    local_to_remote: bool,
}

impl ClipboardBridge {
    /// Creates a bridge honouring the user's security settings.
    pub fn new(remote_to_local: bool, local_to_remote: bool) -> Self {
        Self {
            remote_to_local,
            local_to_remote,
        }
    }

    /// True when text may flow from the remote session to the local clipboard.
    pub fn allows_remote_to_local(&self) -> bool {
        self.remote_to_local
    }

    /// True when text may flow from the local clipboard to the remote session.
    pub fn allows_local_to_remote(&self) -> bool {
        self.local_to_remote
    }

    /// Detects the clipboard helper available on this desktop.
    pub fn detect_unix_backend() -> UnixClipboard {
        if std::env::var_os("WAYLAND_DISPLAY").is_some() && has_program("wl-copy") {
            return UnixClipboard::Wayland;
        }
        if std::env::var_os("DISPLAY").is_some() && (has_program("xclip") || has_program("xsel")) {
            return UnixClipboard::X11;
        }
        UnixClipboard::None
    }

    /// Places text on the local clipboard.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::Permission`] when the policy forbids it and
    /// [`ErrorCode::Platform`] when no clipboard is available.
    pub async fn set_local_text(&self, text: &str) -> RdtResult<()> {
        if !self.remote_to_local {
            return Err(RdtError::new(
                ErrorCode::Permission,
                "copying from the remote session to the local clipboard is disabled",
            ));
        }
        #[cfg(windows)]
        {
            windows_clipboard::set_text(text)
        }
        #[cfg(not(windows))]
        {
            unix_clipboard::set_text(text).await
        }
    }

    /// Reads the local clipboard as text.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::Permission`] when the policy forbids it and
    /// [`ErrorCode::Platform`] when no clipboard is available or it holds no
    /// text.
    pub async fn local_text(&self) -> RdtResult<String> {
        if !self.local_to_remote {
            return Err(RdtError::new(
                ErrorCode::Permission,
                "pasting from the local clipboard to the remote session is disabled",
            ));
        }
        #[cfg(windows)]
        {
            windows_clipboard::get_text()
        }
        #[cfg(not(windows))]
        {
            unix_clipboard::get_text().await
        }
    }
}

fn has_program(name: &str) -> bool {
    let Ok(path) = std::env::var("PATH") else {
        return false;
    };
    std::path::Path::new(&path)
        .components()
        .any(|_| false)
        || std::env::split_paths(&path).any(|directory| directory.join(name).exists())
}

/// Runs a clipboard helper, feeding `input` to its stdin.
async fn run_helper(program: &str, args: &[&str], input: Option<&str>) -> RdtResult<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::process::Command;

    let mut child = Command::new(program)
        .args(args)
        .stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| {
            RdtError::new(
                ErrorCode::Platform,
                format!("cannot run {program}: {error}"),
            )
        })?;
    if let (Some(text), Some(mut stdin)) = (input, child.stdin.take()) {
        stdin.write_all(text.as_bytes()).await.map_err(|error| {
            RdtError::new(ErrorCode::Platform, format!("cannot write to {program}: {error}"))
        })?;
    }
    let output = child.wait_with_output().await.map_err(|error| {
        RdtError::new(ErrorCode::Platform, format!("{program} failed: {error}"))
    })?;
    if !output.status.success() {
        return Err(RdtError::new(
            ErrorCode::Platform,
            format!("{program} exited with {}", output.status),
        ));
    }
    String::from_utf8(output.stdout).map_err(|error| {
        RdtError::new(ErrorCode::Platform, format!("{program} returned invalid UTF-8: {error}"))
    })
}

#[cfg(not(windows))]
mod unix_clipboard {
    use super::*;

    pub async fn set_text(text: &str) -> RdtResult<()> {
        match ClipboardBridge::detect_unix_backend() {
            UnixClipboard::Wayland => {
                run_helper("wl-copy", &["--type", "text/plain"], Some(text)).await?;
            }
            UnixClipboard::X11 => {
                if has_program("xclip") {
                    run_helper("xclip", &["-selection", "clipboard"], Some(text)).await?;
                } else {
                    run_helper("xsel", &["--clipboard", "--input"], Some(text)).await?;
                }
            }
            UnixClipboard::None => {
                return Err(RdtError::new(
                    ErrorCode::Platform,
                    "no clipboard helper is available; install wl-clipboard or xclip",
                ));
            }
        }
        Ok(())
    }

    pub async fn get_text() -> RdtResult<String> {
        match ClipboardBridge::detect_unix_backend() {
            UnixClipboard::Wayland => run_helper("wl-paste", &["--no-newline"], None).await,
            UnixClipboard::X11 => {
                if has_program("xclip") {
                    run_helper("xclip", &["-selection", "clipboard", "-out"], None).await
                } else {
                    run_helper("xsel", &["--clipboard", "--output"], None).await
                }
            }
            UnixClipboard::None => Err(RdtError::new(
                ErrorCode::Platform,
                "no clipboard helper is available; install wl-clipboard or xclip",
            )),
        }
    }
}

#[cfg(windows)]
mod windows_clipboard {
    use super::*;
    use windows_sys::Win32::System::DataExchange::{
        CloseClipboard, GetClipboardData, OpenClipboard, SetClipboardData, EmptyClipboard,
    };
    use windows_sys::Win32::System::Memory::{
        GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE,
    };
    use windows_sys::Win32::System::Ole::CF_UNICODETEXT;

    /// Opens the clipboard, retrying briefly because it is a global lock.
    fn open() -> RdtResult<()> {
        for _ in 0..10 {
            // SAFETY: OpenClipboard takes an optional window handle; null means
            // the clipboard is associated with the current task.
            if unsafe { OpenClipboard(std::ptr::null_mut()) } != 0 {
                return Ok(());
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        Err(RdtError::new(ErrorCode::Platform, "the clipboard is busy"))
    }

    pub fn set_text(text: &str) -> RdtResult<()> {
        open()?;
        let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
        let bytes = wide.len() * 2;
        // SAFETY: GlobalAlloc with GMEM_MOVEABLE returns a movable handle that
        // GlobalLock maps to a writable pointer of the requested size.
        let handle = unsafe { GlobalAlloc(GMEM_MOVEABLE, bytes) };
        if handle.is_null() {
            unsafe { CloseClipboard() };
            return Err(RdtError::new(ErrorCode::Platform, "cannot allocate clipboard memory"));
        }
        // SAFETY: the handle was just allocated with `bytes` bytes.
        let pointer = unsafe { GlobalLock(handle) };
        if pointer.is_null() {
            unsafe { CloseClipboard() };
            return Err(RdtError::new(ErrorCode::Platform, "cannot lock clipboard memory"));
        }
        // SAFETY: `pointer` points at `bytes` writable bytes.
        unsafe {
            std::ptr::copy_nonoverlapping(wide.as_ptr().cast::<u8>(), pointer.cast::<u8>(), bytes);
            GlobalUnlock(handle);
            EmptyClipboard();
            if SetClipboardData(CF_UNICODETEXT, handle).is_null() {
                CloseClipboard();
                return Err(RdtError::new(ErrorCode::Platform, "cannot set the clipboard"));
            }
            CloseClipboard();
        }
        Ok(())
    }

    pub fn get_text() -> RdtResult<String> {
        open()?;
        // SAFETY: GetClipboardData returns a handle owned by the system; it is
        // only read while the clipboard is open and never freed here.
        let result = unsafe {
            let handle = GetClipboardData(CF_UNICODETEXT);
            if handle.is_null() {
                CloseClipboard();
                return Err(RdtError::new(ErrorCode::Platform, "the clipboard holds no text"));
            }
            let pointer = GlobalLock(handle as _) as *const u16;
            if pointer.is_null() {
                CloseClipboard();
                return Err(RdtError::new(ErrorCode::Platform, "cannot read the clipboard"));
            }
            let mut length = 0;
            while *pointer.add(length) != 0 {
                length += 1;
            }
            let text = String::from_utf16_lossy(std::slice::from_raw_parts(pointer, length));
            GlobalUnlock(handle as _);
            CloseClipboard();
            Ok(text)
        };
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bridge_honours_the_security_settings() {
        let bridge = ClipboardBridge::new(true, false);
        assert!(bridge.allows_remote_to_local());
        assert!(!bridge.allows_local_to_remote());
        let bridge = ClipboardBridge::new(false, true);
        assert!(!bridge.allows_remote_to_local());
        assert!(bridge.allows_local_to_remote());
    }

    #[test]
    fn detection_reports_something_on_every_platform() {
        // The result depends on the desktop environment, so only the shape is
        // asserted: the call must not panic and must return a known variant.
        let backend = ClipboardBridge::detect_unix_backend();
        assert!(matches!(
            backend,
            UnixClipboard::Wayland | UnixClipboard::X11 | UnixClipboard::None
        ));
    }

    #[test]
    fn formats_are_distinct() {
        assert_ne!(ClipboardFormat::Text, ClipboardFormat::Png);
        assert_ne!(ClipboardFormat::FileList, ClipboardFormat::Text);
        assert_eq!(
            ClipboardOperation::GetText,
            ClipboardOperation::GetText
        );
    }

    #[tokio::test]
    async fn a_disabled_direction_is_refused_without_touching_the_clipboard() {
        let bridge = ClipboardBridge::new(false, false);
        let error = bridge.set_local_text("secret").await.expect_err("must fail");
        assert_eq!(error.code(), ErrorCode::Permission);
        let error = bridge.local_text().await.expect_err("must fail");
        assert_eq!(error.code(), ErrorCode::Permission);
    }
}
