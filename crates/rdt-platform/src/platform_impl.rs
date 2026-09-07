//! Platform specific primitives.
//!
//! The public surface is identical on every platform; only the implementations
//! differ.  `unsafe` is confined to the Windows module, which calls the Win32
//! API directly.

/// Returns the OS version string (`uname -r` on Unix, the Windows build on
/// Windows).
pub fn os_version() -> String {
    #[cfg(unix)]
    {
        // SAFETY: `uname` writes into the caller provided buffer; the struct is
        // initialised by the call itself.
        unsafe {
            let mut info: libc::utsname = std::mem::zeroed();
            if libc::uname(&mut info) == 0 {
                let release = std::ffi::CStr::from_ptr(info.release.as_ptr())
                    .to_string_lossy()
                    .into_owned();
                let sysname = std::ffi::CStr::from_ptr(info.sysname.as_ptr())
                    .to_string_lossy()
                    .into_owned();
                return format!("{sysname} {release}");
            }
        }
        "unix".to_owned()
    }
    #[cfg(windows)]
    {
        crate::platform_impl::windows::windows_version()
    }
    #[cfg(not(any(unix, windows)))]
    {
        "unknown".to_owned()
    }
}

/// Returns the machine name.
pub fn hostname() -> String {
    #[cfg(unix)]
    {
        let mut buffer = vec![0u8; 256];
        // SAFETY: `gethostname` writes at most `buffer.len()` bytes into the
        // buffer and returns 0 on success.
        unsafe {
            if libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len()) == 0 {
                let end = buffer
                    .iter()
                    .position(|byte| *byte == 0)
                    .unwrap_or(buffer.len());
                if let Ok(name) = String::from_utf8(buffer[..end].to_vec()) {
                    return name;
                }
            }
        }
        "localhost".to_owned()
    }
    #[cfg(windows)]
    {
        crate::platform_impl::windows::computer_name()
    }
    #[cfg(not(any(unix, windows)))]
    {
        std::env::var("HOSTNAME").unwrap_or_else(|_| "localhost".to_owned())
    }
}

/// Whether the process runs with administrator privileges.
pub fn is_elevated() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: `geteuid` takes no arguments and cannot fail.
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(windows)]
    {
        crate::platform_impl::windows::is_elevated()
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

/// Whether a graphical session looks available (used to decide whether the
/// desktop client can be launched).
pub fn graphical_session() -> bool {
    #[cfg(target_os = "windows")]
    {
        true
    }
    #[cfg(target_os = "linux")]
    {
        std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some()
    }
    #[cfg(target_os = "macos")]
    {
        true
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        false
    }
}

/// Restricts a file to the owning user (0600 on Unix, a no-op elsewhere because
/// NTFS inherits the ACL of the per-user profile directory).
pub fn restrict_to_owner(path: &std::path::Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

/// Restricts a directory to the owning user (0700 on Unix).
pub fn restrict_dir_to_owner(path: &std::path::Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

#[cfg(windows)]
mod windows {
    //! Win32 helpers.
    #![allow(unsafe_code)] // Win32 FFI is inherently unsafe; kept in one module.

    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, PSID, TOKEN_ELEVATION, TOKEN_QUERY};
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetTokenInformation, OpenProcessToken, TokenElevation,
    };

    pub fn windows_version() -> String {
        use windows_sys::Win32::System::SystemInformation::{RtlGetVersion, OSVERSIONINFOEXW};
        // SAFETY: `RtlGetVersion` fills the structure we hand it.
        unsafe {
            let mut info: OSVERSIONINFOEXW = std::mem::zeroed();
            info.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOEXW>() as u32;
            if RtlGetVersion(&mut info as *mut OSVERSIONINFOEXW as *mut _) == 0 {
                return format!(
                    "Windows {}.{}.{} (build {})",
                    info.dwMajorVersion,
                    info.dwMinorVersion,
                    info.dwBuildNumber,
                    info.dwBuildNumber
                );
            }
        }
        "Windows".to_owned()
    }

    pub fn computer_name() -> String {
        use windows_sys::Win32::System::SystemInformation::{
            ComputerNamePhysicalDnsHostname, GetComputerNameW, COMPUTER_NAME_FORMAT,
        };
        let mut buffer = [0u16; 256];
        let mut size = buffer.len() as u32;
        // SAFETY: the buffer and its length are passed together.
        let ok = unsafe { GetComputerNameW(buffer.as_mut_ptr(), &mut size) };
        if ok == 0 {
            return "localhost".to_owned();
        }
        String::from_utf16_lossy(&buffer[..size as usize])
    }

    pub fn is_elevated() -> bool {
        let mut token: HANDLE = 0;
        // SAFETY: `OpenProcessToken` writes a token handle on success.
        unsafe {
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return false;
            }
        }
        let mut elevation: TOKEN_ELEVATION = unsafe { std::mem::zeroed() };
        let mut returned = 0u32;
        let ok = unsafe {
            GetTokenInformation(
                token,
                TokenElevation,
                &mut elevation as *mut TOKEN_ELEVATION as *mut _,
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut returned,
            )
        };
        unsafe { CloseHandle(token) };
        ok != 0 && elevation.TokenIsElevated != 0
    }

    #[allow(dead_code)]
    fn _unused(_: PSID, _: COMPUTER_NAME_FORMAT) {}
}
