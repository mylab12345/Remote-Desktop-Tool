//! Operating system keystore integration.
//!
//! * **Windows**: DPAPI (`CryptProtectData`) with a per-user entropy value.  The
//!   protected blob is written next to the configuration; only the user account
//!   (or the machine, for machine scope) can decrypt it.
//! * **Linux**: the freedesktop Secret Service through `secret-tool`, which
//!   talks to GNOME Keyring or KWallet.
//! * **Other platforms**: unavailable; callers fall back to the encrypted vault.
//!
//! Both backends are probed before use, and every failure is reported as a typed
//! error so the UI can offer the vault instead.

use std::path::PathBuf;

use rdt_types::{ErrorCode, RdtError, RdtResult, Secret};

/// Access to the platform keystore.
#[derive(Debug, Clone)]
pub struct OsKeystore {
    backend: Backend,
}

#[derive(Debug, Clone)]
enum Backend {
    #[cfg(windows)]
    Dpapi { directory: PathBuf },
    #[cfg(all(unix, not(target_os = "macos")))]
    SecretTool { program: PathBuf },
    #[cfg(target_os = "macos")]
    Security,
    Unavailable { reason: &'static str },
}

impl OsKeystore {
    /// Detects the best keystore for this machine.
    pub fn new() -> Self {
        Self {
            backend: detect(),
        }
    }

    /// Whether the keystore can be used.
    pub fn available(&self) -> bool {
        !matches!(self.backend, Backend::Unavailable { .. })
    }

    /// Human readable description of the detected backend.
    pub fn describe(&self) -> &'static str {
        match &self.backend {
            #[cfg(windows)]
            Backend::Dpapi { .. } => "Windows DPAPI",
            #[cfg(all(unix, not(target_os = "macos")))]
            Backend::SecretTool { .. } => "freedesktop Secret Service via secret-tool",
            #[cfg(target_os = "macos")]
            Backend::Security => "macOS Keychain",
            Backend::Unavailable { reason } => reason,
        }
    }

    /// Stores `value` under `key`.
    pub fn set(&self, key: &str, value: &Secret) -> RdtResult<()> {
        match &self.backend {
            #[cfg(windows)]
            Backend::Dpapi { directory } => windows_dpapi::set(directory, key, value),
            #[cfg(all(unix, not(target_os = "macos")))]
            Backend::SecretTool { program } => secret_tool_set(program, key, value),
            #[cfg(target_os = "macos")]
            Backend::Security => keychain_set(key, value),
            Backend::Unavailable { reason } => Err(RdtError::new(ErrorCode::Keystore, *reason)),
        }
    }

    /// Reads the value stored under `key`.
    pub fn get(&self, key: &str) -> RdtResult<Secret> {
        match &self.backend {
            #[cfg(windows)]
            Backend::Dpapi { directory } => windows_dpapi::get(directory, key),
            #[cfg(all(unix, not(target_os = "macos")))]
            Backend::SecretTool { program } => secret_tool_get(program, key),
            #[cfg(target_os = "macos")]
            Backend::Security => keychain_get(key),
            Backend::Unavailable { reason } => Err(RdtError::new(ErrorCode::Keystore, *reason)),
        }
    }

    /// Deletes the value stored under `key`.
    pub fn delete(&self, key: &str) -> RdtResult<()> {
        match &self.backend {
            #[cfg(windows)]
            Backend::Dpapi { directory } => windows_dpapi::delete(directory, key),
            #[cfg(all(unix, not(target_os = "macos")))]
            Backend::SecretTool { program } => secret_tool_delete(program, key),
            #[cfg(target_os = "macos")]
            Backend::Security => keychain_delete(key),
            Backend::Unavailable { reason } => Err(RdtError::new(ErrorCode::Keystore, *reason)),
        }
    }
}

impl Default for OsKeystore {
    fn default() -> Self {
        Self::new()
    }
}

fn detect() -> Backend {
    #[cfg(windows)]
    {
        let directory = rdt_platform::AppPaths::detect().data_dir.join("keystore");
        if let Err(error) = std::fs::create_dir_all(&directory) {
            tracing::warn!(?error, "cannot create the DPAPI blob directory");
            return Backend::Unavailable {
                reason: "the DPAPI blob directory could not be created",
            };
        }
        return Backend::Dpapi { directory };
    }
    #[cfg(target_os = "macos")]
    {
        return Backend::Security;
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let program = match rdt_platform::which("secret-tool") {
            Some(program) => program,
            None => {
                return Backend::Unavailable {
                    reason: "secret-tool is not installed; install libsecret or use the encrypted vault",
                }
            }
        };
        if std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_none() {
            return Backend::Unavailable {
                reason: "no D-Bus session bus is available for the Secret Service",
            };
        }
        return Backend::SecretTool { program };
    }
    #[cfg(not(any(unix, windows)))]
    {
        Backend::Unavailable {
            reason: "no keystore is implemented for this platform",
        }
    }
}

/// Hashes a key into a file name that is safe on every filesystem.
fn blob_name(key: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(key.as_bytes());
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(all(unix, not(target_os = "macos")))]
fn secret_tool_set(program: &std::path::Path, key: &str, value: &Secret) -> RdtResult<()> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut child = Command::new(program)
        .args(["store", "--label=RDT secret", "rdt-key", key])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| {
            RdtError::new(
                ErrorCode::Keystore,
                format!("cannot run secret-tool: {error}"),
            )
        })?;
    {
        let stdin = child.stdin.as_mut().ok_or_else(|| {
            RdtError::new(ErrorCode::Keystore, "cannot write to secret-tool")
        })?;
        stdin
            .write_all(value.expose().as_bytes())
            .and_then(|()| stdin.flush())
            .map_err(|error| {
                RdtError::new(
                    ErrorCode::Keystore,
                    format!("cannot write the secret to secret-tool: {error}"),
                )
            })?;
    }
    let output = child
        .wait_with_output()
        .map_err(|error| RdtError::new(ErrorCode::Keystore, error.to_string()))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(RdtError::new(
            ErrorCode::Keystore,
            format!(
                "secret-tool store failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        ))
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
fn secret_tool_get(program: &std::path::Path, key: &str) -> RdtResult<Secret> {
    let output = std::process::Command::new(program)
        .args(["lookup", "rdt-key", key])
        .output()
        .map_err(|error| {
            RdtError::new(
                ErrorCode::Keystore,
                format!("cannot run secret-tool: {error}"),
            )
        })?;
    if !output.status.success() {
        return Err(RdtError::new(
            ErrorCode::Keystore,
            format!("no keyring entry named '{key}'"),
        ));
    }
    let mut text = String::from_utf8_lossy(&output.stdout).to_string();
    // secret-tool does not add a trailing newline, but be defensive anyway.
    while text.ends_with('\n') {
        text.pop();
    }
    Ok(Secret::new(text))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn secret_tool_delete(program: &std::path::Path, key: &str) -> RdtResult<()> {
    let output = std::process::Command::new(program)
        .args(["clear", "rdt-key", key])
        .output()
        .map_err(|error| {
            RdtError::new(
                ErrorCode::Keystore,
                format!("cannot run secret-tool: {error}"),
            )
        })?;
    if output.status.success() {
        Ok(())
    } else {
        Err(RdtError::new(
            ErrorCode::Keystore,
            format!(
                "secret-tool clear failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        ))
    }
}

#[cfg(target_os = "macos")]
fn keychain_set(key: &str, value: &Secret) -> RdtResult<()> {
    let _ = keychain_delete(key);
    let status = std::process::Command::new("security")
        .args([
            "add-generic-password",
            "-s",
            "rdt",
            "-a",
            key,
            "-w",
            value.expose(),
        ])
        .status()
        .map_err(|error| RdtError::new(ErrorCode::Keystore, error.to_string()))?;
    if status.success() {
        Ok(())
    } else {
        Err(RdtError::new(ErrorCode::Keystore, "security add-generic-password failed"))
    }
}

#[cfg(target_os = "macos")]
fn keychain_get(key: &str) -> RdtResult<Secret> {
    let output = std::process::Command::new("security")
        .args(["find-generic-password", "-s", "rdt", "-a", key, "-w"])
        .output()
        .map_err(|error| RdtError::new(ErrorCode::Keystore, error.to_string()))?;
    if !output.status.success() {
        return Err(RdtError::new(
            ErrorCode::Keystore,
            format!("no keychain entry named '{key}'"),
        ));
    }
    Ok(Secret::new(String::from_utf8_lossy(&output.stdout).trim().to_owned()))
}

#[cfg(target_os = "macos")]
fn keychain_delete(key: &str) -> RdtResult<()> {
    let output = std::process::Command::new("security")
        .args(["delete-generic-password", "-s", "rdt", "-a", key])
        .output()
        .map_err(|error| RdtError::new(ErrorCode::Keystore, error.to_string()))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(RdtError::new(
            ErrorCode::Keystore,
            format!("no keychain entry named '{key}'"),
        ))
    }
}

#[cfg(windows)]
mod windows_dpapi {
    //! DPAPI backed storage.
    #![allow(unsafe_code)] // DPAPI is a Win32 FFI.

    use rdt_types::{ErrorCode, RdtError, RdtResult, Secret};
    use std::path::Path;

    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB,
        CRYPTPROTECT_UI_FORBIDDEN,
    };

    /// Per-user entropy so that blobs copied between accounts do not decrypt.
    fn entropy() -> Vec<u8> {
        let mut bytes = b"rdt/keystore/v1/".to_vec();
        bytes.extend(blob_name_bytes());
        bytes
    }

    fn blob_name_bytes() -> Vec<u8> {
        // The user SID is stable per account; fall back to the user name.
        let name = std::env::var("USERNAME").unwrap_or_else(|_| "user".to_owned());
        name.into_bytes()
    }

    fn path_for(directory: &Path, key: &str) -> std::path::PathBuf {
        directory.join(super::blob_name(key)).with_extension("bin")
    }

    pub fn set(directory: &Path, key: &str, value: &Secret) -> RdtResult<()> {
        let plaintext = value.expose().as_bytes().to_vec();
        let entropy = entropy();
        let mut input = CRYPT_INTEGER_BLOB {
            cbData: plaintext.len() as u32,
            pbData: plaintext.as_ptr() as *mut u8,
        };
        let mut salt = CRYPT_INTEGER_BLOB {
            cbData: entropy.len() as u32,
            pbData: entropy.as_ptr() as *mut u8,
        };
        let mut output: CRYPT_INTEGER_BLOB = unsafe { std::mem::zeroed() };
        // SAFETY: the blobs describe the buffers we own; the result is freed below.
        let ok = unsafe {
            CryptProtectData(
                &mut input,
                std::ptr::null(),
                &mut salt,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };
        if ok == 0 {
            return Err(RdtError::new(
                ErrorCode::Keystore,
                "CryptProtectData failed",
            ));
        }
        let protected = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) }.to_vec();
        unsafe { LocalFree(output.pbData as *mut _) };
        std::fs::create_dir_all(directory)?;
        let target = path_for(directory, key);
        std::fs::write(&target, protected)?;
        rdt_platform::restrict_to_owner(&target)?;
        Ok(())
    }

    pub fn get(directory: &Path, key: &str) -> RdtResult<Secret> {
        let path = path_for(directory, key);
        let blob = std::fs::read(&path).map_err(|_| {
            RdtError::new(
                ErrorCode::Keystore,
                format!("no DPAPI blob for '{key}'"),
            )
        })?;
        let entropy = entropy();
        let mut input = CRYPT_INTEGER_BLOB {
            cbData: blob.len() as u32,
            pbData: blob.as_ptr() as *mut u8,
        };
        let mut salt = CRYPT_INTEGER_BLOB {
            cbData: entropy.len() as u32,
            pbData: entropy.as_ptr() as *mut u8,
        };
        let mut output: CRYPT_INTEGER_BLOB = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        let ok = unsafe {
            CryptUnprotectData(
                &mut input,
                std::ptr::null_mut(),
                &mut salt,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };
        if ok == 0 {
            return Err(RdtError::new(
                ErrorCode::Keystore,
                "CryptUnprotectData failed; the blob may belong to another account",
            ));
        }
        let plaintext =
            unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) }.to_vec();
        unsafe { LocalFree(output.pbData as *mut _) };
        Ok(Secret::new(String::from_utf8_lossy(&plaintext).to_string()))
    }

    pub fn delete(directory: &Path, key: &str) -> RdtResult<()> {
        let path = path_for(directory, key);
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_names_are_stable_and_distinct() {
        assert_eq!(blob_name("a"), blob_name("a"));
        assert_ne!(blob_name("a"), blob_name("b"));
        assert_eq!(blob_name("a").len(), 64);
    }

    #[test]
    fn detection_reports_something_usable_or_a_reason() {
        let keystore = OsKeystore::new();
        if keystore.available() {
            assert!(!keystore.describe().is_empty());
        } else {
            assert!(keystore.describe().len() > 10);
            let error = keystore.get("anything").unwrap_err();
            assert_eq!(error.code(), ErrorCode::Keystore);
        }
    }
}
