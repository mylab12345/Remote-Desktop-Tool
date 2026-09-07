//! Cryptographically secure random bytes.
//!
//! RDT needs randomness for identifiers and nonces in a crate that must stay
//! dependency free, so it reads directly from the operating system CSPRNG:
//! `/dev/urandom` on Unix and `BCryptGenRandom` on Windows.  Both are the same
//! sources `getrandom` uses, and both fail loudly instead of returning
//! predictable bytes.

use std::fmt;

/// Errors produced while gathering entropy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RandomError {
    /// The operating system entropy source could not be opened or read.
    Source(String),
    /// The operating system entropy source is not implemented for this platform.
    Unsupported,
}

impl fmt::Display for RandomError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source(message) => write!(f, "cannot read entropy: {message}"),
            Self::Unsupported => f.write_str("no entropy source on this platform"),
        }
    }
}

impl std::error::Error for RandomError {}

/// Fills `buffer` with bytes from the OS CSPRNG.
pub fn fill_random(buffer: &mut [u8]) -> Result<(), RandomError> {
    if buffer.is_empty() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        return fill_from_urandom(buffer);
    }
    #[cfg(windows)]
    {
        return fill_from_bcrypt(buffer);
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = buffer;
        Err(RandomError::Unsupported)
    }
}

/// Fills `buffer`, panicking only if the platform has no entropy source.
///
/// Used for identifiers, where there is no meaningful recovery path: without
/// entropy the process cannot create a session safely at all.
pub fn fill_random_or_panic(buffer: &mut [u8]) {
    if let Err(error) = fill_random(buffer) {
        panic!("RDT requires a working OS entropy source: {error}");
    }
}

#[cfg(unix)]
fn fill_from_urandom(buffer: &mut [u8]) -> Result<(), RandomError> {
    use std::io::Read;

    let mut file = std::fs::File::open("/dev/urandom")
        .map_err(|error| RandomError::Source(error.to_string()))?;
    file.read_exact(buffer)
        .map_err(|error| RandomError::Source(error.to_string()))
}

#[cfg(windows)]
fn fill_from_bcrypt(buffer: &mut [u8]) -> Result<(), RandomError> {
    use windows_sys::Win32::Security::Cryptography::{
        BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
    };

    // SAFETY: BCryptGenRandom writes exactly `buffer.len()` bytes into the
    // buffer we own and returns a status code.
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status == 0 {
        Err(RandomError::Source("BCryptGenRandom failed".to_owned()))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fills_the_requested_number_of_bytes() {
        let mut buffer = [0u8; 32];
        fill_random(&mut buffer).expect("entropy");
        assert!(buffer.iter().any(|byte| *byte != 0), "buffer stayed zeroed");
    }

    #[test]
    fn consecutive_draws_differ() {
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        fill_random(&mut a).expect("entropy");
        fill_random(&mut b).expect("entropy");
        assert_ne!(a, b);
    }

    #[test]
    fn empty_buffer_is_a_no_op() {
        fill_random(&mut []).expect("entropy");
    }

    #[test]
    fn errors_render_readably() {
        let error = RandomError::Source("disk on fire".to_owned());
        assert_eq!(error.to_string(), "cannot read entropy: disk on fire");
        assert_eq!(
            RandomError::Unsupported.to_string(),
            "no entropy source on this platform"
        );
    }
}
