//! In-memory secret handling that never leaks through `Debug`, `Display` or
//! serialization, and that wipes its buffer on drop.

use std::fmt;
use std::ops::Deref;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{ErrorCode, RdtError, RdtResult};
use crate::redact::REDACTED;

/// A UTF-8 secret (password, passphrase, OTP, …).
///
/// The contents are zeroed when the value is dropped, `Debug`/`Display` always
/// print a redaction marker, and `Serialize` writes the marker as well so that a
/// secret can never reach a config file or a log by accident.
#[derive(Clone, Eq, Zeroize)]
#[zeroize(drop)]
pub struct Secret(String);

impl Secret {
    /// Wraps an already allocated string.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Parses a secret that arrived over an untrusted channel (a configuration
    /// file, a clipboard paste, a log line).
    ///
    /// The redaction marker is refused: text containing it never held the real
    /// value, and storing the literal placeholder would silently authenticate
    /// with garbage.
    pub fn from_untrusted(value: &str) -> RdtResult<Self> {
        if value == REDACTED {
            return Err(RdtError::new(
                ErrorCode::Config,
                "refusing to read a redacted secret; the original value was never stored",
            ));
        }
        Ok(Self(value.to_owned()))
    }

    /// An empty secret.
    pub fn empty() -> Self {
        Self(String::new())
    }

    /// Explicit, call-site-visible access to the cleartext.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Number of bytes in the secret.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the secret holds no bytes at all.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Constant-time comparison, so that equality checks do not leak how many
    /// leading bytes matched.
    pub fn equals(&self, other: &Secret) -> bool {
        constant_time_eq(self.0.as_bytes(), other.0.as_bytes())
    }

    /// Constant-time comparison against a byte slice.
    pub fn equals_bytes(&self, other: &[u8]) -> bool {
        constant_time_eq(self.0.as_bytes(), other)
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret({REDACTED}, {} bytes)", self.0.len())
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl From<String> for Secret {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for Secret {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl PartialEq for Secret {
    fn eq(&self, other: &Self) -> bool {
        self.equals(other)
    }
}

/// Serialization is intentionally lossy: the cleartext never leaves the process
/// through a serializer.  Use [`Secret::expose`] when the cleartext is really
/// required (for example to hand it to an authentication library).
impl Serialize for Secret {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(REDACTED)
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        if raw == REDACTED {
            return Err(serde::de::Error::custom(
                "refusing to read a redacted secret; the original value was never stored",
            ));
        }
        Ok(Self(Zeroizing::new(raw).to_string()))
    }
}

/// Binary secret material (key blobs, decrypted vault records, …).
#[derive(Clone, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Wraps an already allocated buffer.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Explicit access to the cleartext bytes.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Number of bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Converts the secret into a UTF-8 [`Secret`] when it is valid UTF-8.
    pub fn into_utf8_secret(self) -> Option<Secret> {
        String::from_utf8(self.0.clone()).ok().map(Secret)
    }
}

impl Deref for SecretBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes({REDACTED}, {} bytes)", self.0.len())
    }
}

impl From<Vec<u8>> for SecretBytes {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl From<Secret> for SecretBytes {
    fn from(value: Secret) -> Self {
        Self(value.expose().as_bytes().to_vec())
    }
}

impl PartialEq for SecretBytes {
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq(&self.0, &other.0)
    }
}

/// Length-independent constant-time equality.
///
/// The comparison always walks the longer of the two inputs; only the final
/// result depends on the length difference, which is already public through the
/// length fields of the containers involved.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = (a.len() ^ b.len()) as u8;
    for index in 0..a.len().max(b.len()) {
        let left = a.get(index).copied().unwrap_or(0);
        let right = b.get(index).copied().unwrap_or(0);
        diff |= left ^ right;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SecretBackend, StoredSecret};

    /// Proves the `Serialize` impl exists for the secret types.
    fn assert_serialize<T: serde::Serialize>() {}

    /// Proves the type is wired into the zeroize machinery.
    fn assert_zeroizing<T: zeroize::Zeroize + zeroize::ZeroizeOnDrop>() {}

    /// Proves a type can be wiped explicitly (Secret wipes on drop through its
    /// own `Drop` impl, which would conflict with the derived one).
    fn assert_wipable<T: zeroize::Zeroize>() {}

    #[test]
    fn secrets_are_zeroized() {
        // The wiping itself is implemented and tested by `zeroize`; what must
        // hold here is that both types opt into it.
        assert_wipable::<Secret>();
        assert_zeroizing::<SecretBytes>();

        let mut secret = Secret::new("wipe-me");
        assert_eq!(secret.expose(), "wipe-me");
        zeroize::Zeroize::zeroize(&mut secret);
        assert!(secret.is_empty());

        let mut bytes = SecretBytes::new(vec![1, 2, 3]);
        zeroize::Zeroize::zeroize(&mut bytes);
        assert!(bytes.expose().is_empty());
    }

    #[test]
    fn display_and_debug_redact() {
        let secret = Secret::new("hunter2");
        assert_eq!(secret.to_string(), REDACTED);
        let debug = format!("{secret:?}");
        assert!(!debug.contains("hunter2"), "{debug} leaked the secret");
        assert!(debug.contains(REDACTED));
        assert!(format!("{:?}", Secret::empty()).contains(REDACTED));
        let bytes = SecretBytes::new(vec![9, 9, 9]);
        let debug = format!("{bytes:?}");
        assert!(debug.contains(REDACTED) && !debug.contains('9'), "{debug}");
    }

    #[test]
    fn the_redaction_marker_is_rejected_on_the_way_in() {
        // The same guard is used by the `Deserialize` impl, which is the path a
        // configuration file takes.
        let rejected = Secret::from_untrusted(REDACTED).expect_err("must be refused");
        assert_eq!(rejected.code(), ErrorCode::Config);
        assert!(rejected.to_string().contains("redacted"));
        assert_eq!(Secret::from_untrusted("real").expect("ok").expose(), "real");
        assert_eq!(Secret::from_untrusted("").expect("ok").expose(), "");
    }

    #[test]
    fn empty_is_detected() {
        assert!(Secret::empty().is_empty());
        assert!(!Secret::new("x").is_empty());
        assert_eq!(Secret::new("abc").len(), 3);
    }

    #[test]
    fn equality_is_value_based() {
        assert!(Secret::new("abc").equals(&Secret::new("abc")));
        assert!(!Secret::new("abc").equals(&Secret::new("abd")));
        // Length differences must not panic inside the constant time compare.
        assert!(!Secret::new("abc").equals(&Secret::new("abcd")));
        assert!(Secret::new("abc").equals_bytes(b"abc"));
        assert!(!Secret::new("abc").equals_bytes(b"abd"));
        assert!(!Secret::new("abc").equals_bytes(b"abcd"));
        assert_eq!(SecretBytes::new(vec![1]), SecretBytes::new(vec![1]));
        assert_ne!(SecretBytes::new(vec![1]), SecretBytes::new(vec![1, 2]));
    }

    #[test]
    fn expose_is_explicit() {
        assert_eq!(Secret::new("value").expose(), "value");
        assert_eq!(SecretBytes::new(vec![1u8, 2]).expose(), &[1u8, 2]);
        assert_eq!(&*SecretBytes::new(vec![7]), &[7u8][..]);
        assert_eq!(
            SecretBytes::new(b"utf8".to_vec())
                .into_utf8_secret()
                .expect("utf8")
                .expose(),
            "utf8"
        );
        assert!(SecretBytes::new(vec![0xFF]).into_utf8_secret().is_none());
    }

    #[test]
    fn conversions_build_secrets() {
        assert_eq!(Secret::from("abc").expose(), "abc");
        assert_eq!(Secret::from(String::from("def")).expose(), "def");
        assert_eq!(SecretBytes::from(Secret::new("xy")).expose(), b"xy");
        assert_eq!(SecretBytes::from(vec![3u8]).len(), 1);
    }

    #[test]
    fn the_types_implement_serde() {
        assert_serialize::<Secret>();
        assert_serialize::<StoredSecret>();
    }

    #[test]
    fn stored_secret_references_never_hold_the_value() {
        let reference = StoredSecret {
            backend: SecretBackend::EncryptedVault,
            key: "ssh/alpha".to_owned(),
        };
        assert_eq!(reference.backend, SecretBackend::EncryptedVault);
        assert_eq!(reference.key, "ssh/alpha");
        let debug = format!("{reference:?}");
        assert!(
            debug.contains("ssh/alpha") && debug.contains("EncryptedVault"),
            "{debug}"
        );
        assert_ne!(SecretBackend::OsKeystore, SecretBackend::EncryptedVault);
    }
}
