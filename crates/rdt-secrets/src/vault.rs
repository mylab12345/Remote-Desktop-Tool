//! Encrypted vault: ChaCha20-Poly1305 with an Argon2id derived key.
//!
//! File layout (all integers little endian):
//!
//! ```text
//! offset  size  field
//! 0       8     magic "RDTVLT1"
//! 8       4     Argon2 memory cost (KiB)
//! 12      4     Argon2 time cost (iterations)
//! 16      4     Argon2 parallelism
//! 20      16    salt
//! 36      12    AEAD nonce
//! 48      ..    ciphertext (ChaCha20-Poly1305 over the payload, AAD = header)
//! ```
//!
//! The payload is a JSON map of key to base64 encoded value.  Because the whole
//! payload is authenticated, tampering with any entry invalidates the file.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine as _;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;
use rdt_types::{ErrorCode, RdtError, RdtResult, Secret};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

/// File magic.
pub const MAGIC: &[u8; 8] = b"RDTVLT1\0";
/// Argon2id memory cost in KiB (64 MiB).
pub const MEMORY_COST: u32 = 64 * 1024;
/// Argon2id iteration count.
pub const TIME_COST: u32 = 3;
/// Argon2id parallelism.
pub const PARALLELISM: u32 = 1;
/// Derived key length.
const KEY_LEN: usize = 32;
/// Salt length.
const SALT_LEN: usize = 16;
/// Nonce length.
const NONCE_LEN: usize = 12;
/// Header length.
const HEADER_LEN: usize = 8 + 4 + 4 + 4 + SALT_LEN + NONCE_LEN;

/// Serialised vault payload.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PayloadMap {
    /// Schema version, bumped when the layout changes.
    version: u32,
    /// Key to base64 value.
    entries: BTreeMap<String, String>,
}

/// An unlocked vault in memory.
#[derive(Debug)]
pub struct Vault {
    path: PathBuf,
    key: Zeroizing<[u8; KEY_LEN]>,
    header: Vec<u8>,
    payload: PayloadMap,
}

impl Vault {
    /// Creates a new vault file, overwriting any previous one.
    pub fn create(path: &Path, passphrase: &Secret) -> RdtResult<Self> {
        if passphrase.is_empty() {
            return Err(RdtError::new(
                ErrorCode::Vault,
                "the vault passphrase must not be empty",
            ));
        }
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        let key = derive_key(passphrase, &salt)?;
        let mut vault = Self {
            path: path.to_path_buf(),
            key,
            header: Vec::new(),
            payload: PayloadMap {
                version: 1,
                entries: BTreeMap::new(),
            },
        };
        vault.header = build_header(&salt);
        vault.save()?;
        Ok(vault)
    }

    /// Opens and decrypts an existing vault.
    pub fn open(path: &Path, passphrase: &Secret) -> RdtResult<Self> {
        let bytes = std::fs::read(path)
            .map_err(|error| RdtError::from(error).context(format!("reading {}", path.display())))?;
        if bytes.len() < HEADER_LEN {
            return Err(RdtError::new(
                ErrorCode::Vault,
                "vault file is truncated",
            ));
        }
        if &bytes[..8] != MAGIC {
            return Err(RdtError::new(
                ErrorCode::Vault,
                "not an RDT vault file",
            ));
        }
        let header = bytes[..HEADER_LEN].to_vec();
        let salt: [u8; SALT_LEN] = header[20..36]
            .try_into()
            .map_err(|_| RdtError::new(ErrorCode::Vault, "corrupt salt"))?;
        let nonce: [u8; NONCE_LEN] = header[36..HEADER_LEN]
            .try_into()
            .map_err(|_| RdtError::new(ErrorCode::Vault, "corrupt nonce"))?;
        let key = derive_key(passphrase, &salt)?;
        let cipher = ChaCha20Poly1305::new(key.as_ref().into());
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &bytes[HEADER_LEN..],
                    aad: &header,
                },
            )
            .map_err(|_| {
                RdtError::new(
                    ErrorCode::Vault,
                    "decryption failed: wrong passphrase or corrupted file",
                )
            })?;
        let payload: PayloadMap = serde_json::from_slice(&plaintext).map_err(|error| {
            RdtError::new(ErrorCode::Vault, format!("corrupt vault payload: {error}"))
        })?;
        Ok(Self {
            path: path.to_path_buf(),
            key,
            header,
            payload,
        })
    }

    /// Path of the vault file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Every entry, sorted by key.
    pub fn entries(&self) -> RdtResult<BTreeMap<String, Secret>> {
        let mut out = BTreeMap::new();
        for (key, encoded) in &self.payload.entries {
            let raw = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|_| RdtError::new(ErrorCode::Vault, format!("corrupt entry '{key}'")))?;
            let text = String::from_utf8(raw)
                .map_err(|_| RdtError::new(ErrorCode::Vault, format!("entry '{key}' is not text")))?;
            out.insert(key.clone(), Secret::new(text));
        }
        Ok(out)
    }

    /// Sorted keys.
    pub fn keys(&self) -> Vec<String> {
        self.payload.entries.keys().cloned().collect()
    }

    /// Reads one entry.
    pub fn get(&self, key: &str) -> RdtResult<Secret> {
        let encoded = self.payload.entries.get(key).ok_or_else(|| {
            RdtError::new(ErrorCode::Vault, format!("no vault entry named '{key}'"))
        })?;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| RdtError::new(ErrorCode::Vault, format!("corrupt entry '{key}'")))?;
        let text = String::from_utf8(raw)
            .map_err(|_| RdtError::new(ErrorCode::Vault, format!("entry '{key}' is not text")))?;
        Ok(Secret::new(text))
    }

    /// Inserts or replaces an entry and writes the file.
    pub fn set(&mut self, key: &str, value: &Secret) -> RdtResult<()> {
        let encoded = base64::engine::general_purpose::STANDARD.encode(value.expose().as_bytes());
        self.payload.entries.insert(key.to_owned(), encoded);
        self.save()
    }

    /// Removes an entry and writes the file.
    pub fn delete(&mut self, key: &str) -> RdtResult<()> {
        if self.payload.entries.remove(key).is_none() {
            return Err(RdtError::new(
                ErrorCode::Vault,
                format!("no vault entry named '{key}'"),
            ));
        }
        self.save()
    }

    /// Changes the passphrase, re-encrypting every entry.
    pub fn change_passphrase(&mut self, new_passphrase: &Secret) -> RdtResult<()> {
        if new_passphrase.is_empty() {
            return Err(RdtError::new(
                ErrorCode::Vault,
                "the vault passphrase must not be empty",
            ));
        }
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        self.key = derive_key(new_passphrase, &salt)?;
        self.header = build_header(&salt);
        self.save()
    }

    /// Encrypts and writes the vault atomically.
    pub fn save(&self) -> RdtResult<()> {
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let mut header = self.header[..HEADER_LEN - NONCE_LEN].to_vec();
        header.extend_from_slice(&nonce);

        let plaintext = serde_json::to_vec(&self.payload)
            .map_err(|error| RdtError::new(ErrorCode::Vault, format!("cannot encode payload: {error}")))?;
        let cipher = ChaCha20Poly1305::new(self.key.as_ref().into());
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &header,
                },
            )
            .map_err(|error| RdtError::new(ErrorCode::Vault, format!("encryption failed: {error}")))?;

        let mut bytes = Vec::with_capacity(HEADER_LEN + ciphertext.len());
        bytes.extend_from_slice(&header);
        bytes.extend_from_slice(&ciphertext);

        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let temporary = self.path.with_extension("vault.tmp");
        {
            let mut file = std::fs::File::create(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
        }
        crate::restrict(&temporary)?;
        std::fs::rename(&temporary, &self.path)?;
        Ok(())
    }
}

impl Drop for Vault {
    fn drop(&mut self) {
        self.payload.entries.clear();
        self.header.zeroize();
    }
}

fn build_header(salt: &[u8; SALT_LEN]) -> Vec<u8> {
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&MEMORY_COST.to_le_bytes());
    header.extend_from_slice(&TIME_COST.to_le_bytes());
    header.extend_from_slice(&PARALLELISM.to_le_bytes());
    header.extend_from_slice(salt);
    header.extend_from_slice(&[0u8; NONCE_LEN]);
    header
}

fn derive_key(passphrase: &Secret, salt: &[u8; SALT_LEN]) -> RdtResult<Zeroizing<[u8; KEY_LEN]>> {
    let params = Params::new(MEMORY_COST, TIME_COST, PARALLELISM, Some(KEY_LEN as u32))
        .map_err(|error| RdtError::new(ErrorCode::Crypto, format!("invalid KDF parameters: {error}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(passphrase.expose().as_bytes(), salt, key.as_mut())
        .map_err(|error| RdtError::new(ErrorCode::Crypto, format!("key derivation failed: {error}")))?;
    Ok(key)
}

/// A vault slot that may be locked.
#[derive(Debug)]
pub enum VaultHandle {
    /// Locked: only the path is known.
    Closed {
        /// Path of the vault file.
        path: PathBuf,
    },
    /// Unlocked.
    Open(Vault),
}

impl VaultHandle {
    /// A locked handle.
    pub fn closed(path: PathBuf) -> Self {
        Self::Closed { path }
    }

    /// Opens the vault with `passphrase`.
    pub fn open(path: PathBuf, passphrase: &Secret) -> RdtResult<Self> {
        Ok(Self::Open(Vault::open(&path, passphrase)?))
    }

    /// Whether the handle holds an unlocked vault.
    pub fn is_open(&self) -> bool {
        matches!(self, Self::Open(_))
    }

    /// Path of the vault file.
    pub fn path(&self) -> &Path {
        match self {
            Self::Closed { path } => path,
            Self::Open(vault) => vault.path(),
        }
    }

    /// Reads an entry.
    pub fn get(&self, key: &str) -> RdtResult<Secret> {
        self.with(|vault| vault.get(key))
    }

    /// Writes an entry.
    pub fn set(&mut self, key: &str, value: &Secret) -> RdtResult<()> {
        self.with_mut(|vault| vault.set(key, value))
    }

    /// Deletes an entry.
    pub fn delete(&mut self, key: &str) -> RdtResult<()> {
        self.with_mut(|vault| vault.delete(key))
    }

    /// Lists keys.
    pub fn keys(&self) -> RdtResult<Vec<String>> {
        self.with(|vault| Ok(vault.keys()))
    }

    /// Lists entries.
    pub fn entries(&self) -> RdtResult<BTreeMap<String, Secret>> {
        self.with(|vault| vault.entries())
    }

    fn with<T>(&self, action: impl FnOnce(&Vault) -> RdtResult<T>) -> RdtResult<T> {
        match self {
            Self::Open(vault) => action(vault),
            Self::Closed { path } => Err(RdtError::new(
                ErrorCode::Vault,
                format!("vault {} is locked", path.display()),
            )),
        }
    }

    fn with_mut<T>(&mut self, action: impl FnOnce(&mut Vault) -> RdtResult<T>) -> RdtResult<T> {
        match self {
            Self::Open(vault) => action(vault),
            Self::Closed { path } => Err(RdtError::new(
                ErrorCode::Vault,
                format!("vault {} is locked", path.display()),
            )),
        }
    }
}

/// Restricts a file to its owner (0600 on Unix).
fn restrict(path: &Path) -> RdtResult<()> {
    rdt_platform::restrict_to_owner(path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rdt-vault-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create dir");
        dir.join(name)
    }

    #[test]
    fn create_set_get_delete_round_trip() {
        let path = temp_path("basic.vault");
        let _ = std::fs::remove_file(&path);
        let mut vault = Vault::create(&path, &Secret::new("pass phrase")).expect("create");
        vault.set("ssh/host/password", &Secret::new("hunter2")).expect("set");
        assert_eq!(vault.keys(), vec!["ssh/host/password"]);
        assert_eq!(vault.get("ssh/host/password").expect("get").expose(), "hunter2");

        let reopened = Vault::open(&path, &Secret::new("pass phrase")).expect("open");
        assert_eq!(
            reopened.get("ssh/host/password").expect("get").expose(),
            "hunter2"
        );

        let mut reopened = reopened;
        reopened.delete("ssh/host/password").expect("delete");
        assert!(Vault::open(&path, &Secret::new("pass phrase"))
            .expect("open")
            .get("ssh/host/password")
            .is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn wrong_passphrase_is_rejected() {
        let path = temp_path("wrong.vault");
        let _ = std::fs::remove_file(&path);
        Vault::create(&path, &Secret::new("right")).expect("create");
        let error = Vault::open(&path, &Secret::new("wrong")).unwrap_err();
        assert_eq!(error.code(), ErrorCode::Vault);
        assert!(error.message().contains("wrong passphrase"), "{error}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn tampering_is_detected() {
        let path = temp_path("tamper.vault");
        let _ = std::fs::remove_file(&path);
        let mut vault = Vault::create(&path, &Secret::new("pass")).expect("create");
        vault.set("a", &Secret::new("b")).expect("set");
        let mut bytes = std::fs::read(&path).expect("read");
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        std::fs::write(&path, bytes).expect("write");
        let error = Vault::open(&path, &Secret::new("pass")).unwrap_err();
        assert_eq!(error.code(), ErrorCode::Vault);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn empty_passphrase_is_refused() {
        let path = temp_path("empty.vault");
        let error = Vault::create(&path, &Secret::empty()).unwrap_err();
        assert_eq!(error.code(), ErrorCode::Vault);
    }

    #[test]
    fn foreign_file_is_refused() {
        let path = temp_path("foreign.vault");
        std::fs::write(&path, b"not a vault at all, definitely not").expect("write");
        let error = Vault::open(&path, &Secret::new("x")).unwrap_err();
        assert_eq!(error.code(), ErrorCode::Vault);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn changing_the_passphrase_keeps_the_data() {
        let path = temp_path("rotate.vault");
        let _ = std::fs::remove_file(&path);
        let mut vault = Vault::create(&path, &Secret::new("old")).expect("create");
        vault.set("k", &Secret::new("v")).expect("set");
        vault.change_passphrase(&Secret::new("new")).expect("rotate");
        assert!(Vault::open(&path, &Secret::new("old")).is_err());
        let reopened = Vault::open(&path, &Secret::new("new")).expect("open with new passphrase");
        assert_eq!(reopened.get("k").expect("get").expose(), "v");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn locked_handle_reports_a_typed_error() {
        let handle = VaultHandle::closed(PathBuf::from("/tmp/nope.vault"));
        assert!(!handle.is_open());
        let error = handle.get("anything").unwrap_err();
        assert_eq!(error.code(), ErrorCode::Vault);
        assert!(error.message().contains("locked"));
    }

    #[test]
    fn header_layout_is_stable() {
        let header = build_header(&[7u8; SALT_LEN]);
        assert_eq!(&header[..8], MAGIC);
        assert_eq!(header.len(), HEADER_LEN);
        assert_eq!(u32::from_le_bytes(header[8..12].try_into().expect("u32")), MEMORY_COST);
        assert_eq!(&header[20..36], &[7u8; SALT_LEN]);
    }
}
