//! Secret storage.
//!
//! Two backends are implemented:
//!
//! * the **operating system keystore** - DPAPI on Windows, the Secret Service
//!   (`secret-tool`, i.e. GNOME Keyring / KWallet) on Linux desktops;
//! * an **encrypted vault file** - ChaCha20-Poly1305 with an Argon2id derived
//!   key, which works everywhere, including headless servers.
//!
//! [`SecretStore`] picks the best available backend and falls back
//! automatically, so callers never have to care which one is in use.

pub mod keystore;
pub mod vault;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;

use rdt_types::{
    ErrorCode, RdtError, RdtResult, Secret, SecretBackend, SecretBytes, StoredSecret,
};

/// Where a secret was actually found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolvedBackend {
    /// The value came from the OS keystore.
    OsKeystore,
    /// The value came from the encrypted vault.
    Vault,
}

/// Unified access to stored secrets.
#[derive(Debug)]
pub struct SecretStore {
    keystore: keystore::OsKeystore,
    vault: Mutex<vault::VaultHandle>,
    vault_path: PathBuf,
    default_backend: SecretBackend,
}

impl SecretStore {
    /// Opens the store.  The vault is *not* unlocked here: [`SecretStore::unlock`]
    /// must be called with the user passphrase before vault entries can be read.
    pub fn open(vault_path: PathBuf, default_backend: SecretBackend) -> RdtResult<Self> {
        Ok(Self {
            keystore: keystore::OsKeystore::new(),
            vault: Mutex::new(vault::VaultHandle::closed(vault_path.clone())),
            vault_path,
            default_backend,
        })
    }

    /// The backend new secrets are written to.
    pub fn default_backend(&self) -> SecretBackend {
        self.default_backend
    }

    /// Whether the OS keystore is usable on this machine.
    pub fn keystore_available(&self) -> bool {
        self.keystore.available()
    }

    /// Human readable description of the backend selection.
    pub fn describe(&self) -> String {
        if self.keystore.available() {
            format!("OS keystore ({}) with encrypted vault fallback", self.keystore.describe())
        } else {
            format!(
                "encrypted vault only ({})",
                self.keystore.describe()
            )
        }
    }

    /// Unlocks the encrypted vault.
    pub fn unlock(&self, passphrase: &Secret) -> RdtResult<()> {
        let mut handle = self.lock_handle();
        *handle = vault::VaultHandle::open(self.vault_path.clone(), passphrase)?;
        Ok(())
    }

    /// Locks the vault again, wiping the derived key.
    pub fn lock(&self) {
        let mut handle = self.lock_handle();
        *handle = vault::VaultHandle::closed(self.vault_path.clone());
    }

    /// Whether the vault is currently unlocked.
    pub fn is_unlocked(&self) -> bool {
        self.lock_handle().is_open()
    }

    /// Whether a vault file exists.
    pub fn vault_exists(&self) -> bool {
        self.vault_path.exists()
    }

    /// Creates a new vault protected by `passphrase`.
    pub fn create_vault(&self, passphrase: &Secret) -> RdtResult<()> {
        vault::Vault::create(&self.vault_path, passphrase)?;
        let mut handle = self.lock_handle();
        *handle = vault::VaultHandle::open(self.vault_path.clone(), passphrase)?;
        Ok(())
    }

    /// Stores `value` under `key`, returning the reference to persist.
    pub fn store(&self, key: &str, value: &Secret) -> RdtResult<StoredSecret> {
        let backend = if self.keystore_available() {
            SecretBackend::OsKeystore
        } else {
            SecretBackend::EncryptedVault
        };
        self.store_in(backend, key, value)
    }

    /// Stores `value` in a specific backend.
    pub fn store_in(
        &self,
        backend: SecretBackend,
        key: &str,
        value: &Secret,
    ) -> RdtResult<StoredSecret> {
        match backend {
            SecretBackend::OsKeystore => {
                if !self.keystore_available() {
                    return Err(RdtError::new(
                        ErrorCode::Keystore,
                        format!(
                            "the OS keystore is unavailable on this machine ({})",
                            self.keystore.describe()
                        ),
                    ));
                }
                self.keystore.set(key, value)
            }
            SecretBackend::EncryptedVault => {
                let mut handle = self.lock_handle();
                handle.set(key, value)
            }
        }?;
        Ok(StoredSecret {
            backend,
            key: key.to_owned(),
        })
    }

    /// Reads a stored secret.
    pub fn read(&self, reference: &StoredSecret) -> RdtResult<Secret> {
        match reference.backend {
            SecretBackend::OsKeystore => self.keystore.get(&reference.key),
            SecretBackend::EncryptedVault => self.lock_handle().get(&reference.key),
        }
    }

    /// Reads a stored secret, trying the other backend when the recorded one no
    /// longer has it (for example after moving profiles between machines).
    pub fn read_lenient(&self, reference: &StoredSecret) -> RdtResult<(Secret, ResolvedBackend)> {
        match self.read(reference) {
            Ok(value) => Ok((
                value,
                match reference.backend {
                    SecretBackend::OsKeystore => ResolvedBackend::OsKeystore,
                    SecretBackend::EncryptedVault => ResolvedBackend::Vault,
                },
            )),
            Err(primary) => {
                let fallback = match reference.backend {
                    SecretBackend::OsKeystore => SecretBackend::EncryptedVault,
                    SecretBackend::EncryptedVault => SecretBackend::OsKeystore,
                };
                self.read(&StoredSecret {
                    backend: fallback,
                    key: reference.key.clone(),
                })
                .map(|value| {
                    (
                        value,
                        match fallback {
                            SecretBackend::OsKeystore => ResolvedBackend::OsKeystore,
                            SecretBackend::EncryptedVault => ResolvedBackend::Vault,
                        },
                    )
                })
                .map_err(|_| primary)
            }
        }
    }

    /// Deletes a stored secret.
    pub fn delete(&self, reference: &StoredSecret) -> RdtResult<()> {
        match reference.backend {
            SecretBackend::OsKeystore => self.keystore.delete(&reference.key),
            SecretBackend::EncryptedVault => self.lock_handle().delete(&reference.key),
        }
    }

    /// Lists the keys stored in the vault (the OS keystore does not support
    /// enumeration portably).
    pub fn vault_keys(&self) -> RdtResult<Vec<String>> {
        self.lock_handle().keys()
    }

    /// Copies every vault entry into the OS keystore.
    pub fn migrate_vault_to_keystore(&self) -> RdtResult<usize> {
        if !self.keystore_available() {
            return Err(RdtError::new(
                ErrorCode::Keystore,
                "the OS keystore is unavailable on this machine",
            ));
        }
        let entries: BTreeMap<String, Secret> = self.lock_handle().entries()?;
        for (key, value) in &entries {
            self.keystore.set(key, value)?;
        }
        Ok(entries.len())
    }

    fn lock_handle(&self) -> std::sync::MutexGuard<'_, vault::VaultHandle> {
        self.vault
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Exports every vault entry as an encrypted blob (used by `rdt vault export`).
pub fn export_vault(path: &PathBuf, passphrase: &Secret) -> RdtResult<Vec<(String, SecretBytes)>> {
    let vault = vault::Vault::open(path, passphrase)?;
    Ok(vault
        .entries()?
        .into_iter()
        .map(|(key, value)| (key, SecretBytes::new(value.expose().as_bytes().to_vec())))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rdt-secrets-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create dir");
        dir.join(name)
    }

    #[test]
    fn vault_round_trip_through_the_store() {
        let path = temp_path("roundtrip.vault");
        let _ = std::fs::remove_file(&path);
        let store = SecretStore::open(path.clone(), SecretBackend::EncryptedVault).expect("open");
        store.create_vault(&Secret::new("correct horse")).expect("create");
        assert!(store.is_unlocked());

        let reference = store
            .store_in(
                SecretBackend::EncryptedVault,
                "profile/abc/password",
                &Secret::new("s3cret"),
            )
            .expect("store");
        assert_eq!(reference.backend, SecretBackend::EncryptedVault);

        let value = store.read(&reference).expect("read");
        assert_eq!(value.expose(), "s3cret");
        assert_eq!(store.vault_keys().expect("keys"), vec!["profile/abc/password"]);

        store.lock();
        assert!(!store.is_unlocked());
        assert!(store.read(&reference).is_err(), "locked vault must refuse reads");

        store.unlock(&Secret::new("correct horse")).expect("unlock");
        assert_eq!(store.read(&reference).expect("read").expose(), "s3cret");

        store.delete(&reference).expect("delete");
        assert!(store.read(&reference).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn reading_from_an_unavailable_backend_reports_a_typed_error() {
        let path = temp_path("missing.vault");
        let store = SecretStore::open(path, SecretBackend::EncryptedVault).expect("open");
        let error = store
            .read(&StoredSecret {
                backend: SecretBackend::EncryptedVault,
                key: "nope".to_owned(),
            })
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::Vault);
    }

    #[test]
    fn describe_mentions_the_available_backends() {
        let store =
            SecretStore::open(temp_path("describe.vault"), SecretBackend::EncryptedVault).expect("open");
        let description = store.describe();
        assert!(description.contains("vault"));
    }
}
