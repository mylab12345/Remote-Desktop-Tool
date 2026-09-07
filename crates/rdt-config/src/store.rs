//! On-disk configuration store with atomic, permission-hardened writes.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use rdt_types::{ErrorCode, ProfileId, RdtError, RdtResult};

use crate::migrate;
use crate::profile::ConnectionProfile;
use crate::settings::{Settings, CURRENT_SCHEMA_VERSION};

/// The whole configuration document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Config {
    /// Schema version of the document.
    #[serde(default)]
    pub schema_version: u32,
    /// Application settings.
    #[serde(default)]
    pub settings: Settings,
    /// Saved connection profiles.
    #[serde(default)]
    pub profiles: Vec<ConnectionProfile>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            schema_version: CURRENT_SCHEMA_VERSION,
            settings: Settings::default(),
            profiles: Vec::new(),
        }
    }
}

/// How the profile list is ordered in the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SortOrder {
    /// Manual order (`sort_index`, then name).
    #[default]
    Manual,
    /// Alphabetical by name.
    Name,
    /// Grouped by `group`, then alphabetical.
    Group,
    /// Most recently used first (requires session history).
    RecentlyUsed,
}

/// Errors while loading the configuration.
#[derive(Debug)]
pub enum LoadError {
    /// The file does not exist yet; the caller should create defaults.
    Missing,
    /// The file exists but could not be read or parsed.
    Failed(RdtError),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => f.write_str("no configuration file yet"),
            Self::Failed(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for LoadError {}

/// Errors while saving the configuration.
pub type SaveError = RdtError;

/// Thread safe handle on the configuration document.
///
/// The store is shared by the UI and the session manager: reads are lock free
/// for readers and every mutation goes through a single writer, so a profile
/// edited in the UI is immediately visible to a session being started.
#[derive(Debug)]
pub struct ConfigStore {
    path: PathBuf,
    inner: RwLock<Config>,
    /// True when the in-memory document differs from the file.
    dirty: RwLock<bool>,
}

impl ConfigStore {
    /// Creates an in-memory store that is not attached to a file.
    pub fn in_memory() -> Self {
        Self {
            path: PathBuf::new(),
            inner: RwLock::new(Config::default()),
            dirty: RwLock::new(false),
        }
    }

    /// Loads the document at `path`, creating defaults when it does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`LoadError::Failed`] when the file exists but is unreadable or
    /// malformed.  A missing file is not an error.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, LoadError> {
        let path = path.as_ref().to_path_buf();
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self {
                    path,
                    inner: RwLock::new(Config::default()),
                    dirty: RwLock::new(true),
                });
            }
            Err(error) => {
                return Err(LoadError::Failed(
                    RdtError::new(ErrorCode::Config, error.to_string())
                        .with_context("path", path.display().to_string()),
                ));
            }
        };

        let migrated = migrate::migrate(&text).map_err(LoadError::Failed)?;
        let config: Config = toml::from_str(&migrated).map_err(|error| {
            LoadError::Failed(
                RdtError::new(ErrorCode::Config, format!("cannot parse configuration: {error}"))
                    .with_context("path", path.display().to_string()),
            )
        })?;
        Ok(Self {
            path,
            inner: RwLock::new(config),
            dirty: RwLock::new(false),
        })
    }

    /// Loads the store from the platform default location.
    ///
    /// # Errors
    ///
    /// Propagates [`LoadError::Failed`].
    pub fn load_default() -> Result<Self, LoadError> {
        Self::load(rdt_platform::AppPaths::detect().config_file())
    }

    /// Path of the backing file (empty for an in-memory store).
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// True when there are unsaved changes.
    pub fn is_dirty(&self) -> bool {
        *self.dirty.read()
    }

    /// Current settings.
    pub fn settings(&self) -> Settings {
        self.inner.read().settings.clone()
    }

    /// Replaces the settings and marks the store dirty.
    pub fn set_settings(&self, settings: Settings) {
        self.inner.write().settings = settings;
        *self.dirty.write() = true;
    }

    /// All profiles in the requested order.
    pub fn profiles(&self, order: SortOrder) -> Vec<ConnectionProfile> {
        let mut profiles = self.inner.read().profiles.clone();
        match order {
            SortOrder::Manual => profiles.sort_by_key(|profile| (profile.sort_index, profile.name.clone())),
            SortOrder::Name => profiles.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase())),
            SortOrder::Group => profiles.sort_by(|a, b| {
                (a.group.clone().unwrap_or_default(), a.name.to_lowercase())
                    .cmp(&(b.group.clone().unwrap_or_default(), b.name.to_lowercase()))
            }),
            // Without session history the most useful stable order is by name.
            SortOrder::RecentlyUsed => profiles.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase())),
        }
        profiles
    }

    /// Finds a profile by identifier.
    pub fn find(&self, id: ProfileId) -> Option<ConnectionProfile> {
        self.inner.read().profiles.iter().find(|profile| profile.id == id).cloned()
    }

    /// Finds a profile by name (case insensitive).
    pub fn find_by_name(&self, name: &str) -> Option<ConnectionProfile> {
        self.inner
            .read()
            .profiles
            .iter()
            .find(|profile| profile.name.eq_ignore_ascii_case(name))
            .cloned()
    }

    /// Inserts a new profile.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::Config`] when the profile is invalid or its name is
    /// already used.
    pub fn add(&self, profile: ConnectionProfile) -> RdtResult<ProfileId> {
        profile.validate()?;
        let mut config = self.inner.write();
        if config
            .profiles
            .iter()
            .any(|existing| existing.name.eq_ignore_ascii_case(&profile.name))
        {
            return Err(RdtError::new(
                ErrorCode::Config,
                format!("a profile named {:?} already exists", profile.name),
            ));
        }
        let id = profile.id;
        config.profiles.push(profile);
        drop(config);
        *self.dirty.write() = true;
        Ok(id)
    }

    /// Replaces an existing profile, keeping its position in the list.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::NotFound`] when the identifier is unknown, or
    /// [`ErrorCode::Config`] when the replacement is invalid or its name
    /// collides with a different profile.
    pub fn update(&self, profile: ConnectionProfile) -> RdtResult<()> {
        profile.validate()?;
        let mut config = self.inner.write();
        let index = config
            .profiles
            .iter()
            .position(|existing| existing.id == profile.id)
            .ok_or_else(|| {
                RdtError::new(ErrorCode::NotFound, "no profile with that identifier")
                    .with_context("profile", profile.id.to_string())
            })?;
        if config.profiles.iter().enumerate().any(|(position, existing)| {
            position != index && existing.name.eq_ignore_ascii_case(&profile.name)
        }) {
            return Err(RdtError::new(
                ErrorCode::Config,
                format!("a profile named {:?} already exists", profile.name),
            ));
        }
        config.profiles[index] = profile;
        drop(config);
        *self.dirty.write() = true;
        Ok(())
    }

    /// Removes a profile.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::NotFound`] when the identifier is unknown.
    pub fn remove(&self, id: ProfileId) -> RdtResult<()> {
        let mut config = self.inner.write();
        let before = config.profiles.len();
        config.profiles.retain(|profile| profile.id != id);
        if config.profiles.len() == before {
            return Err(RdtError::new(ErrorCode::NotFound, "no profile with that identifier")
                .with_context("profile", id.to_string()));
        }
        drop(config);
        *self.dirty.write() = true;
        Ok(())
    }

    /// Serialises the document to TOML.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::Config`] if encoding fails.
    pub fn to_toml(&self) -> RdtResult<String> {
        let config = self.inner.read();
        toml::to_string_pretty(&*config).map_err(|error| {
            RdtError::new(ErrorCode::Config, format!("cannot encode configuration: {error}"))
        })
    }

    /// Writes the document atomically.
    ///
    /// The new content goes to `<path>.tmp`, is flushed and synced, has
    /// owner-only permissions applied and is then renamed over the target, so a
    /// crash cannot leave a truncated or world readable configuration.
    ///
    /// # Errors
    ///
    /// Returns [`SaveError`] describing the I/O failure.
    pub fn save(&self) -> Result<(), SaveError> {
        if self.path.as_os_str().is_empty() {
            return Err(RdtError::new(ErrorCode::Config, "the store is not attached to a file"));
        }
        let text = self.to_toml()?;
        atomic_write(&self.path, text.as_bytes())?;
        *self.dirty.write() = false;
        Ok(())
    }

    /// Reloads the document from disk, discarding local changes.
    ///
    /// # Errors
    ///
    /// Propagates load failures.
    pub fn reload(&self) -> Result<(), LoadError> {
        let reloaded = Self::load(&self.path)?;
        *self.inner.write() = reloaded.inner.read().clone();
        *self.dirty.write() = false;
        Ok(())
    }
}

/// Writes `contents` to `path` atomically with owner-only permissions.
pub(crate) fn atomic_write(path: &Path, contents: &[u8]) -> RdtResult<()> {
    let io_error = |error: std::io::Error, what: &str| {
        RdtError::new(ErrorCode::Io, format!("{what}: {error}"))
            .with_context("path", path.display().to_string())
    };

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| io_error(error, "cannot create directory"))?;
    }

    let temporary = path.with_extension("tmp");
    {
        let mut file = fs::File::create(&temporary).map_err(|error| io_error(error, "cannot create file"))?;
        rdt_platform::restrict_to_owner(&temporary).map_err(|error| {
            RdtError::new(ErrorCode::Permission, error.to_string())
                .with_context("path", temporary.display().to_string())
        })?;
        file.write_all(contents)
            .map_err(|error| io_error(error, "cannot write file"))?;
        file.sync_all().map_err(|error| io_error(error, "cannot flush file"))?;
    }
    fs::rename(&temporary, path).map_err(|error| io_error(error, "cannot replace file"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use rdt_types::Protocol;

    use super::*;

    fn sample() -> ConnectionProfile {
        ConnectionProfile::new("build", "build.example.com", 22, Protocol::Ssh)
    }

    #[test]
    fn in_memory_store_starts_with_defaults() {
        let store = ConfigStore::in_memory();
        assert!(store.profiles(SortOrder::Name).is_empty());
        assert!(store.is_dirty());
        assert_eq!(store.settings().log_level, crate::LogLevel::Info);
    }

    #[test]
    fn profiles_can_be_added_found_and_removed() {
        let store = ConfigStore::in_memory();
        let id = store.add(sample()).expect("add");
        assert!(store.find(id).is_some());
        assert!(store.find_by_name("BUILD").is_some());
        store.remove(id).expect("remove");
        assert!(store.find(id).is_none());
        assert!(store.remove(id).is_err());
    }

    #[test]
    fn duplicate_names_are_rejected() {
        let store = ConfigStore::in_memory();
        store.add(sample()).expect("add");
        assert!(store.add(sample()).is_err());
    }

    #[test]
    fn invalid_profiles_are_rejected() {
        let store = ConfigStore::in_memory();
        let mut bad = sample();
        bad.endpoint.host = String::new();
        assert!(store.add(bad).is_err());
    }

    #[test]
    fn update_keeps_the_identifier_stable() {
        let store = ConfigStore::in_memory();
        let id = store.add(sample()).expect("add");
        let mut changed = store.find(id).expect("find");
        changed.notes = "nightly builds".to_owned();
        store.update(changed).expect("update");
        assert_eq!(store.find(id).expect("find").notes, "nightly builds");
    }

    #[test]
    fn sort_orders_are_stable() {
        let store = ConfigStore::in_memory();
        let mut zeta = sample();
        zeta.name = "zeta".to_owned();
        let mut alpha = sample();
        alpha.name = "alpha".to_owned();
        alpha.group = Some("prod".to_owned());
        store.add(zeta).expect("add");
        store.add(alpha).expect("add");
        let by_name: Vec<String> = store
            .profiles(SortOrder::Name)
            .into_iter()
            .map(|profile| profile.name)
            .collect();
        assert_eq!(by_name, vec!["alpha", "zeta"]);
        assert_eq!(store.profiles(SortOrder::Group).len(), 2);
        assert_eq!(store.profiles(SortOrder::Manual).len(), 2);
        assert_eq!(store.profiles(SortOrder::RecentlyUsed).len(), 2);
    }

    #[test]
    fn round_trips_through_toml() {
        let store = ConfigStore::in_memory();
        store.add(sample()).expect("add");
        let text = store.to_toml().expect("encode");
        let parsed: Config = toml::from_str(&text).expect("decode");
        assert_eq!(parsed.profiles.len(), 1);
        assert_eq!(parsed.schema_version, CURRENT_SCHEMA_VERSION);
        assert!(!text.contains("hunter2"));
    }

    #[test]
    fn unattached_stores_refuse_to_save() {
        let store = ConfigStore::in_memory();
        let error = store.save().expect_err("must fail");
        assert_eq!(error.code(), ErrorCode::Config);
    }
}
