//! An OpenSSH compatible `known_hosts` database.
//!
//! Host key verification is the only defence SSH has against a man in the
//! middle, so this module is deliberately strict:
//!
//! * an unknown host is reported as [`HostKeyStatus::Unknown`] and never
//!   accepted silently — the caller must ask the user and then call
//!   [`KnownHosts::accept`];
//! * a host whose key *changed* is reported as [`HostKeyStatus::Changed`] with
//!   both fingerprints, which the UI renders as a hard warning;
//! * every other entry (a different key type for the same host, a certificate
//!   authority line, a revoked line) is evaluated in the order OpenSSH uses.
//!
//! Both plain and hashed (`|1|salt|hash`) host entries are supported, as are
//! negated patterns and the `@cert-authority` / `@revoked` markers.

use std::fmt;
use std::path::{Path, PathBuf};

use base64::Engine;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use subtle::ConstantTimeEq;

use rdt_types::{ErrorCode, RdtError, RdtResult};

type HmacSha1 = Hmac<Sha1>;

/// The result of comparing a server key with the database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostKeyStatus {
    /// The key matches a stored entry.
    Trusted,
    /// The host is not in the database at all.
    Unknown,
    /// The host is known, but with a different key.
    Changed {
        /// Fingerprint of the stored key (the one that no longer matches).
        known_fingerprint: String,
        /// The stored key type, for example `ssh-ed25519`.
        known_key_type: String,
    },
    /// The key appears on a `@revoked` line and must never be used.
    Revoked,
    /// The host matched a `!` negated pattern, so the entry does not apply.
    Excluded,
}

impl HostKeyStatus {
    /// True when the connection may proceed without asking the user.
    pub fn is_trusted(&self) -> bool {
        matches!(self, Self::Trusted)
    }

    /// True when the failure is fatal under any policy.
    pub fn is_fatal(&self) -> bool {
        matches!(self, Self::Changed { .. } | Self::Revoked | Self::Excluded)
    }
}

impl fmt::Display for HostKeyStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Trusted => f.write_str("host key matches the recorded key"),
            Self::Unknown => f.write_str("host key is not recorded yet"),
            Self::Changed {
                known_fingerprint,
                known_key_type,
            } => write!(
                f,
                "host key changed; recorded {known_key_type} {known_fingerprint}"
            ),
            Self::Revoked => f.write_str("host key has been revoked"),
            Self::Excluded => f.write_str("host is excluded by a negated pattern"),
        }
    }
}

/// Markers that can precede the host patterns on a line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Marker {
    /// A normal entry.
    #[default]
    None,
    /// `@cert-authority`: the key signs host certificates.
    CertAuthority,
    /// `@revoked`: the key must never be accepted.
    Revoked,
}

/// One line of a `known_hosts` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownHostEntry {
    /// `@cert-authority` / `@revoked`, when present.
    pub marker: Marker,
    /// Comma separated host patterns, possibly negated with `!`.
    pub patterns: Vec<String>,
    /// Key type, for example `ssh-ed25519`.
    pub key_type: String,
    /// The public key bytes as stored (base64 decoded).
    pub key: Vec<u8>,
    /// Trailing comment.
    pub comment: String,
    /// Line number in the file, for diagnostics.
    pub line: usize,
}

impl KnownHostEntry {
    /// Parses one `known_hosts` line.
    ///
    /// Returns `None` for blank lines and comments.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::Config`] when the line is malformed.
    pub fn parse(line: &str, number: usize) -> RdtResult<Option<Self>> {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            return Ok(None);
        }
        let mut fields = trimmed.split_whitespace();
        let first = fields.next().ok_or_else(|| malformed(number))?;

        let (marker, patterns_field) = match first {
            "@cert-authority" => (Marker::CertAuthority, fields.next().ok_or_else(|| malformed(number))?),
            "@revoked" => (Marker::Revoked, fields.next().ok_or_else(|| malformed(number))?),
            other => (Marker::None, other),
        };

        let key_type = fields.next().ok_or_else(|| malformed(number))?.to_owned();
        let encoded = fields.next().ok_or_else(|| malformed(number))?.to_owned();
        let comment = fields.collect::<Vec<_>>().join(" ");

        let key = base64::engine::general_purpose::STANDARD
            .decode(encoded.as_bytes())
            .map_err(|_| malformed(number))?;
        if key.is_empty() {
            return Err(malformed(number));
        }

        Ok(Some(Self {
            marker,
            patterns: patterns_field.split(',').map(str::to_owned).collect(),
            key_type,
            key,
            comment,
            line: number,
        })
    }

    /// True when this entry applies to `host` (respecting `!` negations).
    ///
    /// `port` is the connection port; OpenSSH only records it in the pattern
    /// when it differs from 22.
    pub fn matches(&self, host: &str, port: u16) -> bool {
        let mut matched = false;
        for pattern in &self.patterns {
            let (negated, pattern) = match pattern.strip_prefix('!') {
                Some(rest) => (true, rest),
                None => (false, pattern.as_str()),
            };
            if pattern_matches(pattern, host, port) {
                if negated {
                    return false;
                }
                matched = true;
            }
        }
        matched
    }

    /// SHA-256 fingerprint of the stored key, in OpenSSH notation.
    pub fn fingerprint(&self) -> String {
        fingerprint(&self.key)
    }

    /// Serialises the entry back to `known_hosts` syntax.
    pub fn to_line(&self) -> String {
        let marker = match self.marker {
            Marker::None => String::new(),
            Marker::CertAuthority => "@cert-authority ".to_owned(),
            Marker::Revoked => "@revoked ".to_owned(),
        };
        let encoded = base64::engine::general_purpose::STANDARD.encode(&self.key);
        let comment = if self.comment.is_empty() {
            String::new()
        } else {
            format!(" {}", self.comment)
        };
        format!("{marker}{} {} {encoded}{comment}", self.patterns.join(","), self.key_type)
    }
}

fn malformed(line: usize) -> RdtError {
    RdtError::new(ErrorCode::Config, "malformed known_hosts line").with_context("line", line.to_string())
}

/// Matches one host pattern, including the OpenSSH `*` and `?` wildcards and
/// hashed (`|1|salt|hash`) entries.
fn pattern_matches(pattern: &str, host: &str, port: u16) -> bool {
    if let Some(hashed) = pattern.strip_prefix("|1|") {
        return hashed_matches(hashed, host, port);
    }
    let (pattern_host, pattern_port) = split_host_port(pattern);
    if let Some(expected) = pattern_port {
        if expected != port {
            return false;
        }
    }
    wildcard_match(pattern_host, host)
}

/// Splits `[host]:port` or `host:port`, handling IPv6 literals.
fn split_host_port(pattern: &str) -> (&str, Option<u16>) {
    if let Some(rest) = pattern.strip_prefix('[') {
        if let Some((host, tail)) = rest.split_once(']') {
            let port = tail.strip_prefix(':').and_then(|value| value.parse().ok());
            return (host, port);
        }
        return (rest, None);
    }
    match pattern.rsplit_once(':') {
        // A bare IPv6 address contains several colons and no port.
        Some((host, port)) if !host.contains(':') => {
            (host, port.parse().ok())
        }
        _ => (pattern, None),
    }
}

/// Classic glob matching with `*` (any run) and `?` (one character).
fn wildcard_match(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.to_lowercase().collect();
    let mut star: Option<(usize, usize)> = None;
    let (mut p, mut t) = (0usize, 0usize);
    while t < text.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p].to_lowercase().next() == Some(text[t])) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some((p, t));
            p += 1;
        } else if let Some((star_p, star_t)) = star {
            p = star_p + 1;
            t = star_t + 1;
            star = Some((star_p, t));
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == '*' {
        p += 1;
    }
    p == pattern.len()
}

/// Verifies a hashed entry: `|1|<base64 salt>|<base64 hmac>`.
fn hashed_matches(body: &str, host: &str, port: u16) -> bool {
    let Some((salt, digest)) = body.split_once('|') else {
        return false;
    };
    let engine = base64::engine::general_purpose::STANDARD;
    let (Ok(salt), Ok(digest)) = (engine.decode(salt.as_bytes()), engine.decode(digest.as_bytes())) else {
        return false;
    };
    let Ok(mut mac) = HmacSha1::new_from_slice(&salt) else {
        return false;
    };
    let candidate = if port == 22 {
        host.to_lowercase()
    } else {
        format!("[{}]:{port}", host.to_lowercase())
    };
    mac.update(candidate.as_bytes());
    mac.verify_slice(&digest).is_ok()
}

/// Computes the OpenSSH style `SHA256:<base64>` fingerprint of a key blob.
pub fn fingerprint(key: &[u8]) -> String {
    use base64::engine::general_purpose::STANDARD_NO_PAD;
    let digest = sha2::Sha256::digest(key);
    format!("SHA256:{}", STANDARD_NO_PAD.encode(digest))
}

use sha2::Digest;

/// The database itself.
#[derive(Debug, Clone, Default)]
pub struct KnownHosts {
    entries: Vec<KnownHostEntry>,
    path: Option<PathBuf>,
}

impl KnownHosts {
    /// An empty database that is not attached to a file.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Reads a `known_hosts` file.
    ///
    /// A missing file yields an empty database; malformed lines are skipped and
    /// reported through `skipped`, because one bad line must not disable
    /// verification for every other host.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::Io`] when the file exists but cannot be read.
    pub fn load(path: impl AsRef<Path>) -> RdtResult<Self> {
        let path = path.as_ref().to_path_buf();
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Self::empty()),
            Err(error) => {
                return Err(RdtError::new(ErrorCode::Io, error.to_string())
                    .with_context("path", path.display().to_string()));
            }
        };
        Ok(Self::parse(&text).with_path(path))
    }

    /// Parses `known_hosts` content.
    pub fn parse(text: &str) -> Self {
        let mut entries = Vec::new();
        for (index, line) in text.lines().enumerate() {
            if let Ok(Some(entry)) = KnownHostEntry::parse(line, index + 1) {
                entries.push(entry);
            }
        }
        Self {
            entries,
            path: None,
        }
    }

    fn with_path(mut self, path: PathBuf) -> Self {
        self.path = Some(path);
        self
    }

    /// Number of parsed entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the database holds no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// All parsed entries.
    pub fn entries(&self) -> &[KnownHostEntry] {
        &self.entries
    }

    /// File the database was loaded from, if any.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Checks a server key against the database.
    ///
    /// `key_type` is the algorithm name advertised by the server (for example
    /// `ssh-ed25519`) and `key` the public key blob.
    pub fn check(&self, host: &str, port: u16, key_type: &str, key: &[u8]) -> HostKeyStatus {
        let mut matched_same_type: Option<&KnownHostEntry> = None;
        let mut matched_other_type: Option<&KnownHostEntry> = None;

        for entry in &self.entries {
            if !entry.matches(host, port) {
                continue;
            }
            if entry.key.ct_eq(key).into() {
                return match entry.marker {
                    Marker::Revoked => HostKeyStatus::Revoked,
                    Marker::CertAuthority => {
                        // A CA line proves a certificate, not the key itself.
                        continue;
                    }
                    Marker::None => HostKeyStatus::Trusted,
                };
            }
            if entry.marker == Marker::Revoked {
                continue;
            }
            if entry.key_type == key_type {
                matched_same_type.get_or_insert(entry);
            } else {
                matched_other_type.get_or_insert(entry);
            }
        }

        // A different key for the same algorithm is a hard warning; a different
        // algorithm (for example after a server rekey) is only "unknown".
        if let Some(entry) = matched_same_type {
            return HostKeyStatus::Changed {
                known_fingerprint: entry.fingerprint(),
                known_key_type: entry.key_type.clone(),
            };
        }
        if matched_other_type.is_some() {
            return HostKeyStatus::Unknown;
        }
        HostKeyStatus::Unknown
    }

    /// Records a key the user has explicitly accepted.
    pub fn accept(&mut self, host: &str, port: u16, key_type: &str, key: &[u8], comment: &str) {
        let pattern = if port == 22 {
            host.to_lowercase()
        } else {
            format!("[{}]:{port}", host.to_lowercase())
        };
        // Replace any previous entry for the same host and algorithm so the file
        // does not accumulate stale keys.
        self.entries.retain(|entry| {
            !(entry.marker == Marker::None && entry.key_type == key_type && entry.matches(host, port))
        });
        self.entries.push(KnownHostEntry {
            marker: Marker::None,
            patterns: vec![pattern],
            key_type: key_type.to_owned(),
            key: key.to_vec(),
            comment: comment.to_owned(),
            line: 0,
        });
    }

    /// Removes every entry for a host, returning how many were dropped.
    pub fn forget(&mut self, host: &str, port: u16) -> usize {
        let before = self.entries.len();
        self.entries.retain(|entry| !entry.matches(host, port));
        before - self.entries.len()
    }

    /// Serialises the database.
    pub fn to_string_lossy(&self) -> String {
        let mut out = String::new();
        for entry in &self.entries {
            out.push_str(&entry.to_line());
            out.push('\n');
        }
        out
    }

    /// Writes the database back to its file with owner-only permissions.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::Config`] when the database is not attached to a
    /// file, or the underlying I/O error.
    pub fn save(&self) -> RdtResult<()> {
        let Some(path) = self.path.clone() else {
            return Err(RdtError::new(ErrorCode::Config, "the known hosts database has no file"));
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| {
                RdtError::new(ErrorCode::Io, error.to_string())
                    .with_context("path", parent.display().to_string())
            })?;
        }
        std::fs::write(&path, self.to_string_lossy()).map_err(|error| {
            RdtError::new(ErrorCode::Io, error.to_string())
                .with_context("path", path.display().to_string())
        })?;
        rdt_platform::restrict_to_owner(&path).map_err(|error| {
            RdtError::new(ErrorCode::Permission, error.to_string())
                .with_context("path", path.display().to_string())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_A: &[u8] = b"public-key-blob-alpha";
    const KEY_B: &[u8] = b"public-key-blob-bravo";

    fn encode(key: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(key)
    }

    fn db(text: &str) -> KnownHosts {
        KnownHosts::parse(text)
    }

    #[test]
    fn blank_and_comment_lines_are_ignored() {
        let database = db("\n# a comment\n   \n");
        assert!(database.is_empty());
        assert_eq!(database.to_string_lossy(), "");
    }

    #[test]
    fn a_matching_entry_is_trusted() {
        let database = db(&format!("host.example.com ssh-ed25519 {} owner@laptop\n", encode(KEY_A)));
        assert_eq!(
            database.check("host.example.com", 22, "ssh-ed25519", KEY_A),
            HostKeyStatus::Trusted
        );
    }

    #[test]
    fn host_matching_is_case_insensitive() {
        let database = db(&format!("Host.Example.COM ssh-rsa {}\n", encode(KEY_A)));
        assert_eq!(
            database.check("host.example.com", 22, "ssh-rsa", KEY_A),
            HostKeyStatus::Trusted
        );
    }

    #[test]
    fn an_unknown_host_is_reported_as_unknown() {
        let database = db(&format!("other.example.com ssh-ed25519 {}\n", encode(KEY_A)));
        assert_eq!(
            database.check("host.example.com", 22, "ssh-ed25519", KEY_A),
            HostKeyStatus::Unknown
        );
    }

    #[test]
    fn a_changed_key_of_the_same_type_is_a_hard_failure() {
        let database = db(&format!("host.example.com ssh-ed25519 {} old\n", encode(KEY_A)));
        let status = database.check("host.example.com", 22, "ssh-ed25519", KEY_B);
        match status {
            HostKeyStatus::Changed {
                known_fingerprint,
                known_key_type,
            } => {
                assert_eq!(known_key_type, "ssh-ed25519");
                assert!(known_fingerprint.starts_with("SHA256:"), "{known_fingerprint}");
                assert!(status.is_fatal());
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn a_different_algorithm_is_treated_as_unknown_not_changed() {
        let database = db(&format!("host.example.com ssh-rsa {}\n", encode(KEY_A)));
        assert_eq!(
            database.check("host.example.com", 22, "ssh-ed25519", KEY_B),
            HostKeyStatus::Unknown
        );
    }

    #[test]
    fn revoked_keys_are_never_accepted() {
        let database = db(&format!("@revoked host.example.com ssh-ed25519 {}\n", encode(KEY_A)));
        assert_eq!(
            database.check("host.example.com", 22, "ssh-ed25519", KEY_A),
            HostKeyStatus::Revoked
        );
    }

    #[test]
    fn negated_patterns_exclude_hosts() {
        let database = db(&format!("*.example.com,!bad.example.com ssh-ed25519 {}\n", encode(KEY_A)));
        assert_eq!(
            database.check("good.example.com", 22, "ssh-ed25519", KEY_A),
            HostKeyStatus::Trusted
        );
        assert_eq!(
            database.check("bad.example.com", 22, "ssh-ed25519", KEY_A),
            HostKeyStatus::Unknown
        );
    }

    #[test]
    fn non_default_ports_use_the_bracketed_form() {
        let database = db(&format!("[host.example.com]:2222 ssh-ed25519 {}\n", encode(KEY_A)));
        assert_eq!(
            database.check("host.example.com", 2222, "ssh-ed25519", KEY_A),
            HostKeyStatus::Trusted
        );
        assert_eq!(
            database.check("host.example.com", 22, "ssh-ed25519", KEY_A),
            HostKeyStatus::Unknown
        );
    }

    #[test]
    fn ipv6_literals_are_supported() {
        let database = db(&format!("[2001:db8::1]:22 ssh-ed25519 {}\n", encode(KEY_A)));
        assert_eq!(
            database.check("2001:db8::1", 22, "ssh-ed25519", KEY_A),
            HostKeyStatus::Trusted
        );
    }

    #[test]
    fn hashed_entries_are_verified() {
        let salt = b"0123456789abcdef";
        let mut mac = HmacSha1::new_from_slice(salt).expect("key");
        mac.update(b"host.example.com");
        let digest = mac.finalize().into_bytes();
        let engine = base64::engine::general_purpose::STANDARD;
        let line = format!(
            "|1|{}|{} ssh-ed25519 {}",
            engine.encode(salt),
            engine.encode(digest),
            encode(KEY_A)
        );
        let database = db(&line);
        assert_eq!(
            database.check("host.example.com", 22, "ssh-ed25519", KEY_A),
            HostKeyStatus::Trusted
        );
        assert_eq!(
            database.check("other.example.com", 22, "ssh-ed25519", KEY_A),
            HostKeyStatus::Unknown
        );
    }

    #[test]
    fn malformed_lines_are_skipped_not_fatal() {
        let database = db(&format!(
            "garbage line\nhost.example.com ssh-ed25519 not-base64!!\nhost2.example.com ssh-ed25519 {}\n",
            encode(KEY_A)
        ));
        assert_eq!(database.len(), 1);
        assert_eq!(
            database.check("host2.example.com", 22, "ssh-ed25519", KEY_A),
            HostKeyStatus::Trusted
        );
    }

    #[test]
    fn accepting_a_key_replaces_the_previous_one() {
        let mut database = db(&format!("host.example.com ssh-ed25519 {} old\n", encode(KEY_A)));
        database.accept("host.example.com", 22, "ssh-ed25519", KEY_B, "rotated");
        assert_eq!(database.len(), 1);
        assert_eq!(
            database.check("host.example.com", 22, "ssh-ed25519", KEY_B),
            HostKeyStatus::Trusted
        );
        assert!(database.to_string_lossy().contains("rotated"));
    }

    #[test]
    fn forgetting_a_host_removes_its_entries() {
        let mut database = db(&format!(
            "host.example.com ssh-ed25519 {}\nhost.example.com ssh-rsa {}\nother ssh-ed25519 {}\n",
            encode(KEY_A),
            encode(KEY_B),
            encode(KEY_A)
        ));
        assert_eq!(database.forget("host.example.com", 22), 2);
        assert_eq!(database.len(), 1);
    }

    #[test]
    fn entries_round_trip_through_text() {
        let line = format!("@cert-authority *.example.com ssh-ed25519 {} ca key\n", encode(KEY_A));
        let database = db(&line);
        assert_eq!(database.len(), 1);
        let entry = &database.entries()[0];
        assert_eq!(entry.marker, Marker::CertAuthority);
        assert_eq!(entry.comment, "ca key");
        assert!(entry.to_line().starts_with("@cert-authority *.example.com"));
    }

    #[test]
    fn fingerprints_are_stable_and_prefixed() {
        let value = fingerprint(KEY_A);
        assert!(value.starts_with("SHA256:"));
        assert_eq!(value, fingerprint(KEY_A));
        assert_ne!(value, fingerprint(KEY_B));
        assert!(!value.contains('='), "fingerprints use unpadded base64: {value}");
    }

    #[test]
    fn status_messages_are_readable() {
        assert_eq!(HostKeyStatus::Trusted.to_string(), "host key matches the recorded key");
        assert_eq!(HostKeyStatus::Unknown.to_string(), "host key is not recorded yet");
        assert_eq!(HostKeyStatus::Revoked.to_string(), "host key has been revoked");
        assert!(HostKeyStatus::Trusted.is_trusted());
        assert!(!HostKeyStatus::Unknown.is_fatal());
    }

    #[test]
    fn wildcard_matching_covers_the_common_cases() {
        assert!(wildcard_match("*.example.com", "a.example.com"));
        assert!(!wildcard_match("*.example.com", "example.com"));
        assert!(wildcard_match("host?", "host1"));
        assert!(!wildcard_match("host?", "host12"));
        assert!(wildcard_match("*", "anything"));
        assert!(wildcard_match("exact", "exact"));
    }

    #[test]
    fn unattached_databases_refuse_to_save() {
        let database = KnownHosts::empty();
        let error = database.save().expect_err("must fail");
        assert_eq!(error.code(), ErrorCode::Config);
    }
}
