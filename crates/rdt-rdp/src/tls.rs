//! TLS certificate validation and pinning for RDP.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use sha2::Digest;

use rdt_types::{CertPolicy, ErrorCode, RdtError, RdtResult};

/// What RDT decided about a server certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateDecision {
    /// The certificate chains to a trusted root.
    VerifiedByCa,
    /// The certificate matched a recorded fingerprint.
    Pinned {
        /// `sha256:<hex>` of the presented certificate.
        fingerprint: String,
    },
    /// The certificate was recorded on first use.
    RecordedOnFirstUse {
        /// `sha256:<hex>` of the presented certificate.
        fingerprint: String,
    },
}

/// A set of pinned host fingerprints, persisted as JSON.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PinnedCertificates {
    entries: HashMap<String, String>,
    path: Option<PathBuf>,
}

impl PinnedCertificates {
    /// An empty set that is not attached to a file.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Loads the pin store.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::Io`] when the file exists but cannot be read.
    pub fn load(path: impl AsRef<Path>) -> RdtResult<Self> {
        let path = path.as_ref().to_path_buf();
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::empty());
            }
            Err(error) => {
                return Err(RdtError::new(ErrorCode::Io, error.to_string())
                    .with_context("path", path.display().to_string()));
            }
        };
        let entries: HashMap<String, String> = serde_json::from_str(&text).map_err(|error| {
            RdtError::new(ErrorCode::Config, format!("cannot parse the pin store: {error}"))
                .with_context("path", path.display().to_string())
        })?;
        Ok(Self {
            entries,
            path: Some(path),
        })
    }

    /// Number of recorded pins.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no pins are recorded.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Looks up a host.
    pub fn get(&self, host: &str) -> Option<&str> {
        self.entries.get(&host.to_lowercase()).map(String::as_str)
    }

    /// Records or replaces a pin.
    pub fn pin(&mut self, host: &str, fingerprint: &str) {
        self.entries.insert(host.to_lowercase(), fingerprint.to_owned());
    }

    /// Removes a pin, returning whether one existed.
    pub fn unpin(&mut self, host: &str) -> bool {
        self.entries.remove(&host.to_lowercase()).is_some()
    }

    /// Saves the pin store with owner-only permissions.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::Config`] when the store is not attached to a file.
    pub fn save(&self) -> RdtResult<()> {
        let Some(path) = self.path.clone() else {
            return Err(RdtError::new(ErrorCode::Config, "the pin store has no file"));
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| {
                RdtError::new(ErrorCode::Io, error.to_string())
                    .with_context("path", parent.display().to_string())
            })?;
        }
        let text = serde_json::to_string_pretty(&self.entries).map_err(|error| {
            RdtError::new(ErrorCode::Config, format!("cannot encode the pin store: {error}"))
        })?;
        std::fs::write(&path, text).map_err(|error| {
            RdtError::new(ErrorCode::Io, error.to_string())
                .with_context("path", path.display().to_string())
        })?;
        rdt_platform::restrict_to_owner(&path).map_err(|error| {
            RdtError::new(ErrorCode::Permission, error.to_string())
                .with_context("path", path.display().to_string())
        })
    }
}

/// Applies the certificate policy to a presented certificate.
pub struct CertificateVerifier {
    policy: CertPolicy,
    pins: PinnedCertificates,
    host: String,
}

impl CertificateVerifier {
    /// Creates a verifier for one host.
    pub fn new(host: String, policy: CertPolicy, pins: PinnedCertificates) -> Self {
        Self { policy, pins, host }
    }

    /// The policy in force.
    pub fn policy(&self) -> CertPolicy {
        self.policy
    }

    /// The pin store.
    pub fn pins(&self) -> &PinnedCertificates {
        &self.pins
    }

    /// Evaluates a DER encoded leaf certificate.
    ///
    /// `ca_verified` reports whether the chain already validated against a
    /// trusted root; the policy decides what to do when it did not.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::Tls`] when the policy refuses the certificate.
    pub fn verify(&mut self, der: &[u8], ca_verified: bool) -> RdtResult<CertificateDecision> {
        let fingerprint = sha256_fingerprint(der);
        if ca_verified {
            return Ok(CertificateDecision::VerifiedByCa);
        }
        match self.policy {
            CertPolicy::Verify => Err(RdtError::new(
                ErrorCode::Tls,
                format!(
                    "the certificate presented by {} is not signed by a trusted authority",
                    self.host
                ),
            )
            .with_context("fingerprint", fingerprint.clone())),
            CertPolicy::VerifyOrPinned => match self.pins.get(&self.host) {
                Some(expected) if expected == fingerprint => {
                    Ok(CertificateDecision::Pinned { fingerprint })
                }
                Some(expected) => Err(RdtError::new(
                    ErrorCode::Tls,
                    format!(
                        "the certificate for {} changed; pinned {expected}, presented {fingerprint}",
                        self.host
                    ),
                )),
                None => Err(RdtError::new(
                    ErrorCode::Tls,
                    format!("no trusted certificate is recorded for {}", self.host),
                )
                .with_context("fingerprint", fingerprint)),
            },
            CertPolicy::TrustOnFirstUse => match self.pins.get(&self.host) {
                Some(expected) if expected == fingerprint => {
                    Ok(CertificateDecision::Pinned { fingerprint })
                }
                Some(expected) => Err(RdtError::new(
                    ErrorCode::Tls,
                    format!(
                        "the certificate for {} changed since it was first trusted (pinned {expected})",
                        self.host
                    ),
                )),
                None => {
                    self.pins.pin(&self.host, &fingerprint);
                    self.pins.save()?;
                    Ok(CertificateDecision::RecordedOnFirstUse { fingerprint })
                }
            },
        }
    }
}

/// Computes the `sha256:<hex>` fingerprint of a DER certificate.
pub fn sha256_fingerprint(der: &[u8]) -> String {
    format!("sha256:{}", hex::encode(sha2::Sha256::digest(der)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CERT_A: &[u8] = b"certificate-bytes-alpha";
    const CERT_B: &[u8] = b"certificate-bytes-bravo";

    #[test]
    fn a_valid_chain_is_accepted_under_every_policy() {
        for policy in [CertPolicy::Verify, CertPolicy::VerifyOrPinned, CertPolicy::TrustOnFirstUse] {
            let mut verifier = CertificateVerifier::new("host".to_owned(), policy, PinnedCertificates::empty());
            assert_eq!(verifier.verify(CERT_A, true).expect("verify"), CertificateDecision::VerifiedByCa);
        }
    }

    #[test]
    fn verify_policy_refuses_untrusted_certificates() {
        let mut verifier = CertificateVerifier::new("host".to_owned(), CertPolicy::Verify, PinnedCertificates::empty());
        let error = verifier.verify(CERT_A, false).expect_err("must fail");
        assert_eq!(error.code(), ErrorCode::Tls);
    }

    #[test]
    fn pinned_certificates_are_accepted() {
        let mut pins = PinnedCertificates::empty();
        pins.pin("host", &sha256_fingerprint(CERT_A));
        let mut verifier = CertificateVerifier::new("host".to_owned(), CertPolicy::VerifyOrPinned, pins);
        let decision = verifier.verify(CERT_A, false).expect("verify");
        assert!(matches!(decision, CertificateDecision::Pinned { .. }));
    }

    #[test]
    fn a_changed_certificate_is_a_hard_failure() {
        let mut pins = PinnedCertificates::empty();
        pins.pin("host", &sha256_fingerprint(CERT_A));
        for policy in [CertPolicy::VerifyOrPinned, CertPolicy::TrustOnFirstUse] {
            let mut verifier = CertificateVerifier::new("host".to_owned(), policy, pins.clone());
            let error = verifier.verify(CERT_B, false).expect_err("must fail");
            assert_eq!(error.code(), ErrorCode::Tls);
            assert!(error.to_string().contains("changed"));
        }
    }

    #[test]
    fn trust_on_first_use_records_then_enforces() {
        let mut verifier =
            CertificateVerifier::new("host".to_owned(), CertPolicy::TrustOnFirstUse, PinnedCertificates::empty());
        let decision = verifier.verify(CERT_A, false).expect("first use");
        assert!(matches!(decision, CertificateDecision::RecordedOnFirstUse { .. }));
        assert_eq!(verifier.pins().get("host"), Some(sha256_fingerprint(CERT_A).as_str()));
        // A second, different certificate is now refused.
        assert!(verifier.verify(CERT_B, false).is_err());
    }

    #[test]
    fn fingerprints_are_stable_hex() {
        let value = sha256_fingerprint(CERT_A);
        assert!(value.starts_with("sha256:"));
        assert_eq!(value.len(), "sha256:".len() + 64);
        assert_eq!(value, sha256_fingerprint(CERT_A));
        assert_ne!(value, sha256_fingerprint(CERT_B));
    }

    #[test]
    fn pins_are_case_insensitive_and_removable() {
        let mut pins = PinnedCertificates::empty();
        pins.pin("Host.Example.COM", "sha256:aa");
        assert_eq!(pins.get("host.example.com"), Some("sha256:aa"));
        assert_eq!(pins.len(), 1);
        assert!(pins.unpin("HOST.example.com"));
        assert!(pins.is_empty());
        assert!(!pins.unpin("host.example.com"));
    }

    #[test]
    fn unattached_pin_stores_refuse_to_save() {
        let pins = PinnedCertificates::empty();
        let error = pins.save().expect_err("must fail");
        assert_eq!(error.code(), ErrorCode::Config);
    }
}
