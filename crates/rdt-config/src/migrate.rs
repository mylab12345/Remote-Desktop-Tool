//! Forward migration of the configuration document.
//!
//! Every release that changes the on-disk layout adds a step here.  Migration is
//! one directional (old to new) and always ends at
//! [`CURRENT_SCHEMA_VERSION`]; a document from a *newer* version is refused
//! rather than silently downgraded, because writing it back would lose fields.

use rdt_types::{ErrorCode, RdtError, RdtResult};

use crate::settings::CURRENT_SCHEMA_VERSION;

/// Errors specific to migration.
pub type MigrateError = RdtError;

/// The raw shape of the document, used only for version detection.
#[derive(Debug, serde::Deserialize)]
struct VersionProbe {
    #[serde(default)]
    schema_version: u32,
}

/// Returns the schema version declared by a document, defaulting to 0.
pub fn document_version(text: &str) -> u32 {
    toml::from_str::<VersionProbe>(text)
        .map(|probe| probe.schema_version)
        .unwrap_or(0)
}

/// Brings a document up to the current schema version.
///
/// Returns the document text unchanged when it is already current.
///
/// # Errors
///
/// * [`ErrorCode::Config`] when the document cannot be parsed.
/// * [`ErrorCode::Unsupported`] when it was written by a newer version.
pub fn migrate(text: &str) -> RdtResult<String> {
    let version = document_version(text);
    if version == CURRENT_SCHEMA_VERSION {
        return Ok(text.to_owned());
    }
    if version > CURRENT_SCHEMA_VERSION {
        return Err(RdtError::new(
            ErrorCode::Unsupported,
            format!(
                "configuration was written by schema version {version}; this build understands up to {CURRENT_SCHEMA_VERSION}"
            ),
        ));
    }

    let mut value: toml::Value = toml::from_str(text).map_err(|error| {
        RdtError::new(ErrorCode::Config, format!("cannot parse configuration: {error}"))
    })?;

    // Version 0 predates the explicit version field: it is the same document
    // with the defaults filled in by serde, so it only needs stamping.
    if let toml::Value::Table(table) = &mut value {
        table.insert("schema_version".to_owned(), toml::Value::Integer(i64::from(CURRENT_SCHEMA_VERSION)));
    }

    toml::to_string(&value).map_err(|error| {
        RdtError::new(ErrorCode::Config, format!("cannot re-encode configuration: {error}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_documents_pass_through_unchanged() {
        let text = format!("schema_version = {CURRENT_SCHEMA_VERSION}\n");
        assert_eq!(migrate(&text).expect("migrate"), text);
    }

    #[test]
    fn unversioned_documents_are_stamped() {
        let migrated = migrate("[settings]\nlog_level = \"debug\"\n").expect("migrate");
        assert_eq!(document_version(&migrated), CURRENT_SCHEMA_VERSION);
        assert!(migrated.contains("log_level"));
    }

    #[test]
    fn newer_documents_are_refused() {
        let error = migrate("schema_version = 99\n").expect_err("must be refused");
        assert_eq!(error.code(), ErrorCode::Unsupported);
    }

    #[test]
    fn broken_documents_report_a_config_error() {
        let error = migrate("this is not toml [[[\n").expect_err("must fail");
        assert_eq!(error.code(), ErrorCode::Config);
    }

    #[test]
    fn version_probe_tolerates_missing_fields() {
        assert_eq!(document_version(""), 0);
        assert_eq!(document_version("schema_version = 3\n"), 3);
    }
}
