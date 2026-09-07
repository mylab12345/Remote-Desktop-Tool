//! Secret redaction helpers.
//!
//! Redaction is applied in two places: explicitly by code that formats
//! potentially sensitive values, and defensively by the logging layer, which
//! scrubs every line it writes for both known secret values and for the usual
//! `key=value` shapes used by tools such as OpenSSH and libcurl.

/// Marker written in place of a secret.
pub const REDACTED: &str = "<redacted>";

/// Field names whose values are treated as secret by [`Redactor`].
const SENSITIVE_KEYS: &[&str] = &[
    "password",
    "passwd",
    "passphrase",
    "pass",
    "secret",
    "token",
    "apikey",
    "api_key",
    "authorization",
    "auth",
    "credential",
    "credentials",
    "private_key",
    "privatekey",
    "otp",
    "pin",
];

/// Replaces every occurrence of `secret` in `text` with [`REDACTED`].
pub fn redact_secret_in(text: &str, secret: &str) -> String {
    if secret.is_empty() {
        return text.to_owned();
    }
    text.replace(secret, REDACTED)
}

/// Streaming redactor that scrubs known secret values and `key=value` pairs
/// whose key looks sensitive.
#[derive(Debug, Clone, Default)]
pub struct Redactor {
    secrets: Vec<String>,
}

impl Redactor {
    /// An empty redactor that only scrubs sensitive looking `key=value` pairs.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a literal value that must never appear in output.
    ///
    /// Short values (< 4 characters) are ignored on purpose: scrubbing them
    /// would mangle unrelated text (for example the word "the" for a 3 letter
    /// password) while providing no real protection.
    pub fn with_secret(mut self, secret: &str) -> Self {
        if secret.len() >= 4 && !self.secrets.iter().any(|known| known == secret) {
            self.secrets.push(secret.to_owned());
        }
        self
    }

    /// Number of registered literal secrets.
    pub fn secret_count(&self) -> usize {
        self.secrets.len()
    }

    /// Returns `text` with every known secret and sensitive value removed.
    pub fn redact(&self, text: &str) -> String {
        let mut output = text.to_owned();
        for secret in &self.secrets {
            if output.contains(secret.as_str()) {
                output = output.replace(secret.as_str(), REDACTED);
            }
        }
        scrub_sensitive_pairs(&output)
    }

    /// Convenience wrapper: returns `value` or [`REDACTED`] when it is secret.
    pub fn show(&self, value: &str, is_secret: bool) -> String {
        if is_secret {
            REDACTED.to_owned()
        } else {
            self.redact(value)
        }
    }
}

/// Rewrites `key=value` / `key: value` pairs with a sensitive looking key.
///
/// The scan is deliberately conservative: it only rewrites a run of
/// non-whitespace characters that follows `=` or `: ` directly.
fn scrub_sensitive_pairs(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut output = String::with_capacity(text.len());
    let mut index = 0usize;
    while index < chars.len() {
        let separator_len = if chars[index] == '=' {
            1
        } else if chars[index] == ':' && chars.get(index + 1) == Some(&' ') {
            2
        } else {
            0
        };
        if separator_len == 0 {
            output.push(chars[index]);
            index += 1;
            continue;
        }

        // Find the start of the key: walk back over identifier characters.
        let mut start = index;
        while start > 0 {
            let previous = chars[start - 1];
            if previous.is_ascii_alphanumeric() || previous == '_' || previous == '-' {
                start -= 1;
            } else {
                break;
            }
        }
        let key: String = chars[start..index].iter().collect();
        let sensitive = SENSITIVE_KEYS
            .iter()
            .any(|candidate| key.eq_ignore_ascii_case(candidate) || key.ends_with(candidate));

        // The key characters were already copied by the scan above, so drop
        // them from the output before re-emitting the key verbatim.
        for _ in start..index {
            output.pop();
        }
        output.extend(&chars[start..index]);
        output.extend(&chars[index..index + separator_len]);
        index += separator_len;

        // Copy (or replace) the value.  A header style separator (`Key: value`)
        // takes the rest of the line, because headers such as `Authorization`
        // carry multi-word credentials ("Bearer <token>"); a `Key=value` pair
        // stops at the next delimiter.
        let value_start = index;
        let header_style = separator_len == 2;
        while index < chars.len() {
            let current = chars[index];
            if header_style {
                if current == '\n' {
                    break;
                }
            } else if current.is_whitespace() || current == ',' || current == ';' {
                break;
            }
            index += 1;
        }
        if sensitive && index > value_start {
            output.push_str(REDACTED);
        } else {
            output.extend(&chars[value_start..index]);
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_secrets_are_scrubbed() {
        let redactor = Redactor::new().with_secret("Sup3rSecret!");
        let line = "user auth ok with Sup3rSecret! after 3 tries";
        let scrubbed = redactor.redact(line);
        assert!(!scrubbed.contains("Sup3rSecret!"));
        assert!(scrubbed.contains(REDACTED));
    }

    #[test]
    fn sensitive_pairs_are_scrubbed() {
        let redactor = Redactor::new();
        assert_eq!(
            redactor.redact("password=hunter2 user=root"),
            format!("password={REDACTED} user=root")
        );
        assert_eq!(
            redactor.redact("Authorization: Bearer abc.def"),
            format!("Authorization: {REDACTED}")
        );
        assert_eq!(
            redactor.redact("passphrase: 'x y'"),
            format!("passphrase: {REDACTED}")
        );
    }

    #[test]
    fn innocuous_pairs_are_untouched() {
        let redactor = Redactor::new();
        let line = "host=db01 port=22 user=alice";
        assert_eq!(redactor.redact(line), line);
    }

    #[test]
    fn very_short_secrets_are_ignored() {
        let redactor = Redactor::new().with_secret("abc");
        assert_eq!(redactor.secret_count(), 0);
    }

    #[test]
    fn redact_secret_in_handles_empty_secret() {
        assert_eq!(redact_secret_in("keep me", ""), "keep me");
        assert_eq!(
            redact_secret_in("a b a", "a"),
            format!("{REDACTED} b {REDACTED}")
        );
    }
}
