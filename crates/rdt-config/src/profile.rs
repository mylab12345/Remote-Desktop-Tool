//! The saved description of a remote endpoint: a *profile*.
//!
//! A profile holds everything needed to connect except secrets, which are
//! referenced indirectly through [`CredentialSource`].

use serde::{Deserialize, Serialize};

use rdt_types::{
    AuthMethod, CertPolicy, Endpoint, HostKeyPolicy, ProfileId, Protocol, RdpOptions, SshOptions,
};

/// A stored connection profile.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConnectionProfile {
    /// Stable identifier, generated when the profile is created.
    pub id: ProfileId,
    /// Human readable name shown in the UI.  Unique inside a store.
    pub name: String,
    /// Optional group used to organise the profile list (for example `prod/web`).
    #[serde(default)]
    pub group: Option<String>,
    /// Where to connect.
    pub endpoint: Endpoint,
    /// Which protocol to speak.
    pub protocol: Protocol,
    /// How to authenticate.
    #[serde(default)]
    pub auth: AuthMethod,
    /// Optional jump host (`user@host[:port]`).
    #[serde(default)]
    pub jump_host: Option<Endpoint>,
    /// SSH specific options (ignored for RDP).
    #[serde(default)]
    pub ssh: SshOptions,
    /// RDP specific options (ignored for SSH).
    #[serde(default)]
    pub rdp: RdpOptions,
    /// Free form notes, never shown to the remote side.
    #[serde(default)]
    pub notes: String,
    /// Tags used for filtering.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Connect automatically when the application starts.
    #[serde(default)]
    pub connect_on_startup: bool,
    /// Monotonic counter used to keep the list order stable across saves.
    #[serde(default)]
    pub sort_index: u32,
}

impl ConnectionProfile {
    /// Creates a profile with a fresh identifier and protocol defaults.
    pub fn new(name: impl Into<String>, host: impl Into<String>, port: u16, protocol: Protocol) -> Self {
        let ssh = SshOptions::default();
        let rdp = RdpOptions::default();
        Self {
            id: ProfileId::new(),
            name: name.into(),
            group: None,
            endpoint: Endpoint {
                host: host.into(),
                port,
            },
            protocol,
            auth: AuthMethod::default(),
            jump_host: None,
            ssh,
            rdp,
            notes: String::new(),
            tags: Vec::new(),
            connect_on_startup: false,
            sort_index: 0,
        }
    }

    /// The `host:port` pair as shown in the UI.
    pub fn address(&self) -> String {
        format!("{}:{}", self.endpoint.host, self.endpoint.port)
    }

    /// The default port for a protocol.
    pub fn default_port(protocol: Protocol) -> u16 {
        match protocol {
            Protocol::Ssh => 22,
            Protocol::Rdp => 3389,
        }
    }

    /// True when the profile would be accepted by [`Self::validate`].
    pub fn is_valid(&self) -> bool {
        self.validate().is_ok()
    }

    /// Checks the profile before it is saved or used.
    ///
    /// # Errors
    ///
    /// Returns [`rdt_types::ErrorCode::Config`] describing the first problem.
    pub fn validate(&self) -> rdt_types::RdtResult<()> {
        use rdt_types::{ErrorCode, RdtError};

        let fail = |message: &str| {
            Err(RdtError::new(ErrorCode::Config, message).with_context("profile", self.name.clone()))
        };

        if self.name.trim().is_empty() {
            return fail("profile name must not be empty");
        }
        if self.name.len() > 120 {
            return fail("profile name is longer than 120 characters");
        }
        if self.endpoint.host.trim().is_empty() {
            return fail("host must not be empty");
        }
        if self.endpoint.port == 0 {
            return fail("port must not be zero");
        }
        if self.endpoint.host.chars().any(char::is_whitespace) {
            return fail("host must not contain whitespace");
        }
        for tag in &self.tags {
            if tag.trim().is_empty() {
                return fail("tags must not be empty");
            }
        }
        // Security invariant: never accept a policy that trusts blindly.
        if matches!(self.ssh.host_key_policy, HostKeyPolicy::Strict) == false
            && self.ssh.host_key_policy.auto_accepts_unknown()
        {
            return fail("host key policy must not auto-accept unknown keys");
        }
        if matches!(self.rdp.cert_policy, CertPolicy::Verify | CertPolicy::VerifyOrPinned | CertPolicy::TrustOnFirstUse)
            == false
        {
            return fail("certificate policy must verify the server certificate");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use rdt_types::CredentialSource;

    use super::*;

    fn profile() -> ConnectionProfile {
        ConnectionProfile::new("build", "build.example.com", 22, Protocol::Ssh)
    }

    #[test]
    fn new_profiles_are_valid_and_identified() {
        let profile = profile();
        assert!(profile.is_valid());
        assert_eq!(profile.address(), "build.example.com:22");
        assert_ne!(profile.id, ProfileId::new());
    }

    #[test]
    fn default_ports_follow_the_protocol() {
        assert_eq!(ConnectionProfile::default_port(Protocol::Ssh), 22);
        assert_eq!(ConnectionProfile::default_port(Protocol::Rdp), 3389);
    }

    #[test]
    fn invalid_profiles_are_rejected() {
        let mut bad = profile();
        bad.name = "   ".to_owned();
        assert!(bad.validate().is_err());

        let mut bad = profile();
        bad.endpoint.host = " ".to_owned();
        assert!(bad.validate().is_err());

        let mut bad = profile();
        bad.endpoint.port = 0;
        assert!(bad.validate().is_err());

        let mut bad = profile();
        bad.endpoint.host = "two words".to_owned();
        assert!(bad.validate().is_err());

        let mut bad = profile();
        bad.tags = vec![String::new()];
        assert!(bad.validate().is_err());
    }

    #[test]
    fn authentication_defaults_never_embed_a_secret() {
        let profile = profile();
        // The default asks at connect time and never names a stored secret.
        assert_eq!(
            profile.auth,
            AuthMethod::Password(CredentialSource::Prompt)
        );
    }
}
