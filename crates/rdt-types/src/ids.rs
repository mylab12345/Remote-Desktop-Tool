//! Opaque, randomly generated identifiers.
//!
//! Identifiers are generated from the operating system CSPRNG so that neither
//! session identifiers nor profile identifiers can be guessed by a process that
//! is allowed to talk to the agent's control socket.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::rng::fill_random_or_panic;

/// Number of random bytes backing an identifier.
const ID_BYTES: usize = 8;

macro_rules! identifier {
    ($name:ident, $label:literal) => {
        #[doc = concat!("Opaque ", $label, " identifier.")]
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name([u8; ID_BYTES]);

        impl $name {
            /// Generates a fresh identifier from the OS CSPRNG.
            pub fn new() -> Self {
                let mut bytes = [0u8; ID_BYTES];
                fill_random_or_panic(&mut bytes);
                Self(bytes)
            }

            /// Rebuilds an identifier from its byte representation.
            pub fn from_bytes(bytes: [u8; ID_BYTES]) -> Self {
                Self(bytes)
            }

            /// The raw bytes of the identifier.
            pub fn as_bytes(&self) -> &[u8; ID_BYTES] {
                &self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({self})", stringify!($name))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                for byte in self.0 {
                    write!(f, "{byte:02x}")?;
                }
                Ok(())
            }
        }

        impl FromStr for $name {
            type Err = IdParseError;

            fn from_str(text: &str) -> Result<Self, Self::Err> {
                if text.len() != ID_BYTES * 2 {
                    return Err(IdParseError::Length(text.len()));
                }
                let mut bytes = [0u8; ID_BYTES];
                for (index, slot) in bytes.iter_mut().enumerate() {
                    let pair = &text[index * 2..index * 2 + 2];
                    *slot = u8::from_str_radix(pair, 16).map_err(|_| IdParseError::NotHex)?;
                }
                Ok(Self(bytes))
            }
        }
    };
}

identifier!(ProfileId, "connection profile");
identifier!(SessionId, "session");

/// Errors produced while parsing an identifier from text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdParseError {
    /// The string had the wrong length (expected 16 hex characters).
    Length(usize),
    /// The string contained a non-hexadecimal character.
    NotHex,
}

impl fmt::Display for IdParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length(len) => {
                write!(
                    f,
                    "identifier must be {expected} hex characters, got {len}",
                    expected = ID_BYTES * 2
                )
            }
            Self::NotHex => f.write_str("identifier must be hexadecimal"),
        }
    }
}

impl std::error::Error for IdParseError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_are_unique() {
        let a = SessionId::new();
        let b = SessionId::new();
        assert_ne!(a, b);
    }

    #[test]
    fn identifiers_round_trip_through_text() {
        let id = ProfileId::new();
        let text = id.to_string();
        assert_eq!(text.len(), 16);
        assert_eq!(text.parse::<ProfileId>().expect("parse"), id);
    }

    #[test]
    fn identifiers_reject_bad_input() {
        assert_eq!("abc".parse::<ProfileId>(), Err(IdParseError::Length(3)));
        assert_eq!(
            "zzzzzzzzzzzzzzzz".parse::<ProfileId>(),
            Err(IdParseError::NotHex)
        );
    }

    #[test]
    fn identifiers_survive_a_round_trip_through_text() {
        let id = SessionId::new();
        let text = id.to_string();
        let back: SessionId = text.parse().expect("parse");
        assert_eq!(id, back);
        assert_eq!(back.as_bytes(), id.as_bytes());
    }
}
