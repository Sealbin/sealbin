//! Seal ids.
//!
//! A seal id is exactly 12 base62 characters (`0-9A-Za-z`), drawn from a
//! CSPRNG, about 71 bits (D4, spec §1). It is the Durable Object name in
//! production (D9), so validation matters: an id either parses or it does not.
//!
//! `sealbin-format` does not export `SealId` yet; when it does, this type moves
//! there (or becomes a re-export) and this module goes away.

use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Serialize};

/// The number of characters in a seal id (spec §1).
pub const ID_LEN: usize = 12;

/// A seal id: 12 base62 characters (`0-9A-Za-z`), spec §1.
///
/// Construct one with [`SealId::parse`] or [`str::parse`]. Deserialisation runs
/// the same validation, so a `SealId` read back from storage is always valid.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SealId(String);

/// Why a string is not a valid [`SealId`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdError {
    /// The id was not exactly [`ID_LEN`] characters.
    Length {
        /// The length that was seen.
        len: usize,
    },
    /// The id contained a byte outside the base62 alphabet `0-9A-Za-z`.
    Character {
        /// The first offending byte.
        byte: u8,
    },
}

impl fmt::Display for IdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdError::Length { len } => {
                write!(f, "seal id must be {ID_LEN} characters, got {len}")
            }
            IdError::Character { byte } => {
                write!(f, "seal id byte 0x{byte:02x} is not base62")
            }
        }
    }
}

impl std::error::Error for IdError {}

fn validate(s: &str) -> Result<(), IdError> {
    if s.len() != ID_LEN {
        return Err(IdError::Length { len: s.len() });
    }
    if let Some(&byte) = s.as_bytes().iter().find(|b| !b.is_ascii_alphanumeric()) {
        return Err(IdError::Character { byte });
    }
    Ok(())
}

impl SealId {
    /// Parse a seal id, rejecting anything that is not 12 base62 characters.
    ///
    /// # Errors
    ///
    /// [`IdError::Length`] if the input is not [`ID_LEN`] bytes;
    /// [`IdError::Character`] on the first non-base62 byte.
    pub fn parse(s: &str) -> Result<Self, IdError> {
        validate(s)?;
        Ok(Self(s.to_owned()))
    }

    /// The id as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for SealId {
    type Err = IdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for SealId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<SealId> for String {
    fn from(id: SealId) -> Self {
        id.0
    }
}

impl TryFrom<String> for SealId {
    type Error = IdError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        validate(&s)?;
        Ok(Self(s))
    }
}
