//! The fixed 49-byte envelope header (spec §5).
//!
//! The header is cleartext; it is the AEAD associated data (its SHA-256 is the
//! AAD for every chunk) and the HKDF salt's source. A reader parses it before
//! it can name a single key, so the rules that make a header canonical are
//! enforced here: `chunk_size` exactly 65,536, iterations 0 and a zero salt
//! without the password flag, and at least 600,000 iterations with a non-zero
//! salt with it.

use rand_core::CryptoRng;
use sha2::{Digest, Sha256};

use crate::error::FormatError;

/// ASCII `SEALBIN`, the first 7 bytes of every envelope.
const MAGIC: [u8; 7] = *b"SEALBIN";
/// The only version this crate writes or reads.
const VERSION: u8 = 0x01;
/// The password bit in the flags byte; bits 1-7 are reserved and must be 0.
const FLAG_PASSWORD: u8 = 0x01;
/// The only `chunk_size` v1 allows.
const CHUNK_SIZE: u32 = 65_536;
/// Lower bound on PBKDF2 iterations with a password (spec §5).
const MIN_ITERATIONS: u32 = 600_000;
/// Upper bound a reader should enforce to bound decrypt-time work (spec §5).
const MAX_ITERATIONS: u32 = 10_000_000;
/// The count the writer uses with a password: the minimum, from OWASP.
const DEFAULT_ITERATIONS: u32 = MIN_ITERATIONS;

/// The public, non-secret view of a header the server may serve in metadata
/// (spec §4, used by #9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicInfo {
    /// The envelope version, always `1` in v1.
    pub version: u8,
    /// Whether the seal is password-protected.
    pub password: bool,
}

/// A validated 49-byte envelope header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    flags: u8,
    iterations: u32,
    salt: [u8; 16],
    nonce: [u8; 16],
}

impl Header {
    /// The encoded header length in bytes.
    pub const LEN: usize = 49;

    /// A fresh header: a random nonce, and either no password (iterations 0,
    /// zero salt) or a random non-zero salt and the default iteration count.
    #[must_use]
    pub fn new<R: CryptoRng + ?Sized>(rng: &mut R, password: bool) -> Self {
        let mut nonce = [0u8; 16];
        rng.fill_bytes(&mut nonce);
        if password {
            let mut salt = [0u8; 16];
            while salt == [0u8; 16] {
                rng.fill_bytes(&mut salt);
            }
            Self {
                flags: FLAG_PASSWORD,
                iterations: DEFAULT_ITERATIONS,
                salt,
                nonce,
            }
        } else {
            Self {
                flags: 0,
                iterations: 0,
                salt: [0u8; 16],
                nonce,
            }
        }
    }

    /// Build a header from explicit fields, validating it.
    ///
    /// `chunk_size` is not a parameter: it is always 65,536 in v1.
    ///
    /// # Errors
    ///
    /// [`FormatError::BadHeader`] if the flag/iterations/salt combination is
    /// not canonical: iterations must be 0 and the salt all-zero without the
    /// password flag, and between 600,000 and 10,000,000 with a non-zero salt
    /// with it.
    pub fn from_parts(
        password: bool,
        iterations: u32,
        salt: [u8; 16],
        nonce: [u8; 16],
    ) -> Result<Self, FormatError> {
        let header = Self {
            flags: if password { FLAG_PASSWORD } else { 0 },
            iterations,
            salt,
            nonce,
        };
        header.validate()?;
        Ok(header)
    }

    /// Decode the first 49 bytes of `bytes`, ignoring anything after them.
    ///
    /// # Errors
    ///
    /// [`FormatError::Truncated`] when fewer than 49 bytes are supplied;
    /// otherwise the first broken rule in spec §5's order, one of
    /// [`FormatError::BadMagic`], [`FormatError::UnsupportedVersion`],
    /// [`FormatError::UnknownFlags`] or [`FormatError::BadHeader`].
    pub fn decode(bytes: &[u8]) -> Result<Self, FormatError> {
        if bytes.len() < Self::LEN {
            return Err(FormatError::Truncated);
        }
        let bytes = &bytes[..Self::LEN];
        if bytes[0..7] != MAGIC {
            return Err(FormatError::BadMagic);
        }
        if bytes[7] != VERSION {
            return Err(FormatError::UnsupportedVersion);
        }
        let flags = bytes[8];
        if flags & !FLAG_PASSWORD != 0 {
            return Err(FormatError::UnknownFlags);
        }
        let iterations = u32::from_be_bytes([bytes[9], bytes[10], bytes[11], bytes[12]]);
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&bytes[13..29]);
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&bytes[29..45]);
        let chunk_size = u32::from_be_bytes([bytes[45], bytes[46], bytes[47], bytes[48]]);
        if chunk_size != CHUNK_SIZE {
            return Err(FormatError::BadHeader);
        }
        let header = Self {
            flags,
            iterations,
            salt,
            nonce,
        };
        header.validate()?;
        Ok(header)
    }

    /// Check the canonical rules of §5. `chunk_size` is constant and checked
    /// by [`Header::decode`].
    fn validate(&self) -> Result<(), FormatError> {
        if self.flags & !FLAG_PASSWORD != 0 {
            return Err(FormatError::UnknownFlags);
        }
        if self.password() {
            if self.iterations < MIN_ITERATIONS
                || self.iterations > MAX_ITERATIONS
                || self.salt == [0u8; 16]
            {
                return Err(FormatError::BadHeader);
            }
        } else if self.iterations != 0 || self.salt != [0u8; 16] {
            return Err(FormatError::BadHeader);
        }
        Ok(())
    }

    /// Encode to the 49 wire bytes.
    #[must_use]
    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        out[0..7].copy_from_slice(&MAGIC);
        out[7] = VERSION;
        out[8] = self.flags;
        out[9..13].copy_from_slice(&self.iterations.to_be_bytes());
        out[13..29].copy_from_slice(&self.salt);
        out[29..45].copy_from_slice(&self.nonce);
        out[45..49].copy_from_slice(&CHUNK_SIZE.to_be_bytes());
        out
    }

    /// The raw flags byte.
    #[must_use]
    pub fn flags(&self) -> u8 {
        self.flags
    }

    /// Whether the password flag is set.
    #[must_use]
    pub fn password(&self) -> bool {
        self.flags & FLAG_PASSWORD != 0
    }

    /// The PBKDF2 iteration count (0 without a password).
    #[must_use]
    pub fn iterations(&self) -> u32 {
        self.iterations
    }

    /// The PBKDF2 salt (all zero without a password).
    #[must_use]
    pub fn salt(&self) -> &[u8; 16] {
        &self.salt
    }

    /// The per-seal random nonce: the HKDF salt and chunk-nonce context.
    #[must_use]
    pub fn nonce(&self) -> &[u8; 16] {
        &self.nonce
    }

    /// The chunk size, always 65,536 in v1.
    #[must_use]
    pub fn chunk_size(&self) -> u32 {
        CHUNK_SIZE
    }

    /// `SHA-256` of the 49 header bytes: the AAD for every chunk (spec §6).
    #[must_use]
    pub fn aad(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&Sha256::digest(self.encode()));
        out
    }

    /// The non-secret summary a server may serve (spec §4).
    #[must_use]
    pub fn public_info(&self) -> PublicInfo {
        PublicInfo {
            version: VERSION,
            password: self.password(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Header;
    use crate::error::FormatError;

    fn header_bytes() -> [u8; Header::LEN] {
        Header::from_parts(true, 600_000, [0x20; 16], [0x30; 16])
            .unwrap()
            .encode()
    }

    #[test]
    fn encodes_the_appendix_a_layout() {
        // Appendix A counts up: salt 20..2f, nonce 30..3f.
        let mut salt = [0u8; 16];
        for (i, byte) in salt.iter_mut().enumerate() {
            *byte = 0x20 + u8::try_from(i).unwrap();
        }
        let mut nonce = [0u8; 16];
        for (i, byte) in nonce.iter_mut().enumerate() {
            *byte = 0x30 + u8::try_from(i).unwrap();
        }
        let header = Header::from_parts(true, 600_000, salt, nonce).unwrap();
        assert_eq!(header.salt(), &salt);
        assert_eq!(header.nonce(), &nonce);
        assert_eq!(header.chunk_size(), 65_536);
        assert!(header.password());
        assert_eq!(header.public_info().version, 1);
        assert!(header.public_info().password);
        let bytes = header.encode();
        assert_eq!(&bytes[0..7], b"SEALBIN");
        assert_eq!(bytes[7], 0x01);
        assert_eq!(bytes[8], 0x01);
        assert_eq!(&bytes[9..13], &600_000u32.to_be_bytes());
        assert_eq!(&bytes[45..49], &65_536u32.to_be_bytes());
        assert_eq!(Header::decode(&bytes).unwrap(), header);
    }

    #[test]
    fn round_trips_without_password() {
        let header = Header::from_parts(false, 0, [0u8; 16], [0x55; 16]).unwrap();
        assert!(!header.password());
        assert_eq!(header.iterations(), 0);
        assert_eq!(Header::decode(&header.encode()).unwrap(), header);
    }

    #[test]
    fn decode_rejects_each_broken_rule() {
        let good = header_bytes();
        let truncate = |len: usize| -> Vec<u8> { good[..len].to_vec() };
        assert_eq!(
            Header::decode(&truncate(0)).unwrap_err(),
            FormatError::Truncated
        );
        assert_eq!(
            Header::decode(&truncate(48)).unwrap_err(),
            FormatError::Truncated
        );

        let mut bad_magic = good;
        bad_magic[0] = b'X';
        assert_eq!(
            Header::decode(&bad_magic).unwrap_err(),
            FormatError::BadMagic
        );

        let mut bad_version = good;
        bad_version[7] = 0x02;
        assert_eq!(
            Header::decode(&bad_version).unwrap_err(),
            FormatError::UnsupportedVersion
        );

        let mut bad_flags = good;
        bad_flags[8] = 0x02;
        assert_eq!(
            Header::decode(&bad_flags).unwrap_err(),
            FormatError::UnknownFlags
        );

        let mut bad_chunk = good;
        bad_chunk[45..49].copy_from_slice(&32_768u32.to_be_bytes());
        assert_eq!(
            Header::decode(&bad_chunk).unwrap_err(),
            FormatError::BadHeader
        );

        // Password flag with an all-zero salt.
        let mut zero_salt = good;
        zero_salt[13..29].copy_from_slice(&[0u8; 16]);
        assert_eq!(
            Header::decode(&zero_salt).unwrap_err(),
            FormatError::BadHeader
        );

        // Password flag with too few iterations.
        let mut few_iterations = good;
        few_iterations[9..13].copy_from_slice(&599_999u32.to_be_bytes());
        assert_eq!(
            Header::decode(&few_iterations).unwrap_err(),
            FormatError::BadHeader
        );

        // No password flag but non-zero iterations.
        let mut stray_iterations = good;
        stray_iterations[8] = 0x00;
        assert_eq!(
            Header::decode(&stray_iterations).unwrap_err(),
            FormatError::BadHeader
        );
    }

    #[test]
    fn from_parts_validates() {
        assert!(Header::from_parts(true, 600_000, [1u8; 16], [0u8; 16]).is_ok());
        assert!(Header::from_parts(true, 10_000_001, [1u8; 16], [0u8; 16]).is_err());
        assert!(Header::from_parts(true, 600_000, [0u8; 16], [0u8; 16]).is_err());
        assert!(Header::from_parts(false, 1, [0u8; 16], [0u8; 16]).is_err());
        assert!(Header::from_parts(false, 0, [1u8; 16], [0u8; 16]).is_err());
    }
}
