//! Whole-buffer helpers over the streaming types (spec §5, §6).
//!
//! These are conveniences for callers that already hold the whole payload —
//! a CLI reading a small file, or the test vectors. The streaming
//! [`Encryptor`] and [`Decryptor`](crate::Decryptor) are the
//! bounded-memory path.

use rand_core::CryptoRng;

use crate::error::FormatError;
use crate::header::Header;
use crate::keys::{Ikm, KeySchedule};
use crate::link::LinkKey;
use crate::stream::{Encryptor, Opener};

/// Seal `plaintext` into an envelope (header followed by chunks), no password.
///
/// The header gets a fresh random nonce from `rng`.
///
/// # Errors
///
/// [`FormatError::TooManyChunks`] for a payload above `2^32` chunks (256 TiB).
pub fn seal_bytes<R: CryptoRng + ?Sized>(
    rng: &mut R,
    key: &LinkKey,
    plaintext: &[u8],
) -> Result<Vec<u8>, FormatError> {
    let header = Header::new(rng, false);
    let ikm = Ikm::from_link_key(key);
    seal_with_ikm(&ikm, &header, plaintext)
}

/// Seal `plaintext` under an explicit IKM and header.
///
/// This is the form the test vectors and the password case (#4) use: the
/// caller owns the header (and so the salt, nonce and iteration count) and the
/// 64-byte IKM when there is a password.
///
/// # Errors
///
/// [`FormatError::TooManyChunks`] for a payload above `2^32` chunks.
pub fn seal_with_ikm(ikm: &Ikm, header: &Header, plaintext: &[u8]) -> Result<Vec<u8>, FormatError> {
    let schedule = KeySchedule::derive(ikm, header);
    let mut encryptor = Encryptor::new(&schedule.payload, header);
    let mut envelope = header.encode().to_vec();
    for chunk in encryptor.push(plaintext)? {
        envelope.extend_from_slice(&chunk);
    }
    envelope.extend_from_slice(&encryptor.finish()?);
    Ok(envelope)
}

/// Open an envelope with a link key (no password).
///
/// # Errors
///
/// The header and envelope errors of [`crate::Opener::push`] and
/// [`crate::Opener::finish`].
pub fn open_bytes(key: &LinkKey, envelope: &[u8]) -> Result<Vec<u8>, FormatError> {
    let ikm = Ikm::from_link_key(key);
    open_with_ikm(&ikm, envelope)
}

/// Open an envelope under an explicit IKM.
///
/// # Errors
///
/// The header and envelope errors of [`crate::Opener::push`] and
/// [`crate::Opener::finish`].
pub fn open_with_ikm(ikm: &Ikm, envelope: &[u8]) -> Result<Vec<u8>, FormatError> {
    let mut opener = Opener::new(ikm.clone());
    let mut plaintext = opener.push(envelope)?;
    plaintext.extend_from_slice(&opener.finish()?);
    Ok(plaintext)
}
