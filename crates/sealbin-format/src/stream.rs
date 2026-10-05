//! STREAM over AES-256-GCM: the chunked payload encryption of spec §6.
//!
//! The plaintext is cut into 65,536-byte chunks; each is sealed with a 12-byte
//! nonce (`11-byte` big-endian chunk index followed by `0x01` on the final
//! chunk, `0x00` otherwise) and the header's SHA-256 as AAD. A chunk on the
//! wire is its ciphertext followed by the 16-byte tag.
//!
//! **Memory.** Neither half ever buffers the whole payload. The encryptor
//! holds back its last full chunk — it cannot know whether it is final — so it
//! keeps at most `chunk_size + 1` plaintext bytes. The decryptor looks one byte
//! ahead to tell a full non-final chunk from a final one, so it keeps at most
//! `chunk_size + 16 + 1` ciphertext bytes. `push` releases the plaintext of
//! authenticated non-final chunks incrementally; only `finish` proves the whole
//! stream, so a caller must treat `finish` as the success signal.

use aes_gcm::aead::consts::U12;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use zeroize::Zeroizing;

use crate::error::FormatError;
use crate::header::Header;
use crate::keys::{Ikm, KeySchedule, PayloadKey};
use crate::link::LinkKey;

/// Plaintext chunk size.
const CHUNK_SIZE: usize = 65_536;
/// AES-GCM tag length.
const TAG_LEN: usize = 16;
/// A full chunk on the wire: ciphertext plus tag.
const BLOCK_LEN: usize = CHUNK_SIZE + TAG_LEN;

/// Build the AES-256-GCM cipher for a payload key.
///
/// The conversion borrows the key bytes rather than copying them, so no
/// unzeroized copy of the key is left on the stack; the cipher itself zeroizes
/// its key schedule on drop (the `zeroize` feature of `aes-gcm`).
fn cipher_for(key: &PayloadKey) -> Aes256Gcm {
    let key: &Key<Aes256Gcm> = key.as_bytes().into();
    Aes256Gcm::new(key)
}

/// The 12-byte nonce for chunk `index` (spec §6).
fn chunk_nonce(index: u32, is_last: bool) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[7..11].copy_from_slice(&index.to_be_bytes());
    nonce[11] = u8::from(is_last);
    nonce
}

/// Seal one chunk, returning ciphertext followed by the tag.
fn seal(
    cipher: &Aes256Gcm,
    aad: &[u8; 32],
    index: u32,
    is_last: bool,
    plaintext: &[u8],
) -> Vec<u8> {
    let nonce = Nonce::<U12>::from(chunk_nonce(index, is_last));
    cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("a 64 KiB chunk is far below the AES-GCM length limit")
}

/// Open one chunk, or [`FormatError::AuthFailed`] if the tag does not verify.
fn open(
    cipher: &Aes256Gcm,
    aad: &[u8; 32],
    index: u32,
    is_last: bool,
    ciphertext: &[u8],
) -> Result<Vec<u8>, FormatError> {
    let nonce = Nonce::<U12>::from(chunk_nonce(index, is_last));
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| FormatError::AuthFailed)
}

/// The chunk index as a `u32`, or [`FormatError::TooManyChunks`] past `2^32`.
fn checked_index(next_index: u64) -> Result<u32, FormatError> {
    u32::try_from(next_index).map_err(|_| FormatError::TooManyChunks)
}

/// Seal a stream chunk by chunk (spec §6).
pub struct Encryptor {
    cipher: Aes256Gcm,
    aad: [u8; 32],
    /// The held-back chunk plus a partial one. Plaintext, so it zeroizes on
    /// drop.
    buffer: Zeroizing<Vec<u8>>,
    next_index: u64,
}

impl core::fmt::Debug for Encryptor {
    /// Prints the buffered byte count, never the buffered plaintext.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Encryptor")
            .field("cipher", &self.cipher)
            .field("aad", &self.aad)
            .field("buffered", &self.buffer.len())
            .field("next_index", &self.next_index)
            .finish()
    }
}

impl Encryptor {
    /// Start an encryptor for `key` under `header`.
    #[must_use]
    pub fn new(key: &PayloadKey, header: &Header) -> Self {
        Self {
            cipher: cipher_for(key),
            aad: header.aad(),
            buffer: Zeroizing::new(Vec::with_capacity(CHUNK_SIZE + 1)),
            next_index: 0,
        }
    }

    /// Feed plaintext, returning every chunk that is now provably non-final.
    ///
    /// The last full chunk is held back: it is only emitted by
    /// [`Encryptor::finish`], because a positive multiple of `chunk_size` must
    /// end with that chunk as the final one and not an empty trailing chunk.
    ///
    /// # Errors
    ///
    /// [`FormatError::TooManyChunks`] if the payload would need a chunk index at
    /// or above `2^32`.
    pub fn push(&mut self, data: &[u8]) -> Result<Vec<Vec<u8>>, FormatError> {
        let mut chunks = Vec::new();
        let mut data = data;
        while !data.is_empty() {
            let take = ((CHUNK_SIZE + 1) - self.buffer.len()).min(data.len());
            self.buffer.extend_from_slice(&data[..take]);
            data = &data[take..];
            if self.buffer.len() == CHUNK_SIZE + 1 {
                let index = checked_index(self.next_index)?;
                let chunk = seal(
                    &self.cipher,
                    &self.aad,
                    index,
                    false,
                    &self.buffer[..CHUNK_SIZE],
                );
                self.buffer.drain(..CHUNK_SIZE);
                self.next_index += 1;
                chunks.push(chunk);
            }
        }
        Ok(chunks)
    }

    /// Seal the final chunk and return it (ciphertext followed by tag).
    ///
    /// # Errors
    ///
    /// [`FormatError::TooManyChunks`] if the final chunk's index would be at or
    /// above `2^32`.
    pub fn finish(self) -> Result<Vec<u8>, FormatError> {
        let index = checked_index(self.next_index)?;
        Ok(seal(&self.cipher, &self.aad, index, true, &self.buffer))
    }

    /// Bytes currently buffered (the held-back chunk plus a partial one).
    #[doc(hidden)]
    #[must_use]
    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }
}

/// Open a stream chunk by chunk (spec §6).
#[derive(Debug)]
pub struct Decryptor {
    cipher: Aes256Gcm,
    aad: [u8; 32],
    buffer: Vec<u8>,
    next_index: u64,
}

impl Decryptor {
    /// Start a decryptor for `key` under `header`.
    #[must_use]
    pub fn new(key: &PayloadKey, header: &Header) -> Self {
        Self {
            cipher: cipher_for(key),
            aad: header.aad(),
            buffer: Vec::with_capacity(BLOCK_LEN + 1),
            next_index: 0,
        }
    }

    /// Feed ciphertext, returning the plaintext of every chunk now known to be
    /// non-final.
    ///
    /// # Errors
    ///
    /// [`FormatError::AuthFailed`] when a chunk's tag does not verify — which
    /// covers reordering, trailing bytes and a wrong key.
    pub fn push(&mut self, data: &[u8]) -> Result<Vec<u8>, FormatError> {
        let mut plaintext = Vec::new();
        let mut data = data;
        while !data.is_empty() {
            let take = ((BLOCK_LEN + 1) - self.buffer.len()).min(data.len());
            self.buffer.extend_from_slice(&data[..take]);
            data = &data[take..];
            // A full block with at least one byte after it is non-final; a full
            // block with nothing after it might be the final chunk, so it waits.
            if self.buffer.len() > BLOCK_LEN {
                let index = checked_index(self.next_index)?;
                let chunk = open(
                    &self.cipher,
                    &self.aad,
                    index,
                    false,
                    &self.buffer[..BLOCK_LEN],
                )?;
                self.buffer.drain(..BLOCK_LEN);
                self.next_index += 1;
                plaintext.extend_from_slice(&chunk);
            }
        }
        Ok(plaintext)
    }

    /// Open the final chunk and return its plaintext.
    ///
    /// # Errors
    ///
    /// [`FormatError::Truncated`] if there are no chunks at all or fewer than
    /// 16 bytes remain for the final chunk's tag; [`FormatError::AuthFailed`] if
    /// the final chunk's tag does not verify.
    pub fn finish(self) -> Result<Vec<u8>, FormatError> {
        if self.buffer.len() < TAG_LEN {
            // Either no chunks at all, or the final chunk is too short to hold
            // a tag.
            return Err(FormatError::Truncated);
        }
        // Spec §6: a final chunk may be empty only when it is the only chunk.
        // A 16-byte block (an empty final chunk) after a non-final chunk is not
        // a canonical encoding, so reject it here, before the tag check.
        if self.buffer.len() == TAG_LEN && self.next_index != 0 {
            return Err(FormatError::AuthFailed);
        }
        let index = checked_index(self.next_index)?;
        open(&self.cipher, &self.aad, index, true, &self.buffer)
    }

    /// Bytes currently buffered (the held-back chunk plus a partial one).
    #[doc(hidden)]
    #[must_use]
    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }
}

/// The opener's state machine: collecting the 49-byte header, then the body.
///
/// The header variant is tiny; the body variant carries the decryptor, which
/// is boxed because it holds a large AES key schedule and a chunk buffer.
#[derive(Debug)]
enum OpenerState {
    /// Fewer than 49 header bytes seen so far.
    Header(Vec<u8>),
    Body {
        header: Header,
        decryptor: Box<Decryptor>,
    },
}

/// Parse the header from a stream and open the body, given an IKM.
///
/// This is the one that also serves the password case (#4): the caller builds
/// the IKM (with or without the password key) and this parses the 49-byte
/// header out of the stream before it derives anything.
#[derive(Debug)]
pub struct Opener {
    ikm: Ikm,
    state: OpenerState,
}

impl Opener {
    /// Start an opener from input keying material.
    #[must_use]
    pub fn new(ikm: Ikm) -> Self {
        Self {
            ikm,
            state: OpenerState::Header(Vec::with_capacity(Header::LEN)),
        }
    }

    /// Start an opener from a link key (no password).
    #[must_use]
    pub fn from_link_key(key: &LinkKey) -> Self {
        Self::new(Ikm::from_link_key(key))
    }

    /// Feed envelope bytes, returning any plaintext released so far.
    ///
    /// # Errors
    ///
    /// The header errors of [`Header::decode`] while the header is incomplete,
    /// then [`Decryptor::push`]'s errors. On error the opener is left in an
    /// unusable state; treat any error as terminal.
    pub fn push(&mut self, data: &[u8]) -> Result<Vec<u8>, FormatError> {
        let state = core::mem::replace(&mut self.state, OpenerState::Header(Vec::new()));
        match state {
            OpenerState::Body {
                header,
                mut decryptor,
            } => {
                let out = decryptor.push(data)?;
                self.state = OpenerState::Body { header, decryptor };
                Ok(out)
            }
            OpenerState::Header(mut head) => {
                let take = (Header::LEN - head.len()).min(data.len());
                head.extend_from_slice(&data[..take]);
                if head.len() < Header::LEN {
                    self.state = OpenerState::Header(head);
                    return Ok(Vec::new());
                }
                let header = Header::decode(&head)?;
                let schedule = KeySchedule::derive(&self.ikm, &header);
                let mut decryptor = Box::new(Decryptor::new(&schedule.payload, &header));
                let out = decryptor.push(&data[take..])?;
                self.state = OpenerState::Body { header, decryptor };
                Ok(out)
            }
        }
    }

    /// The header, once 49 bytes have arrived.
    #[must_use]
    pub fn header(&self) -> Option<Header> {
        match &self.state {
            OpenerState::Body { header, .. } => Some(*header),
            OpenerState::Header(_) => None,
        }
    }

    /// Finish and return the final chunk's plaintext.
    ///
    /// # Errors
    ///
    /// [`FormatError::Truncated`] if the header never arrived, or otherwise the
    /// errors of [`Decryptor::finish`].
    pub fn finish(self) -> Result<Vec<u8>, FormatError> {
        match self.state {
            OpenerState::Body { decryptor, .. } => decryptor.finish(),
            OpenerState::Header(_) => Err(FormatError::Truncated),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CHUNK_SIZE, Decryptor, Encryptor, cipher_for, seal};
    use crate::error::FormatError;
    use crate::header::Header;
    use crate::keys::{Ikm, KeySchedule};
    use crate::link::LinkKey;

    fn actors(password: bool) -> (Encryptor, Decryptor) {
        let key = LinkKey::from_bytes([3u8; 32]);
        let header = Header::from_parts(
            password,
            if password { 600_000 } else { 0 },
            if password { [7u8; 16] } else { [0u8; 16] },
            [9u8; 16],
        )
        .unwrap();
        let ikm = Ikm::from_link_key(&key);
        let schedule = KeySchedule::derive(&ikm, &header);
        (
            Encryptor::new(&schedule.payload, &header),
            Decryptor::new(&schedule.payload, &header),
        )
    }

    #[test]
    fn full_chunk_is_held_back_until_finish() {
        let (mut enc, _) = actors(false);
        let plaintext = vec![0xABu8; 65_536];
        assert!(enc.push(&plaintext).unwrap().is_empty());
        assert_eq!(enc.buffered_len(), 65_536);
        let final_chunk = enc.finish().unwrap();
        assert_eq!(final_chunk.len(), 65_536 + 16);
    }

    #[test]
    fn one_chunk_plus_one_byte_emits_one_non_final_chunk() {
        let (mut enc, _) = actors(false);
        let plaintext = vec![0x5Au8; 65_537];
        let chunks = enc.push(&plaintext).unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].len(), 65_552);
        assert_eq!(enc.finish().unwrap().len(), 1 + 16);
    }

    #[test]
    fn empty_payload_is_a_single_empty_chunk() {
        let (enc, mut dec) = actors(false);
        let envelope = enc.finish().unwrap();
        assert_eq!(envelope.len(), 16);
        assert!(dec.push(&envelope).unwrap().is_empty());
        assert!(dec.finish().unwrap().is_empty());
    }

    #[test]
    fn finish_reports_no_chunks_as_truncated() {
        let (_, dec) = actors(false);
        assert_eq!(
            dec.finish().unwrap_err(),
            crate::error::FormatError::Truncated
        );
    }

    #[test]
    fn empty_final_chunk_after_a_non_final_chunk_is_rejected() {
        let key = LinkKey::from_bytes([3u8; 32]);
        let header = Header::from_parts(false, 0, [0u8; 16], [9u8; 16]).expect("valid header");
        let schedule = KeySchedule::derive(&Ikm::from_link_key(&key), &header);
        let cipher = cipher_for(&schedule.payload);
        let aad = header.aad();
        // `chunk0(non-final, full) || empty-final`: both tags are genuine under
        // the real key, but §6 allows an empty final chunk only when it is the
        // only chunk, so the reader must reject it.
        let mut body = seal(&cipher, &aad, 0, false, &vec![0xAB; CHUNK_SIZE]);
        body.extend_from_slice(&seal(&cipher, &aad, 1, true, &[]));
        let mut decryptor = Decryptor::new(&schedule.payload, &header);
        assert_eq!(decryptor.push(&body).unwrap().len(), CHUNK_SIZE);
        assert_eq!(decryptor.finish().unwrap_err(), FormatError::AuthFailed);
    }
}
