//! The key schedule: input keying material, HKDF, and the two derived keys
//! (spec §3, D5).
//!
//! With no password the IKM is the 32-byte link key; with one it is the link
//! key followed by `P`, the 32-byte PBKDF2 output, for 64 bytes. This crate
//! computes `P` nowhere — the password API belongs to #4 — but the seam
//! [`Ikm::from_link_key_and_password_key`] lets the test vectors and #4 build
//! the 64-byte IKM.

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::header::Header;
use crate::link::LinkKey;
use crate::secret::define_key_type;

/// HKDF info for the AES-256-GCM payload key.
const INFO_PAYLOAD: &[u8] = b"sealbin/v1/payload";
/// HKDF info for the read token.
const INFO_READ: &[u8] = b"sealbin/v1/read";

/// Input keying material: 32 bytes without a password, 64 with.
///
/// Zeroises on drop and never appears in `Debug`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Ikm {
    bytes: [u8; 64],
    len: u8,
}

impl Ikm {
    /// IKM from the link key alone: 32 bytes (no password).
    #[must_use]
    pub fn from_link_key(key: &LinkKey) -> Self {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(key.as_bytes());
        Self { bytes, len: 32 }
    }

    /// IKM from the link key followed by a password key `P`: 64 bytes.
    ///
    /// `P` is PBKDF2-HMAC-SHA256 of the NFC-normalised password under the
    /// header's salt and iteration count. The password API — normalisation,
    /// PBKDF2 and validation — is owned by #4; this seam exists so the test
    /// vectors and that issue can build the 64-byte IKM without this crate
    /// depending on a KDF it does not otherwise need.
    #[doc(hidden)]
    #[must_use]
    pub fn from_link_key_and_password_key(key: &LinkKey, password_key: &[u8; 32]) -> Self {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(key.as_bytes());
        bytes[32..].copy_from_slice(password_key);
        Self { bytes, len: 64 }
    }

    /// Borrow the IKM bytes (32 or 64 of them).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

impl core::fmt::Debug for Ikm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Ikm([redacted])")
    }
}

impl subtle::ConstantTimeEq for Ikm {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        if self.len != other.len {
            return subtle::Choice::from(0);
        }
        subtle::ConstantTimeEq::ct_eq(self.as_bytes(), other.as_bytes())
    }
}

impl PartialEq for Ikm {
    fn eq(&self, other: &Self) -> bool {
        bool::from(subtle::ConstantTimeEq::ct_eq(self, other))
    }
}

impl Eq for Ikm {}

define_key_type!(
    /// The AES-256-GCM payload key `K_payload` (spec §3).
    PayloadKey,
    "PayloadKey"
);

define_key_type!(
    /// The read token: `SHA-256` of it is the verifier a server stores
    /// (spec §4, D6).
    ReadToken,
    "ReadToken"
);

impl ReadToken {
    /// `read_verifier = SHA-256(read_token)`, 32 bytes (spec §4).
    #[must_use]
    pub fn verifier(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&Sha256::digest(self.as_bytes()));
        out
    }

    /// Constant-time check against a stored verifier (spec §4).
    #[must_use]
    pub fn verify(&self, verifier: &[u8; 32]) -> bool {
        let computed = self.verifier();
        bool::from(subtle::ConstantTimeEq::ct_eq(&computed[..], &verifier[..]))
    }
}

/// The two keys derived from an IKM and a header (spec §3).
#[derive(Debug)]
pub struct KeySchedule {
    /// The AES-256-GCM key that encrypts the payload.
    pub payload: PayloadKey,
    /// The read token whose hash is the verifier.
    pub read_token: ReadToken,
}

impl KeySchedule {
    /// HKDF-SHA256 over `ikm`, salted with the header nonce.
    #[must_use]
    pub fn derive(ikm: &Ikm, header: &Header) -> Self {
        let hkdf = Hkdf::<Sha256>::new(Some(header.nonce().as_slice()), ikm.as_bytes());
        let payload = Zeroizing::new(expand32(&hkdf, INFO_PAYLOAD));
        let read_token = Zeroizing::new(expand32(&hkdf, INFO_READ));
        Self {
            payload: PayloadKey::from_bytes(*payload),
            read_token: ReadToken::from_bytes(*read_token),
        }
    }
}

/// One HKDF expansion to 32 bytes.
///
/// A private helper so the impossible panic (32 is well under HKDF-SHA256's
/// 255 × 32-byte limit) is not part of [`KeySchedule::derive`]'s documented
/// contract.
fn expand32(hkdf: &Hkdf<Sha256>, info: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    hkdf.expand(info, &mut out)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}
