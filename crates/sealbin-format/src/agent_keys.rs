//! The agent key bundle: one Ed25519 key that signs and one X25519 key that
//! agrees (spec §14).
//!
//! An agent is a long-lived identity, not a seal. It registers a [`KeyBundle`]
//! — its two public keys, the name and account it belongs to, and the time it
//! was created — and proves it owns the bundle with a *binding* signature. To
//! replace its keys it publishes a new bundle plus a *rotation* signature made
//! by the key it is replacing, so a key directory can check the chain without
//! ever seeing a secret.
//!
//! Nothing here generates randomness of its own: [`KeyBundle::generate`] takes
//! a caller-supplied CSPRNG, like the rest of the crate (D4).

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::CryptoRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

use crate::crockford;

/// The domain tag of the binding signature: what the Ed25519 key signs to prove
/// it owns the X25519 key and the metadata beside it.
const BINDING_TAG: &[u8] = b"sealbin/v1/agent-key-binding";

/// The domain tag of the rotation signature: what the outgoing key signs to
/// hand over to the incoming one.
const ROTATION_TAG: &[u8] = b"sealbin/v1/agent-key-rotation";

/// The longest an agent name or an account id may be, in UTF-8 bytes. The
/// canonical encoding length-prefixes both, so the limit is a sanity bound, not
/// an ambiguity fix.
pub const MAX_NAME_LEN: usize = 64;

/// The number of characters in a [`KeyBundle::fingerprint`].
const FINGERPRINT_CHARS: usize = 26;

/// The characters of a key id before each hyphen of a fingerprint: four groups
/// of four, then the remaining ten.
const FINGERPRINT_GROUP: usize = 4;

/// A published agent key bundle.
///
/// The five public members are exactly what the key directory stores; the
/// private keys never leave the agent that generated them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyBundle {
    /// The Ed25519 public key: the bundle's identity, and the key every
    /// binding and rotation signature is checked against.
    pub ed25519_pub: [u8; 32],
    /// The X25519 public key: the agreement half of the bundle, covered by the
    /// binding signature so it cannot be swapped for another.
    pub x25519_pub: [u8; 32],
    /// When the bundle was created, in seconds since the Unix epoch.
    pub created_at: u64,
    /// The agent's display name, 1 to [`MAX_NAME_LEN`] UTF-8 bytes.
    pub agent_name: String,
    /// The account the agent belongs to, 1 to [`MAX_NAME_LEN`] UTF-8 bytes.
    pub account_id: String,
}

/// The two secret halves of a bundle.
///
/// Both zeroise when they are dropped: `SigningKey` and `StaticSecret` each
/// carry a zeroising `Drop` (dalek's `zeroize` feature is on for this
/// workspace), and this type adds nothing to keep that from happening. It has
/// no `Serialize`, no `Display`, and prints `AgentKeyPair([redacted])`.
pub struct AgentKeyPair {
    signing: SigningKey,
    static_secret: StaticSecret,
}

/// A failure in the agent key bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AgentKeyError {
    /// The agent name is empty or longer than [`MAX_NAME_LEN`].
    #[error("the agent name is empty or too long")]
    NameTooLong,
    /// The account id is empty or longer than [`MAX_NAME_LEN`].
    #[error("the account id is empty or too long")]
    AccountIdTooLong,
    /// The 32 bytes are not a valid Ed25519 public key.
    #[error("the ed25519 public key is not valid")]
    BadEd25519Key,
    /// The binding signature does not verify under this bundle's Ed25519 key.
    #[error("the binding signature does not verify")]
    BadBinding,
    /// The rotation signature does not verify under the previous bundle's
    /// Ed25519 key.
    #[error("the rotation signature does not verify")]
    BadRotation,
    /// The wire encoding is truncated, mislabelled or not valid UTF-8.
    #[error("the key bundle wire encoding is invalid")]
    BadWire,
    /// The key id is not 26 canonical Crockford base32 characters.
    #[error("the key id is not 26 crockford base32 characters")]
    BadKeyId,
}

impl AgentKeyError {
    /// The stable name this failure carries, in the same style as
    /// [`crate::FormatError::code`].
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::NameTooLong => "agent-keys/name-too-long",
            Self::AccountIdTooLong => "agent-keys/account-id-too-long",
            Self::BadEd25519Key => "agent-keys/bad-ed25519-key",
            Self::BadBinding => "agent-keys/bad-binding",
            Self::BadRotation => "agent-keys/bad-rotation",
            Self::BadWire => "agent-keys/bad-wire",
            Self::BadKeyId => "agent-keys/bad-key-id",
        }
    }
}

impl KeyBundle {
    /// The fixed part of the wire encoding: both public keys and the creation
    /// time. The two length-prefixed strings follow it.
    pub const WIRE_FIXED_LEN: usize = 72;

    /// The number of bytes in a key id before it is written as text.
    pub const KEY_ID_LEN: usize = 16;

    /// The number of characters in a key id: 128 bits in five-bit groups.
    pub const KEY_ID_CHARS: usize = 26;

    /// Generate a fresh bundle and its key pair from `rng`.
    ///
    /// # Errors
    ///
    /// Returns [`AgentKeyError::NameTooLong`] or
    /// [`AgentKeyError::AccountIdTooLong`] if either string is empty or longer
    /// than [`MAX_NAME_LEN`].
    pub fn generate<R: CryptoRng + ?Sized>(
        agent_name: &str,
        account_id: &str,
        created_at: u64,
        rng: &mut R,
    ) -> Result<(Self, AgentKeyPair), AgentKeyError> {
        validate_name(agent_name)?;
        validate_account_id(account_id)?;
        let signing = SigningKey::generate(rng);
        let static_secret = StaticSecret::random_from_rng(rng);
        let bundle = Self {
            ed25519_pub: signing.verifying_key().to_bytes(),
            x25519_pub: X25519Public::from(&static_secret).to_bytes(),
            created_at,
            agent_name: agent_name.to_owned(),
            account_id: account_id.to_owned(),
        };
        Ok((bundle, AgentKeyPair::new(signing, static_secret)))
    }

    /// The canonical bytes the binding signature covers.
    ///
    /// The message is, byte for byte:
    ///
    /// ```text
    /// "sealbin/v1/agent-key-binding"            (28 bytes, ASCII)
    /// || u32be(len(agent_name)) || agent_name   (1..=64 bytes, UTF-8)
    /// || u32be(len(account_id)) || account_id   (1..=64 bytes, UTF-8)
    /// || u64be(created_at)
    /// || x25519_pub                             (32 bytes)
    /// ```
    ///
    /// The Ed25519 public key is *not* in the message: it is the key the
    /// signature is checked against, so it is authenticated by being the
    /// verifier rather than by containing itself. The X25519 key is a
    /// different key and is covered, without which a bundle's agreement half
    /// could be replaced. The key id is not in the message either; it is
    /// derived from the two public keys.
    #[must_use]
    pub fn binding_message(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(BINDING_TAG.len() + 48 + self.string_len());
        out.extend_from_slice(BINDING_TAG);
        push_string(&mut out, &self.agent_name);
        push_string(&mut out, &self.account_id);
        out.extend_from_slice(&self.created_at.to_be_bytes());
        out.extend_from_slice(&self.x25519_pub);
        out
    }

    /// Sign the binding message with the agent's Ed25519 key.
    #[must_use]
    pub fn sign(&self, ed25519_secret: &SigningKey) -> [u8; 64] {
        sign(&self.binding_message(), ed25519_secret)
    }

    /// Check a binding signature against the Ed25519 key already in this
    /// bundle.
    ///
    /// The check is strict: a signature from a different key, over different
    /// bytes, or from a non-canonical (small-order or off-curve) public key is
    /// rejected.
    ///
    /// # Errors
    ///
    /// Returns [`AgentKeyError::NameTooLong`] or
    /// [`AgentKeyError::AccountIdTooLong`] if this bundle was built with an
    /// over-long name or account id, [`AgentKeyError::BadEd25519Key`] if
    /// `ed25519_pub` is not a valid public key, and
    /// [`AgentKeyError::BadBinding`] if the signature does not verify.
    pub fn verify_binding(&self, sig: &[u8; 64]) -> Result<(), AgentKeyError> {
        self.validate()?;
        verifying_key(&self.ed25519_pub)?
            .verify_strict(&self.binding_message(), &Signature::from_bytes(sig))
            .map_err(|_| AgentKeyError::BadBinding)
    }

    /// The canonical bytes a rotation signature covers: the domain tag and
    /// *this* bundle's key id, 16 raw bytes.
    ///
    /// ```text
    /// "sealbin/v1/agent-key-rotation" || key_id_bytes   (45 bytes: 29 + 16)
    /// ```
    ///
    /// The outgoing key signs this, so a directory learns that its holder
    /// vouched for this bundle, and nothing else: the message does not carry
    /// the names, the time, or the public keys.
    #[must_use]
    pub fn rotation_message(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ROTATION_TAG.len() + Self::KEY_ID_LEN);
        out.extend_from_slice(ROTATION_TAG);
        out.extend_from_slice(&self.key_id_bytes());
        out
    }

    /// Sign this bundle's rotation message with the *previous* Ed25519 key.
    #[must_use]
    pub fn sign_rotation(&self, previous: &SigningKey) -> [u8; 64] {
        sign(&self.rotation_message(), previous)
    }

    /// Check a rotation signature made by `previous` over this bundle's key id.
    ///
    /// # Errors
    ///
    /// Returns [`AgentKeyError::BadEd25519Key`] if the previous bundle's
    /// Ed25519 key is not a valid public key, and
    /// [`AgentKeyError::BadRotation`] if the signature does not verify.
    pub fn verify_rotation(
        &self,
        previous: &KeyBundle,
        sig: &[u8; 64],
    ) -> Result<(), AgentKeyError> {
        verifying_key(&previous.ed25519_pub)?
            .verify_strict(&self.rotation_message(), &Signature::from_bytes(sig))
            .map_err(|_| AgentKeyError::BadRotation)
    }

    /// The key id: the first 16 bytes of `SHA-256(ed25519_pub || x25519_pub)`.
    #[must_use]
    pub fn key_id_bytes(&self) -> [u8; Self::KEY_ID_LEN] {
        let mut hasher = Sha256::new();
        hasher.update(self.ed25519_pub);
        hasher.update(self.x25519_pub);
        let digest = hasher.finalize();
        let mut out = [0u8; Self::KEY_ID_LEN];
        out.copy_from_slice(&digest[..Self::KEY_ID_LEN]);
        out
    }

    /// The key id as text: 26 characters of lower-case Crockford base32
    /// without padding.
    #[must_use]
    pub fn key_id(&self) -> String {
        crockford::encode(&self.key_id_bytes())
    }

    /// The key id for a human to read or dictate: the 26 characters of
    /// [`KeyBundle::key_id`] in five groups of 4, 4, 4, 4 and 10, separated by
    /// hyphens.
    ///
    /// The grouping is 4-4-4-4-10 because 16 bytes are 128 bits, which is 26
    /// base32 characters, and 4-4-4-4 leaves exactly ten for the tail. The
    /// hyphens carry no information: strip them and you have the key id.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        let id = self.key_id();
        let mut out = String::with_capacity(FINGERPRINT_CHARS + 4);
        for group in 0..5 {
            if group > 0 {
                out.push('-');
            }
            let start = group * FINGERPRINT_GROUP;
            let end = if group == 4 {
                FINGERPRINT_CHARS
            } else {
                start + FINGERPRINT_GROUP
            };
            out.push_str(&id[start..end]);
        }
        out
    }

    /// The compact wire encoding: `ed25519_pub || x25519_pub || u64be
    /// (created_at) || u32be(len(agent_name)) || agent_name || u32be(len
    /// (account_id)) || account_id`, the whole thing after
    /// [`KeyBundle::WIRE_FIXED_LEN`] being variable-length strings. This is the
    /// shape of an HTTP body, not the shape that is signed.
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::WIRE_FIXED_LEN + 8 + self.string_len());
        out.extend_from_slice(&self.ed25519_pub);
        out.extend_from_slice(&self.x25519_pub);
        out.extend_from_slice(&self.created_at.to_be_bytes());
        push_string(&mut out, &self.agent_name);
        push_string(&mut out, &self.account_id);
        out
    }

    /// Parse the wire encoding of [`KeyBundle::to_wire`].
    ///
    /// # Errors
    ///
    /// Returns [`AgentKeyError::BadWire`] if the input is too short, if a
    /// length prefix runs past the end, or if either string is not valid UTF-8;
    /// and [`AgentKeyError::NameTooLong`] or
    /// [`AgentKeyError::AccountIdTooLong`] if a string is empty or over
    /// [`MAX_NAME_LEN`].
    pub fn from_wire(bytes: &[u8]) -> Result<Self, AgentKeyError> {
        let fixed: [u8; Self::WIRE_FIXED_LEN] = bytes
            .get(..Self::WIRE_FIXED_LEN)
            .and_then(|slice| slice.try_into().ok())
            .ok_or(AgentKeyError::BadWire)?;
        let mut ed25519_pub = [0u8; 32];
        let mut x25519_pub = [0u8; 32];
        ed25519_pub.copy_from_slice(&fixed[..32]);
        x25519_pub.copy_from_slice(&fixed[32..64]);
        let mut created_at = [0u8; 8];
        created_at.copy_from_slice(&fixed[64..72]);
        let created_at = u64::from_be_bytes(created_at);

        let (agent_name, rest) = take_string(&bytes[Self::WIRE_FIXED_LEN..])?;
        let (account_id, rest) = take_string(rest)?;
        if !rest.is_empty() {
            return Err(AgentKeyError::BadWire);
        }
        validate_name(&agent_name)?;
        validate_account_id(&account_id)?;
        Ok(Self {
            ed25519_pub,
            x25519_pub,
            created_at,
            agent_name,
            account_id,
        })
    }

    /// What the two length-prefixed strings contribute: their bytes and their
    /// two four-byte prefixes.
    fn string_len(&self) -> usize {
        self.agent_name.len() + self.account_id.len() + 8
    }

    /// Check the field rules, for bundles built by struct literal rather than
    /// by [`KeyBundle::generate`] or [`KeyBundle::from_wire`].
    ///
    /// # Errors
    ///
    /// As [`KeyBundle::verify_binding`] documents.
    fn validate(&self) -> Result<(), AgentKeyError> {
        validate_name(&self.agent_name)?;
        validate_account_id(&self.account_id)
    }
}

impl AgentKeyPair {
    /// Assemble a pair from two secret keys, as stored by an agent.
    #[must_use]
    pub fn from_secret_bytes(ed25519_secret: [u8; 32], x25519_secret: [u8; 32]) -> Self {
        Self::new(
            SigningKey::from_bytes(&ed25519_secret),
            StaticSecret::from(x25519_secret),
        )
    }

    /// The two secret keys, for writing to the agent's own key file.
    ///
    /// Read back with [`AgentKeyPair::from_secret_bytes`]. A caller MUST NOT
    /// log this value or put it in a request body; `Debug` redacts it, this
    /// method deliberately does not.
    #[must_use]
    pub fn secret_bytes(&self) -> ([u8; 32], [u8; 32]) {
        (self.signing.to_bytes(), self.static_secret.to_bytes())
    }

    /// The Ed25519 secret, for handing to [`KeyBundle::sign`].
    #[must_use]
    pub fn signing_key(&self) -> SigningKey {
        self.signing.clone()
    }

    /// The X25519 secret, for the key agreement the bundle exists for. The
    /// caller MUST reject an all-zero shared secret (§14).
    #[must_use]
    pub fn static_secret(&self) -> StaticSecret {
        self.static_secret.clone()
    }

    /// The public bundle this pair stands for.
    #[must_use]
    pub fn public_bundle(&self) -> ([u8; 32], [u8; 32]) {
        (
            self.signing.verifying_key().to_bytes(),
            X25519Public::from(&self.static_secret).to_bytes(),
        )
    }

    fn new(signing: SigningKey, static_secret: StaticSecret) -> Self {
        Self {
            signing,
            static_secret,
        }
    }
}

impl core::fmt::Debug for AgentKeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AgentKeyPair([redacted])")
    }
}

/// Parse a 26-character key id back to its 16 bytes.
///
/// Upper case is accepted and `i`, `l`, `o` and `u` decode as the digit they
/// resemble, so a key id read aloud or copied by hand still parses.
///
/// # Errors
///
/// Returns [`AgentKeyError::BadKeyId`] if `id` is not 26 characters of the
/// Crockford alphabet.
pub fn key_id_to_bytes(id: &str) -> Result<[u8; KeyBundle::KEY_ID_LEN], AgentKeyError> {
    crockford::decode_16(id).ok_or(AgentKeyError::BadKeyId)
}

/// Sign a message with an Ed25519 key, returning the 64 signature bytes.
fn sign(message: &[u8], key: &SigningKey) -> [u8; 64] {
    let signature: Signature = key.sign(message);
    signature.to_bytes()
}

/// The Ed25519 public key as a verifier.
fn verifying_key(bytes: &[u8; 32]) -> Result<VerifyingKey, AgentKeyError> {
    VerifyingKey::from_bytes(bytes).map_err(|_| AgentKeyError::BadEd25519Key)
}

/// Append a length-prefixed UTF-8 string.
///
/// # Panics
///
/// Never: a string longer than 4 GiB cannot be held in memory here, and the
/// field rules cap both strings at [`MAX_NAME_LEN`] anyway.
fn push_string(out: &mut Vec<u8>, value: &str) {
    let len = u32::try_from(value.len()).expect("a string of at most 4 GiB");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value.as_bytes());
}

/// Take one length-prefixed UTF-8 string off the front of `bytes`.
fn take_string(bytes: &[u8]) -> Result<(String, &[u8]), AgentKeyError> {
    let prefix: [u8; 4] = bytes
        .get(..4)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(AgentKeyError::BadWire)?;
    let len = usize::try_from(u32::from_be_bytes(prefix)).map_err(|_| AgentKeyError::BadWire)?;
    let end = len.checked_add(4).ok_or(AgentKeyError::BadWire)?;
    let body = bytes.get(4..end).ok_or(AgentKeyError::BadWire)?;
    let text = core::str::from_utf8(body).map_err(|_| AgentKeyError::BadWire)?;
    Ok((text.to_owned(), &bytes[end..]))
}

fn validate_name(name: &str) -> Result<(), AgentKeyError> {
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return Err(AgentKeyError::NameTooLong);
    }
    Ok(())
}

fn validate_account_id(account_id: &str) -> Result<(), AgentKeyError> {
    if account_id.is_empty() || account_id.len() > MAX_NAME_LEN {
        return Err(AgentKeyError::AccountIdTooLong);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use rand_chacha::ChaCha20Rng;
    use rand_chacha::rand_core::SeedableRng as _;

    use super::{AgentKeyError, AgentKeyPair, KeyBundle, MAX_NAME_LEN, key_id_to_bytes};

    /// The fixed inputs every vector in this module is built from. They are
    /// the ones the spec's vectors use, so a reader can recompute the expected
    /// values by hand from §14.
    const ED25519_SECRET: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    const X25519_SECRET: [u8; 32] = [
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e,
        0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d,
        0x3e, 0x3f,
    ];
    const ED25519_SECRET_ROTATED: [u8; 32] = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e,
        0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d,
        0x5e, 0x5f,
    ];
    const X25519_SECRET_ROTATED: [u8; 32] = [
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e,
        0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d,
        0x7e, 0x7f,
    ];
    const AGENT_NAME: &str = "ledger-bot";
    const ACCOUNT_ID: &str = "acct_01hq8z4m";
    const CREATED_AT: u64 = 1_750_000_000;

    /// The canonical message, signature, key id and wire bytes for
    /// [`KeyBundle::agent`], cross-checked against Node's `WebCrypto`.
    const BINDING_MESSAGE: &str = "7365616c62696e2f76312f6167656e742d6b65792d62696e64696e67\
        0000000a6c65646765722d626f740000000d616363745f30316871387a346d00000000684ee180\
        358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254";
    const BINDING_SIGNATURE: &str = "74cc7255ee4bbd5b9f396552668a1fbeb83f7ea0bdcdfe12f185b24e3\
        7c932bd03cc51f6840366652d285c4151ff3f40866b9283cf0f0a0661c0ae671a160c05";
    const KEY_ID: &str = "6rcyem52vn9bn5w80ysa03fndm";
    const KEY_ID_BYTES: &str = "3619e750a2dd52ba978807b2a00df56d";
    const ROTATION_MESSAGE: &str = "7365616c62696e2f76312f6167656e742d6b65792d726f746174696f6e\
        ce04d757588b607db7dd1e31c428b180";
    const ROTATION_SIGNATURE: &str = "0fa60e7fa36d006c3e53d2e1f142ceed51372f37ffb3288849ecb382\
        2c3bc742092b85bfb9051a92d8713e5b30c88f07b8099b1423fda6861f1fc1339def8b02";

    /// A bundle and its key pair, from the fixed inputs above.
    fn bundle() -> (KeyBundle, AgentKeyPair) {
        let pair = AgentKeyPair::from_secret_bytes(ED25519_SECRET, X25519_SECRET);
        let (ed25519_pub, x25519_pub) = pair.public_bundle();
        let bundle = KeyBundle {
            ed25519_pub,
            x25519_pub,
            created_at: CREATED_AT,
            agent_name: AGENT_NAME.to_owned(),
            account_id: ACCOUNT_ID.to_owned(),
        };
        (bundle, pair)
    }

    /// The same bundle after a rotation: new keys, one second later.
    fn rotated() -> (KeyBundle, AgentKeyPair) {
        let pair = AgentKeyPair::from_secret_bytes(ED25519_SECRET_ROTATED, X25519_SECRET_ROTATED);
        let (ed25519_pub, x25519_pub) = pair.public_bundle();
        let bundle = KeyBundle {
            ed25519_pub,
            x25519_pub,
            created_at: CREATED_AT + 1,
            agent_name: AGENT_NAME.to_owned(),
            account_id: ACCOUNT_ID.to_owned(),
        };
        (bundle, pair)
    }

    fn unhex(text: &str) -> Vec<u8> {
        let bytes = text.as_bytes();
        assert!(bytes.len().is_multiple_of(2), "hex must be even-length");
        let (pairs, _) = bytes.as_chunks::<2>();
        pairs
            .iter()
            .map(|pair| hex_digit(pair[0]) << 4 | hex_digit(pair[1]))
            .collect()
    }

    fn hex_digit(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => panic!("lowercase hex only"),
        }
    }

    #[test]
    fn the_canonical_bytes_are_the_ones_the_spec_fixes() {
        let (bundle, _) = bundle();
        assert_eq!(bundle.binding_message(), unhex(BINDING_MESSAGE));
        assert_eq!(bundle.key_id_bytes()[..], unhex(KEY_ID_BYTES)[..]);
        assert_eq!(bundle.key_id(), KEY_ID);
        assert_eq!(bundle.fingerprint(), "6rcy-em52-vn9b-n5w8-0ysa03fndm");
        let (new, _) = rotated();
        assert_eq!(new.rotation_message(), unhex(ROTATION_MESSAGE));
    }

    #[test]
    fn a_binding_signature_verifies_and_matches_the_reference() {
        let (bundle, pair) = bundle();
        let signature = bundle.sign(&pair.signing_key());
        assert_eq!(signature[..], unhex(BINDING_SIGNATURE)[..]);
        assert_eq!(bundle.verify_binding(&signature), Ok(()));
    }

    #[test]
    fn every_signed_field_is_covered_by_the_binding_signature() {
        let (bundle, pair) = bundle();
        let signature = bundle.sign(&pair.signing_key());
        for (what, tampered) in [
            (
                "agent_name",
                KeyBundle {
                    agent_name: "ledger-bot2".to_owned(),
                    ..bundle.clone()
                },
            ),
            (
                "account_id",
                KeyBundle {
                    account_id: "acct_01hq8z4n".to_owned(),
                    ..bundle.clone()
                },
            ),
            (
                "created_at",
                KeyBundle {
                    created_at: CREATED_AT + 1,
                    ..bundle.clone()
                },
            ),
            (
                "x25519_pub",
                KeyBundle {
                    x25519_pub: [0x42; 32],
                    ..bundle.clone()
                },
            ),
        ] {
            assert_eq!(
                tampered.verify_binding(&signature),
                Err(AgentKeyError::BadBinding),
                "{what}"
            );
        }
    }

    #[test]
    fn a_binding_signature_from_another_key_fails() {
        let (bundle, _) = bundle();
        let (_, stranger) = rotated();
        let forged = bundle.sign(&stranger.signing_key());
        assert_eq!(
            bundle.verify_binding(&forged),
            Err(AgentKeyError::BadBinding)
        );
    }

    #[test]
    fn an_over_long_name_is_rejected_before_it_is_signed() {
        let (bundle, pair) = bundle();
        let signature = bundle.sign(&pair.signing_key());
        let long = KeyBundle {
            agent_name: "a".repeat(MAX_NAME_LEN + 1),
            ..bundle
        };
        assert_eq!(
            long.verify_binding(&signature),
            Err(AgentKeyError::NameTooLong)
        );
    }

    #[test]
    fn rotation_verifies_against_the_previous_key_only() {
        let (previous, previous_pair) = bundle();
        let (new, _) = rotated();
        let signature = new.sign_rotation(&previous_pair.signing_key());
        assert_eq!(signature[..], unhex(ROTATION_SIGNATURE)[..]);
        assert_eq!(new.verify_rotation(&previous, &signature), Ok(()));

        // The new key did not hand over to itself, and a stranger signed
        // nothing.
        assert_eq!(
            new.verify_rotation(&new, &signature),
            Err(AgentKeyError::BadRotation)
        );
        let (stranger, _) = bundle_from_seed(9);
        assert_eq!(
            new.verify_rotation(&stranger, &signature),
            Err(AgentKeyError::BadRotation)
        );
    }

    #[test]
    fn the_two_messages_are_domain_separated() {
        let (bundle, pair) = bundle();
        assert_eq!(bundle.rotation_message().len(), 29 + 16);
        let binding = bundle.sign(&pair.signing_key());
        let rotation = bundle.sign_rotation(&pair.signing_key());
        // Neither signature is a valid signature of the other message, even
        // though both come from the same key.
        assert_eq!(
            bundle.verify_rotation(&bundle, &binding),
            Err(AgentKeyError::BadRotation)
        );
        assert_eq!(
            bundle.verify_binding(&rotation),
            Err(AgentKeyError::BadBinding)
        );
    }

    #[test]
    fn generate_makes_a_matching_pair_and_a_valid_bundle() {
        let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
        let (bundle, pair) = KeyBundle::generate(AGENT_NAME, ACCOUNT_ID, CREATED_AT, &mut rng)
            .expect("short names are valid");
        assert_eq!(bundle.created_at, CREATED_AT);
        assert_eq!(bundle.agent_name, AGENT_NAME);
        assert_eq!(bundle.account_id, ACCOUNT_ID);
        assert_eq!(
            (bundle.ed25519_pub, bundle.x25519_pub),
            pair.public_bundle()
        );
        let signature = bundle.sign(&pair.signing_key());
        assert_eq!(bundle.verify_binding(&signature), Ok(()));

        let mut other = ChaCha20Rng::from_seed([7u8; 32]);
        let (again, _) = KeyBundle::generate(AGENT_NAME, ACCOUNT_ID, CREATED_AT, &mut other)
            .expect("short names are valid");
        assert_eq!(again.key_id(), bundle.key_id(), "the seed decides");
    }

    #[test]
    fn generate_refuses_names_it_cannot_encode() {
        let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
        assert_eq!(
            KeyBundle::generate("", ACCOUNT_ID, CREATED_AT, &mut rng).map(|_| ()),
            Err(AgentKeyError::NameTooLong)
        );
        assert_eq!(
            KeyBundle::generate(AGENT_NAME, "", CREATED_AT, &mut rng).map(|_| ()),
            Err(AgentKeyError::AccountIdTooLong)
        );
        assert_eq!(
            KeyBundle::generate(
                AGENT_NAME,
                &"a".repeat(MAX_NAME_LEN + 1),
                CREATED_AT,
                &mut rng
            )
            .map(|_| ()),
            Err(AgentKeyError::AccountIdTooLong)
        );
    }

    #[test]
    fn the_wire_encoding_round_trips_and_is_the_body_shape() {
        let (bundle, _) = bundle();
        let wire = bundle.to_wire();
        assert_eq!(wire.len(), KeyBundle::WIRE_FIXED_LEN + 4 + 10 + 4 + 13);
        assert_eq!(KeyBundle::from_wire(&wire).unwrap(), bundle);
        assert_eq!(
            KeyBundle::from_wire(&wire[..wire.len() - 1]),
            Err(AgentKeyError::BadWire)
        );
        let mut trailing = wire.clone();
        trailing.push(0);
        assert_eq!(KeyBundle::from_wire(&trailing), Err(AgentKeyError::BadWire));
    }

    #[test]
    fn a_key_id_round_trips_through_its_text_form() {
        let (bundle, _) = bundle();
        let id = bundle.key_id();
        assert_eq!(id.len(), KeyBundle::KEY_ID_CHARS);
        assert_eq!(key_id_to_bytes(&id), Ok(bundle.key_id_bytes()));
        assert_eq!(
            key_id_to_bytes(&id.to_uppercase()),
            Ok(bundle.key_id_bytes())
        );
        assert_eq!(key_id_to_bytes(&id[..25]), Err(AgentKeyError::BadKeyId));
        let mut starred = id.clone();
        starred.replace_range(0..1, "*");
        assert_eq!(key_id_to_bytes(&starred), Err(AgentKeyError::BadKeyId));
    }

    #[test]
    fn a_fingerprint_is_five_groups_of_4_4_4_4_10() {
        let (bundle, _) = bundle();
        let fingerprint = bundle.fingerprint();
        let groups: Vec<&str> = fingerprint.split('-').collect();
        assert_eq!(groups.len(), 5);
        assert_eq!(
            groups.iter().map(|group| group.len()).collect::<Vec<_>>(),
            vec![4, 4, 4, 4, 10]
        );
        assert_eq!(fingerprint.replace('-', ""), bundle.key_id());
        assert_eq!(fingerprint.len(), KeyBundle::KEY_ID_CHARS + 4);
    }

    #[test]
    fn the_key_id_covers_both_public_keys() {
        let (bundle, _) = bundle();
        let other = KeyBundle {
            x25519_pub: [0x42; 32],
            ..bundle.clone()
        };
        let other = KeyBundle {
            ed25519_pub: [0x42; 32],
            ..other
        };
        assert_ne!(other.key_id(), bundle.key_id());
        // The order is fixed: Ed25519 first, then X25519.
        assert_ne!(
            KeyBundle {
                ed25519_pub: bundle.x25519_pub,
                x25519_pub: bundle.ed25519_pub,
                ..bundle.clone()
            }
            .key_id(),
            bundle.key_id()
        );
    }

    #[test]
    fn a_bundle_with_an_invalid_ed25519_key_is_refused() {
        let (bundle, _) = bundle();
        let mut bad = bundle;
        // Not a point on the curve: `VerifyingKey::from_bytes` refuses it.
        bad.ed25519_pub = [2u8; 32];
        assert_eq!(
            bad.verify_binding(&[0u8; 64]),
            Err(AgentKeyError::BadEd25519Key)
        );
    }

    #[test]
    fn a_key_pair_never_prints_its_secrets() {
        let (_, pair) = bundle();
        assert_eq!(format!("{pair:?}"), "AgentKeyPair([redacted])");
    }

    fn bundle_from_seed(seed: u8) -> (KeyBundle, AgentKeyPair) {
        let mut rng = ChaCha20Rng::from_seed([seed; 32]);
        KeyBundle::generate(AGENT_NAME, ACCOUNT_ID, CREATED_AT, &mut rng)
            .expect("short names are valid")
    }
}
