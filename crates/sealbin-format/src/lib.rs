//! The sealbin handoff format.
//!
//! One crate holds the link, the envelope, the chunked AEAD, the KDFs, the read
//! token and the bundle — the wire format specified in `spec/`, nothing else.
//!
//! Rules (design decisions D4–D6):
//! - **Pure.** No I/O, no clocks, no randomness except through a caller-supplied
//!   RNG. Everything here is a function of its inputs and a byte slice.
//! - **Portable.** Compiles native and for `wasm32-unknown-unknown`: a browser
//!   must be able to open a link with no plugin, so no native-only crypto.
//! - **Frozen.** The crypto changes only with a spec change in `spec/` and new
//!   test vectors, in the same pull request.
//!
//! # Modules
//!
//! - [`link`]: the `https://host/s/<id>#key=…` link, its id and its key.
//! - [`header`]: the 49-byte cleartext envelope header.
//! - [`keys`]: HKDF-SHA256 over the input keying material, and the derived
//!   payload key and read token.
//! - [`stream`]: STREAM chunked AES-256-GCM; the streaming encryptor, decryptor
//!   and header-stripping opener.
//! - [`envelope`]: whole-buffer `seal`/`open` helpers over the streaming types.
//! - [`agent_keys`]: the agent key bundle — its Ed25519 and X25519 public keys,
//!   its key id, and the binding and rotation signatures (§14).
//! - [`error`]: one [`FormatError`] with a spec error name per variant.
//!
//! # Memory
//!
//! The streaming types bound their buffers to a small constant, not to the
//! payload size: the [`Encryptor`] keeps at most one chunk plus one byte of
//! plaintext (it holds back its last full chunk, which may be final), and the
//! [`Decryptor`] keeps at most one chunk plus its tag plus one byte of
//! ciphertext (it looks one byte ahead to tell a full non-final chunk from a
//! final one). Calls that hand a whole payload to the convenience helpers in
//! [`envelope`] hold the whole ciphertext, as their signatures imply.
//!
//! # Secrets
//!
//! Every secret type — [`LinkKey`], [`PayloadKey`], [`ReadToken`], [`Ikm`],
//! [`AgentKeyPair`] — zeroises on drop, prints `[redacted]` from `Debug`, and
//! has no `Display` or `serde::Serialize`, so it cannot reach a log or a
//! request body by accident. Errors carry no data, so they cannot leak a
//! fragment either.

mod b64;
mod crockford;
mod secret;

pub mod agent_keys;
pub mod envelope;
pub mod error;
pub mod header;
pub mod keys;
pub mod link;
pub mod stream;

pub use agent_keys::{AgentKeyError, AgentKeyPair, KeyBundle, key_id_to_bytes};
pub use envelope::{open_bytes, open_with_ikm, seal_bytes, seal_with_ikm};
pub use error::FormatError;
pub use header::{Header, PublicInfo};
pub use keys::{Ikm, KeySchedule, PayloadKey, ReadToken};
pub use link::{Link, LinkKey, SealId};
pub use stream::{Decryptor, Encryptor, Opener};
