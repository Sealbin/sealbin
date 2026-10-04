//! The sealbin server domain, with no harness types.
//!
//! The seal state machine (`sealed -> opening -> gone`, D8), the plans as data
//! (D13) and the id and limit rules live here. It deliberately depends on
//! nothing from the Cratefield harness (D1), so the rules are testable as plain
//! Rust and usable from the CLI.
//!
//! The state machine is pure: every command takes the time as an argument and
//! returns its outcome plus the [`Effect`]s for the caller to carry out. See
//! `docs/design/seal-lifecycle.md` for the state diagram and the transition
//! table; the spec is `spec/handoff-format.md` §9.
//!
//! ```rust
//! use sealbin_core::{NewSeal, SealRecord, SealId, Storage, DEFAULT_TTL_MS, hash_token};
//!
//! let created = 1_000_000_i64;
//! let read_token = [7u8; 32];
//! let record = SealRecord::new(NewSeal {
//!     id: SealId::parse("Ab3xY9zQ0pLm").unwrap(),
//!     created_at: created,
//!     expires_at: created + DEFAULT_TTL_MS,
//!     burn: true,
//!     read_verifier: hash_token(&read_token),
//!     password: false,
//!     size: 4,
//!     storage: Storage::Inline,
//! });
//! assert!(matches!(record.state, sealbin_core::State::Sealed));
//! ```

pub mod ids;
pub mod seal;

pub use ids::{ID_LEN, IdError, SealId};
pub use seal::{
    AckOutcome, AuditEvent, DEFAULT_TTL_MS, Effect, GoneReason, INITIAL_BACKOFF_MS, MAX_BACKOFF_MS,
    Metadata, MetadataState, NewSeal, OpenOutcome, REOPEN_WINDOW_MS, ReopenOutcome, SealRecord,
    State, Storage, hash_token,
};
