//! The seal lifecycle state machine.
//!
//! A seal moves `Uploading -> Sealed -> Opening -> Gone` (D8, spec §9). This
//! module is pure: every command takes the current unix-milliseconds time as an
//! argument and returns the outcome plus a list of [`Effect`]s for the caller
//! to carry out. There is no clock, no randomness and no I/O here, so the whole
//! machine is testable as plain Rust and compiles for `wasm32-unknown-unknown`.
//!
//! Production runs one [`SealRecord`] inside a Durable Object, whose
//! single-threaded, serial execution is what makes "atomic" true: "exactly one
//! of any number of concurrent opens wins" (spec §9) reduces to running the
//! calls one after another on one record.

use core::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ids::SealId;

/// How long after the first burn-seal open the holder may `reopen`, in
/// milliseconds (D8, spec §9).
pub const REOPEN_WINDOW_MS: i64 = 60_000;

/// The default time to live of an unopened seal: 24 hours (D8, D13).
pub const DEFAULT_TTL_MS: i64 = 24 * 60 * 60 * 1000;

/// The first wrong-key backoff: 1 second (D6, spec §4).
pub const INITIAL_BACKOFF_MS: i64 = 1_000;

/// The wrong-key backoff ceiling: 5 minutes (D6, spec §4).
pub const MAX_BACKOFF_MS: i64 = 300_000;

/// SHA-256 of a 32-byte token.
///
/// This is `read_verifier = SHA-256(read_token)` (spec §4) and the stored
/// `SHA-256(reopen_token)` (spec §9). Public so callers can build records and
/// so tests can compute the values they assert on.
#[must_use]
pub fn hash_token(token: &[u8; 32]) -> [u8; 32] {
    let digest = Sha256::digest(token);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..]);
    out
}

/// Constant-time equality of two 32-byte values.
///
/// XOR-folds the difference and compares the fold to zero: no early exit, no
/// extra crate, no `unsafe`. Used for the `read_token` and `reopen_token`
/// comparisons (spec §4).
#[must_use]
pub(crate) fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// The exponential wrong-key backoff after `failed_attempts` consecutive
/// failures: `min(INITIAL_BACKOFF_MS << (n - 1), MAX_BACKOFF_MS)`.
///
/// The shift is bounded so it can never overflow; the product is saturated and
/// then capped.
fn backoff_for(failed_attempts: u32) -> i64 {
    let shift = failed_attempts.saturating_sub(1).min(40);
    let factor = 1i64 << shift;
    INITIAL_BACKOFF_MS
        .saturating_mul(factor)
        .min(MAX_BACKOFF_MS)
}

/// Where a seal's ciphertext lives (D9).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Storage {
    /// Stored inline in the Durable Object (ciphertext at or below the inline
    /// limit).
    Inline,
    /// Stored in R2 at `key` (a multipart upload, larger than the inline
    /// limit).
    R2 {
        /// The R2 object key, `seals/<id>` in production.
        key: String,
    },
}

/// Why a seal is [`State::Gone`] (spec §9).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GoneReason {
    /// A TTL-free burn read ended the seal.
    ///
    /// Reserved: no transition in this design produces `Read`. The variant is
    /// kept because the issue defines it and issues #8/#30 may use it; burn
    /// seals end via [`GoneReason::Acked`] or
    /// [`GoneReason::ReopenWindowClosed`] instead.
    Read,
    /// The TTL passed with the seal still unopened.
    Expired,
    /// The sealer deleted it (`DELETE /v1/seals/{id}`).
    Revoked,
    /// The holder acknowledged the read; deleted at once.
    Acked,
    /// The 60-second reopen window ended without an `ack`.
    ReopenWindowClosed,
    /// Removed for abuse.
    Abuse,
}

/// The lifecycle state of a seal (D8, spec §9).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum State {
    /// A multipart upload is in progress; the seal is not yet readable.
    Uploading {
        /// The upload id from `POST /v1/seals/uploads`.
        upload_id: String,
        /// How many parts have arrived.
        parts_received: u32,
    },
    /// Stored and never opened.
    Sealed,
    /// A burn seal claimed by one reader, inside its reopen window.
    ///
    /// The issue listed an `acked: bool` here, but `ack` moves straight to
    /// [`State::Gone`] with [`GoneReason::Acked`], so the flag would always be
    /// false. It is omitted: an unrepresentable state is better than an
    /// unrepresentable-by-convention one.
    Opening {
        /// When the first successful open happened.
        opened_at: i64,
        /// `SHA-256(reopen_token)`; only the holder of the token can reopen.
        #[serde(with = "hex32")]
        reopen_hash: [u8; 32],
    },
    /// The ciphertext is deleted; every command is a no-op.
    Gone {
        /// Why the seal ended.
        reason: GoneReason,
        /// When it ended.
        at: i64,
    },
}

/// Something the caller must carry out after a command (D9, spec §9).
///
/// Never persisted, so no serde: it is returned to the caller and acted on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Effect {
    /// Delete the stored ciphertext. Emitted exactly once per seal, ever.
    DeleteCiphertext,
    /// Abort the multipart upload instead of deleting an object.
    AbortUpload,
    /// Set the Durable Object alarm to fire at this unix-milliseconds time.
    SetAlarm(i64),
    /// Append an audit event.
    RecordEvent(AuditEvent),
}

/// An audit-log entry. The server maps these onto `POST /v1/audit` (D10).
///
/// Never persisted by this crate, so no serde.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditEvent {
    /// A successful open at `at` (the first, for a burn seal).
    Opened {
        /// When.
        at: i64,
    },
    /// A successful reopen inside the window.
    Reopened {
        /// When.
        at: i64,
    },
    /// A wrong `read_token`; state did not change.
    WrongKey {
        /// When.
        at: i64,
        /// The failure count after this attempt.
        failed_attempts: u32,
    },
    /// The seal ended.
    Gone {
        /// Why.
        reason: GoneReason,
        /// When.
        at: i64,
    },
}

/// The fields needed to create a seal. Mirrors the `POST /v1/seals` body
/// (D10): all values are already known at creation time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewSeal {
    /// The server-generated id.
    pub id: SealId,
    /// Creation time, unix milliseconds.
    pub created_at: i64,
    /// When the unopened seal expires, unix milliseconds.
    pub expires_at: i64,
    /// Whether the first open burns the seal.
    pub burn: bool,
    /// `SHA-256(read_token)` (spec §4).
    pub read_verifier: [u8; 32],
    /// Whether the reader needs a password to derive `read_token`.
    pub password: bool,
    /// Ciphertext size in bytes.
    pub size: u64,
    /// Where the ciphertext lives.
    pub storage: Storage,
}

/// Outcome of [`SealRecord::open`].
///
/// `Debug` is hand-written and redacts the reopen token: it is a raw secret and
/// must never reach a log (AGENTS.md). `PartialEq` still compares the real
/// value, so tests can assert on it.
#[derive(Clone, PartialEq, Eq)]
pub enum OpenOutcome {
    /// The open succeeded.
    Granted {
        /// Present for a burn seal: the token that lets the same client reopen
        /// inside the window. `None` for a non-burn seal (no window).
        reopen_token: Option<[u8; 32]>,
    },
    /// The seal is gone, not yet ready, or already claimed by another reader.
    Gone,
    /// The `read_token` did not match. The seal is unchanged.
    WrongKey {
        /// Wait at least this long before the next attempt.
        retry_after_ms: i64,
    },
    /// Inside the wrong-key backoff; the token was not even evaluated.
    Throttled {
        /// Milliseconds until the next attempt is allowed.
        retry_after_ms: i64,
    },
}

impl fmt::Debug for OpenOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OpenOutcome::Granted { reopen_token } => f
                .debug_struct("Granted")
                .field("reopen_token", &reopen_token.map(|_| "<redacted>"))
                .finish(),
            OpenOutcome::Gone => f.write_str("Gone"),
            OpenOutcome::WrongKey { retry_after_ms } => f
                .debug_struct("WrongKey")
                .field("retry_after_ms", retry_after_ms)
                .finish(),
            OpenOutcome::Throttled { retry_after_ms } => f
                .debug_struct("Throttled")
                .field("retry_after_ms", retry_after_ms)
                .finish(),
        }
    }
}

/// Outcome of [`SealRecord::reopen`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReopenOutcome {
    /// The holder presented the right token inside the window.
    Granted,
    /// Not the holder, not in the window, or already gone.
    Gone,
}

/// Outcome of [`SealRecord::ack`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AckOutcome {
    /// The holder ended the window; the seal is now [`State::Gone`].
    Acked,
    /// Not the holder, not in the window, or already gone.
    Ignored,
}

/// The state the public `GET /v1/seals/{id}` reports (D10, spec §10).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum MetadataState {
    /// Stored, unopened and unexpired.
    Sealed,
    /// Gone, or not yet opened into a settled state.
    Gone,
}

/// Non-burning metadata for a seal (spec §10).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Metadata {
    /// `sealed` or `gone`.
    pub state: MetadataState,
    /// Ciphertext size in bytes.
    pub size: u64,
    /// When the unopened seal expires, unix milliseconds.
    pub expires_at: i64,
    /// Whether the first open burns the seal.
    pub burn: bool,
    /// Whether a password is required.
    pub password: bool,
}

/// One seal, and the whole lifecycle state machine.
///
/// All times are unix milliseconds and are passed in to every command: the
/// record never reads a clock. Public fields are fine here; the invariants are
/// enforced by the command methods, not by privacy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealRecord {
    /// The seal id (also the Durable Object name, D9).
    pub id: SealId,
    /// Creation time.
    pub created_at: i64,
    /// When the unopened seal expires.
    pub expires_at: i64,
    /// Whether the first open burns the seal.
    pub burn: bool,
    /// `SHA-256(read_token)`.
    #[serde(with = "hex32")]
    pub read_verifier: [u8; 32],
    /// Whether a password is required to derive `read_token`.
    pub password: bool,
    /// Ciphertext size in bytes.
    pub size: u64,
    /// Where the ciphertext lives.
    pub storage: Storage,
    /// The lifecycle state.
    pub state: State,
    /// Consecutive wrong-key attempts, reset on success (D6).
    pub failed_attempts: u32,
    /// Writes reject an open before this time, unix milliseconds.
    pub next_attempt_at: Option<i64>,
    /// Successful reads so far.
    pub reads: u32,
}

impl SealRecord {
    /// A new, [`State::Sealed`] record with all counters zero.
    #[must_use]
    pub fn new(new: NewSeal) -> Self {
        Self {
            id: new.id,
            created_at: new.created_at,
            expires_at: new.expires_at,
            burn: new.burn,
            read_verifier: new.read_verifier,
            password: new.password,
            size: new.size,
            storage: new.storage,
            state: State::Sealed,
            failed_attempts: 0,
            next_attempt_at: None,
            reads: 0,
        }
    }

    /// A new record in [`State::Uploading`], before the upload is complete.
    #[must_use]
    pub fn new_uploading(new: NewSeal, upload_id: String) -> Self {
        Self {
            state: State::Uploading {
                upload_id,
                parts_received: 0,
            },
            ..Self::new(new)
        }
    }

    /// The time of the next alarm this record needs, or `None` when gone
    /// (D9: the Durable Object alarms to expire and to close the window).
    #[must_use]
    pub fn next_alarm(&self) -> Option<i64> {
        match &self.state {
            State::Sealed | State::Uploading { .. } => Some(self.expires_at),
            State::Opening { opened_at, .. } => Some(opened_at.saturating_add(REOPEN_WINDOW_MS)),
            State::Gone { .. } => None,
        }
    }

    /// Non-burning metadata, computed as if settled. Never mutates (spec §10).
    #[must_use]
    pub fn metadata(&self, now: i64) -> Metadata {
        let state = if matches!(self.state, State::Sealed) && now < self.expires_at {
            MetadataState::Sealed
        } else {
            MetadataState::Gone
        };
        Metadata {
            state,
            size: self.size,
            expires_at: self.expires_at,
            burn: self.burn,
            password: self.password,
        }
    }

    /// Apply the time-based transitions, appending any effects (spec §9).
    ///
    /// A `Sealed` or `Uploading` seal at or past `expires_at` becomes
    /// [`GoneReason::Expired`]; an `Opening` seal at or past
    /// `opened_at + REOPEN_WINDOW_MS` becomes
    /// [`GoneReason::ReopenWindowClosed`]. TTL expiry does not cut an open
    /// window short, so `Opening` ignores `expires_at` entirely.
    fn settle(&mut self, now: i64, effects: &mut Vec<Effect>) {
        let reason = match &self.state {
            State::Sealed | State::Uploading { .. } => {
                (now >= self.expires_at).then_some(GoneReason::Expired)
            }
            State::Opening { opened_at, .. } => (now >= opened_at.saturating_add(REOPEN_WINDOW_MS))
                .then_some(GoneReason::ReopenWindowClosed),
            State::Gone { .. } => None,
        };
        if let Some(reason) = reason {
            self.transition_gone(reason, now, effects);
        }
    }

    /// Move to [`State::Gone`], emitting exactly one delete effect and one
    /// audit event. Callers must ensure the record is not already gone.
    fn transition_gone(&mut self, reason: GoneReason, at: i64, effects: &mut Vec<Effect>) {
        let was_uploading = matches!(self.state, State::Uploading { .. });
        self.state = State::Gone { reason, at };
        effects.push(if was_uploading {
            Effect::AbortUpload
        } else {
            Effect::DeleteCiphertext
        });
        effects.push(Effect::RecordEvent(AuditEvent::Gone { reason, at }));
    }

    /// Open a seal with the reader's `read_token`; `reopen_secret` becomes the
    /// reopen token if the seal is a burn seal.
    ///
    /// A wrong token never changes the state and never destroys the seal: it
    /// only bumps the failure counter and the backoff (D6, spec §4, spec §9).
    /// A second opener, however close in time, gets [`OpenOutcome::Gone`] and
    /// leaves the first opener's window intact.
    #[must_use]
    pub fn open(
        &mut self,
        now: i64,
        read_token: &[u8; 32],
        reopen_secret: [u8; 32],
    ) -> (OpenOutcome, Vec<Effect>) {
        let mut effects = Vec::new();
        self.settle(now, &mut effects);

        if matches!(
            self.state,
            State::Gone { .. } | State::Uploading { .. } | State::Opening { .. }
        ) {
            return (OpenOutcome::Gone, effects);
        }

        if let Some(next) = self.next_attempt_at
            && now < next
        {
            return (
                OpenOutcome::Throttled {
                    retry_after_ms: next.saturating_sub(now),
                },
                effects,
            );
        }

        if !ct_eq(&hash_token(read_token), &self.read_verifier) {
            self.failed_attempts += 1;
            let backoff = backoff_for(self.failed_attempts);
            self.next_attempt_at = Some(now.saturating_add(backoff));
            effects.push(Effect::RecordEvent(AuditEvent::WrongKey {
                at: now,
                failed_attempts: self.failed_attempts,
            }));
            return (
                OpenOutcome::WrongKey {
                    retry_after_ms: backoff,
                },
                effects,
            );
        }

        self.failed_attempts = 0;
        self.next_attempt_at = None;
        self.reads += 1;

        let reopen_token = if self.burn {
            self.state = State::Opening {
                opened_at: now,
                reopen_hash: hash_token(&reopen_secret),
            };
            effects.push(Effect::SetAlarm(now.saturating_add(REOPEN_WINDOW_MS)));
            Some(reopen_secret)
        } else {
            None
        };
        effects.push(Effect::RecordEvent(AuditEvent::Opened { at: now }));
        (OpenOutcome::Granted { reopen_token }, effects)
    }

    /// Read again inside the window, as the holder of the `reopen_token`.
    ///
    /// A wrong token is [`ReopenOutcome::Gone`] and leaves the state alone, so
    /// it cannot end the holder's window early (spec §9).
    #[must_use]
    pub fn reopen(&mut self, now: i64, reopen_token: &[u8; 32]) -> (ReopenOutcome, Vec<Effect>) {
        let mut effects = Vec::new();
        self.settle(now, &mut effects);

        let State::Opening { reopen_hash, .. } = self.state else {
            return (ReopenOutcome::Gone, effects);
        };
        if !ct_eq(&hash_token(reopen_token), &reopen_hash) {
            return (ReopenOutcome::Gone, effects);
        }
        self.reads += 1;
        effects.push(Effect::RecordEvent(AuditEvent::Reopened { at: now }));
        (ReopenOutcome::Granted, effects)
    }

    /// Acknowledge the read, ending the window at once.
    #[must_use]
    pub fn ack(&mut self, now: i64, reopen_token: &[u8; 32]) -> (AckOutcome, Vec<Effect>) {
        let mut effects = Vec::new();
        self.settle(now, &mut effects);

        let State::Opening { reopen_hash, .. } = self.state else {
            return (AckOutcome::Ignored, effects);
        };
        if !ct_eq(&hash_token(reopen_token), &reopen_hash) {
            return (AckOutcome::Ignored, effects);
        }
        self.transition_gone(GoneReason::Acked, now, &mut effects);
        (AckOutcome::Acked, effects)
    }

    /// Settle time-based transitions and report the next alarm.
    #[must_use]
    pub fn alarm(&mut self, now: i64) -> (Option<i64>, Vec<Effect>) {
        let mut effects = Vec::new();
        self.settle(now, &mut effects);
        (self.next_alarm(), effects)
    }

    /// The sealer revokes the seal (`DELETE /v1/seals/{id}`). No-op if gone.
    #[must_use]
    pub fn revoke(&mut self, now: i64) -> Vec<Effect> {
        let mut effects = Vec::new();
        self.settle(now, &mut effects);
        if !matches!(self.state, State::Gone { .. }) {
            self.transition_gone(GoneReason::Revoked, now, &mut effects);
        }
        effects
    }

    /// Remove the seal for abuse. No-op if gone.
    #[must_use]
    pub fn take_down(&mut self, now: i64) -> Vec<Effect> {
        let mut effects = Vec::new();
        self.settle(now, &mut effects);
        if !matches!(self.state, State::Gone { .. }) {
            self.transition_gone(GoneReason::Abuse, now, &mut effects);
        }
        effects
    }
}

/// Lowercase hex for `[u8; 32]` fields, used with `#[serde(with = "hex32")]`.
///
/// A fixed 64-character string is a stable, human-readable shape for the two
/// hashes a record persists (D9). Hand-rolled so no new dependency is needed.
mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};

    const HEX: &[u8; 16] = b"0123456789abcdef";

    pub fn serialize<S: Serializer>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        let mut text = String::with_capacity(64);
        for &byte in value {
            text.push(char::from(HEX[usize::from(byte >> 4)]));
            text.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        serializer.serialize_str(&text)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
        let text = String::deserialize(deserializer)?;
        let bytes = text.as_bytes();
        if bytes.len() != 64 {
            return Err(serde::de::Error::custom("expected 64 hex characters"));
        }
        let mut out = [0u8; 32];
        let (pairs, _remainder) = bytes.as_chunks::<2>();
        for (i, pair) in pairs.iter().enumerate() {
            let hi = nibble(pair[0]).ok_or_else(|| serde::de::Error::custom("invalid hex"))?;
            let lo = nibble(pair[1]).ok_or_else(|| serde::de::Error::custom("invalid hex"))?;
            out[i] = (hi << 4) | lo;
        }
        Ok(out)
    }

    fn nibble(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const READ: [u8; 32] = [1; 32];
    const WRONG: [u8; 32] = [2; 32];
    const REOPEN: [u8; 32] = [3; 32];

    fn record(state: State, expires_at: i64) -> SealRecord {
        let mut rec = SealRecord::new(NewSeal {
            id: SealId::parse("Ab3xY9zQ0pLm").unwrap(),
            created_at: 0,
            expires_at,
            burn: true,
            read_verifier: hash_token(&READ),
            password: false,
            size: 0,
            storage: Storage::Inline,
        });
        rec.state = state;
        rec
    }

    #[test]
    fn ct_eq_folds_without_early_exit() {
        assert!(ct_eq(&READ, &READ));
        assert!(!ct_eq(&READ, &WRONG));
        let mut one_bit = READ;
        one_bit[31] ^= 1;
        assert!(!ct_eq(&READ, &one_bit));
    }

    /// Persisted records from #8 may hold hostile values, so arithmetic on
    /// times must saturate and never panic — even at `i64::MAX`.
    #[test]
    fn hostile_times_saturate() {
        // A burn open one millisecond below i64::MAX: the alarm saturates.
        let mut rec = record(State::Sealed, i64::MAX);
        let (outcome, effects) = rec.open(i64::MAX - 1, &READ, REOPEN);
        assert!(matches!(outcome, OpenOutcome::Granted { .. }));
        assert_eq!(
            effects,
            vec![
                Effect::SetAlarm(i64::MAX),
                Effect::RecordEvent(AuditEvent::Opened { at: i64::MAX - 1 }),
            ]
        );
        assert_eq!(rec.next_alarm(), Some(i64::MAX));

        // A wrong key one millisecond below i64::MAX saturates `now + backoff`.
        let mut rec = record(State::Sealed, i64::MAX);
        let (outcome, _) = rec.open(i64::MAX - 1, &WRONG, REOPEN);
        assert_eq!(
            outcome,
            OpenOutcome::WrongKey {
                retry_after_ms: 1_000
            }
        );
        assert_eq!(rec.next_attempt_at, Some(i64::MAX));

        // Throttled across the whole range saturates `next - now`.
        let mut rec = record(State::Sealed, i64::MAX);
        rec.next_attempt_at = Some(i64::MAX);
        let (outcome, effects) = rec.open(i64::MIN, &READ, REOPEN);
        assert_eq!(
            outcome,
            OpenOutcome::Throttled {
                retry_after_ms: i64::MAX
            }
        );
        assert!(effects.is_empty());

        // An Opening seal whose window start saturates still settles to Gone.
        let mut rec = record(
            State::Opening {
                opened_at: i64::MAX - 10,
                reopen_hash: hash_token(&REOPEN),
            },
            i64::MAX,
        );
        let (next, effects) = rec.alarm(i64::MAX);
        assert_eq!(next, None);
        assert!(matches!(
            rec.state,
            State::Gone {
                reason: GoneReason::ReopenWindowClosed,
                ..
            }
        ));
        assert!(effects.contains(&Effect::DeleteCiphertext));
    }
}
