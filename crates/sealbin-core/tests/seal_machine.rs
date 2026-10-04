//! The seal state machine, exercised as plain Rust.
//!
//! Three layers: a compact table over every (state, command) pair, the specific
//! properties D8 and spec §9 call out (same-millisecond race, the reopen window
//! boundary, backoff, non-burn reads), and a 10,000-case proptest.

use sealbin_core::{
    AckOutcome, AuditEvent, DEFAULT_TTL_MS, Effect, GoneReason, MetadataState, NewSeal,
    OpenOutcome, REOPEN_WINDOW_MS, ReopenOutcome, SealId, SealRecord, State, Storage, hash_token,
};

const T0: i64 = 1_000_000;
const EXP: i64 = T0 + DEFAULT_TTL_MS;
const WINDOW: i64 = REOPEN_WINDOW_MS;

const RIGHT_READ: [u8; 32] = [1; 32];
const WRONG_READ: [u8; 32] = [2; 32];
const RIGHT_REOPEN: [u8; 32] = [3; 32];
const WRONG_REOPEN: [u8; 32] = [4; 32];

const ID: &str = "Ab3xY9zQ0pLm";

// ---------------------------------------------------------------------------
// The (state, command) table
// ---------------------------------------------------------------------------

/// The starting record for a table row: `SealedExpired` and `UploadingExpired`
/// start at `expires_at == now`, `OpeningWindowPassed` at `opened_at + 60_000 ==
/// now`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Setup {
    Uploading,
    SealedBurn,
    SealedTtl,
    Opening,
    Gone,
    SealedExpired,
    UploadingExpired,
    OpeningWindowPassed,
}

/// The command a row runs. `Right`/`Wrong` pick the token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cmd {
    OpenRight,
    OpenWrong,
    ReopenRight,
    ReopenWrong,
    AckRight,
    AckWrong,
    Alarm,
    Revoke,
    TakeDown,
    Metadata,
}

#[rustfmt::skip]
const ALL_SETUPS: [Setup; 8] = [
    Setup::Uploading, Setup::SealedBurn, Setup::SealedTtl, Setup::Opening,
    Setup::Gone, Setup::SealedExpired, Setup::UploadingExpired, Setup::OpeningWindowPassed,
];

#[rustfmt::skip]
const ALL_CMDS: [Cmd; 10] = [
    Cmd::OpenRight, Cmd::OpenWrong, Cmd::ReopenRight, Cmd::ReopenWrong, Cmd::AckRight,
    Cmd::AckWrong, Cmd::Alarm, Cmd::Revoke, Cmd::TakeDown, Cmd::Metadata,
];

/// A normalised outcome, so one table can mix command types.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Obs {
    Open(OpenOutcome),
    Reopen(ReopenOutcome),
    Ack(AckOutcome),
    Alarm(Option<i64>),
    /// `revoke` and `take_down` return no outcome.
    EffectsOnly,
    Metadata(MetadataState),
}

/// The state after a row, at the granularity the table asserts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum After {
    Uploading,
    Sealed,
    Opening,
    Gone(GoneReason),
}

/// A normalised effect, so a row can name its exact effect list.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Eff {
    Delete,
    Abort,
    Alarm(i64),
    Opened(i64),
    Reopened(i64),
    WrongKey(i64, u32),
    Gone(GoneReason, i64),
}

struct Row {
    setup: Setup,
    cmd: Cmd,
    outcome: Obs,
    after: After,
    effects: &'static [Eff],
}

/// One row per line: `Setup / Cmd => outcome, state after, effects;`.
macro_rules! rows {
    ($( $setup:ident / $cmd:ident => $outcome:expr, $after:expr, $effects:expr; )*) => {
        &[ $( Row {
            setup: Setup::$setup,
            cmd: Cmd::$cmd,
            outcome: $outcome,
            after: $after,
            effects: $effects,
        }, )* ]
    };
}

// Shared expected values.
const GONE: Obs = Obs::Open(OpenOutcome::Gone);
const GRANT_BURN: Obs = Obs::Open(OpenOutcome::Granted {
    reopen_token: Some(RIGHT_REOPEN),
});
const GRANT_TTL: Obs = Obs::Open(OpenOutcome::Granted { reopen_token: None });
const WK_1S: Obs = Obs::Open(OpenOutcome::WrongKey {
    retry_after_ms: 1_000,
});
const RGONE: Obs = Obs::Reopen(ReopenOutcome::Gone);
const RGRANT: Obs = Obs::Reopen(ReopenOutcome::Granted);
const AIGN: Obs = Obs::Ack(AckOutcome::Ignored);
const AACK: Obs = Obs::Ack(AckOutcome::Acked);
const NOEFF: Obs = Obs::EffectsOnly;
const M_SEALED: Obs = Obs::Metadata(MetadataState::Sealed);
const M_GONE: Obs = Obs::Metadata(MetadataState::Gone);

const E_NONE: &[Eff] = &[];
const E_WRONGKEY: &[Eff] = &[Eff::WrongKey(T0, 1)];
const E_OPENED: &[Eff] = &[Eff::Opened(T0)];
const E_OPEN_BURN: &[Eff] = &[Eff::Alarm(T0 + WINDOW), Eff::Opened(T0)];
const E_REOPENED: &[Eff] = &[Eff::Reopened(T0)];
const E_DELETE_REVOKED: &[Eff] = &[Eff::Delete, Eff::Gone(GoneReason::Revoked, T0)];
const E_DELETE_ABUSE: &[Eff] = &[Eff::Delete, Eff::Gone(GoneReason::Abuse, T0)];
const E_DELETE_ACKED: &[Eff] = &[Eff::Delete, Eff::Gone(GoneReason::Acked, T0)];
const E_ABORT_REVOKED: &[Eff] = &[Eff::Abort, Eff::Gone(GoneReason::Revoked, T0)];
const E_ABORT_ABUSE: &[Eff] = &[Eff::Abort, Eff::Gone(GoneReason::Abuse, T0)];
const E_EXPIRED: &[Eff] = &[Eff::Delete, Eff::Gone(GoneReason::Expired, T0)];
const E_EXPIRED_UPLOAD: &[Eff] = &[Eff::Abort, Eff::Gone(GoneReason::Expired, T0)];
#[rustfmt::skip]
const E_WINDOW_CLOSED: &[Eff] = &[Eff::Delete, Eff::Gone(GoneReason::ReopenWindowClosed, T0 + WINDOW)];

#[rustfmt::skip]
const ROWS: &[Row] = rows![
    // Uploading: not yet readable; nothing burns.
    Uploading / OpenRight => GONE, After::Uploading, E_NONE;
    Uploading / OpenWrong => GONE, After::Uploading, E_NONE;
    Uploading / ReopenRight => RGONE, After::Uploading, E_NONE;
    Uploading / ReopenWrong => RGONE, After::Uploading, E_NONE;
    Uploading / AckRight => AIGN, After::Uploading, E_NONE;
    Uploading / AckWrong => AIGN, After::Uploading, E_NONE;
    Uploading / Alarm => Obs::Alarm(Some(EXP)), After::Uploading, E_NONE;
    Uploading / Revoke => NOEFF, After::Gone(GoneReason::Revoked), E_ABORT_REVOKED;
    Uploading / TakeDown => NOEFF, After::Gone(GoneReason::Abuse), E_ABORT_ABUSE;
    Uploading / Metadata => M_GONE, After::Uploading, E_NONE;
    // Sealed, burn, unexpired.
    SealedBurn / OpenRight => GRANT_BURN, After::Opening, E_OPEN_BURN;
    SealedBurn / OpenWrong => WK_1S, After::Sealed, E_WRONGKEY;
    SealedBurn / ReopenRight => RGONE, After::Sealed, E_NONE;
    SealedBurn / ReopenWrong => RGONE, After::Sealed, E_NONE;
    SealedBurn / AckRight => AIGN, After::Sealed, E_NONE;
    SealedBurn / AckWrong => AIGN, After::Sealed, E_NONE;
    SealedBurn / Alarm => Obs::Alarm(Some(EXP)), After::Sealed, E_NONE;
    SealedBurn / Revoke => NOEFF, After::Gone(GoneReason::Revoked), E_DELETE_REVOKED;
    SealedBurn / TakeDown => NOEFF, After::Gone(GoneReason::Abuse), E_DELETE_ABUSE;
    SealedBurn / Metadata => M_SEALED, After::Sealed, E_NONE;
    // Sealed, non-burn, unexpired: reads stay Sealed.
    SealedTtl / OpenRight => GRANT_TTL, After::Sealed, E_OPENED;
    SealedTtl / OpenWrong => WK_1S, After::Sealed, E_WRONGKEY;
    SealedTtl / ReopenRight => RGONE, After::Sealed, E_NONE;
    SealedTtl / ReopenWrong => RGONE, After::Sealed, E_NONE;
    SealedTtl / AckRight => AIGN, After::Sealed, E_NONE;
    SealedTtl / AckWrong => AIGN, After::Sealed, E_NONE;
    SealedTtl / Alarm => Obs::Alarm(Some(EXP)), After::Sealed, E_NONE;
    SealedTtl / Revoke => NOEFF, After::Gone(GoneReason::Revoked), E_DELETE_REVOKED;
    SealedTtl / TakeDown => NOEFF, After::Gone(GoneReason::Abuse), E_DELETE_ABUSE;
    SealedTtl / Metadata => M_SEALED, After::Sealed, E_NONE;
    // Opening, inside the window.
    Opening / OpenRight => GONE, After::Opening, E_NONE;
    Opening / OpenWrong => GONE, After::Opening, E_NONE;
    Opening / ReopenRight => RGRANT, After::Opening, E_REOPENED;
    Opening / ReopenWrong => RGONE, After::Opening, E_NONE;
    Opening / AckRight => AACK, After::Gone(GoneReason::Acked), E_DELETE_ACKED;
    Opening / AckWrong => AIGN, After::Opening, E_NONE;
    Opening / Alarm => Obs::Alarm(Some(T0 + WINDOW)), After::Opening, E_NONE;
    Opening / Revoke => NOEFF, After::Gone(GoneReason::Revoked), E_DELETE_REVOKED;
    Opening / TakeDown => NOEFF, After::Gone(GoneReason::Abuse), E_DELETE_ABUSE;
    Opening / Metadata => M_GONE, After::Opening, E_NONE;
    // Gone: every mutating command is a no-op.
    Gone / OpenRight => GONE, After::Gone(GoneReason::Revoked), E_NONE;
    Gone / OpenWrong => GONE, After::Gone(GoneReason::Revoked), E_NONE;
    Gone / ReopenRight => RGONE, After::Gone(GoneReason::Revoked), E_NONE;
    Gone / ReopenWrong => RGONE, After::Gone(GoneReason::Revoked), E_NONE;
    Gone / AckRight => AIGN, After::Gone(GoneReason::Revoked), E_NONE;
    Gone / AckWrong => AIGN, After::Gone(GoneReason::Revoked), E_NONE;
    Gone / Alarm => Obs::Alarm(None), After::Gone(GoneReason::Revoked), E_NONE;
    Gone / Revoke => NOEFF, After::Gone(GoneReason::Revoked), E_NONE;
    Gone / TakeDown => NOEFF, After::Gone(GoneReason::Revoked), E_NONE;
    Gone / Metadata => M_GONE, After::Gone(GoneReason::Revoked), E_NONE;
    // Sealed but expired: settle first, then the command sees Gone.
    SealedExpired / OpenRight => GONE, After::Gone(GoneReason::Expired), E_EXPIRED;
    SealedExpired / OpenWrong => GONE, After::Gone(GoneReason::Expired), E_EXPIRED;
    SealedExpired / ReopenRight => RGONE, After::Gone(GoneReason::Expired), E_EXPIRED;
    SealedExpired / ReopenWrong => RGONE, After::Gone(GoneReason::Expired), E_EXPIRED;
    SealedExpired / AckRight => AIGN, After::Gone(GoneReason::Expired), E_EXPIRED;
    SealedExpired / AckWrong => AIGN, After::Gone(GoneReason::Expired), E_EXPIRED;
    SealedExpired / Alarm => Obs::Alarm(None), After::Gone(GoneReason::Expired), E_EXPIRED;
    SealedExpired / Revoke => NOEFF, After::Gone(GoneReason::Expired), E_EXPIRED;
    SealedExpired / TakeDown => NOEFF, After::Gone(GoneReason::Expired), E_EXPIRED;
    SealedExpired / Metadata => M_GONE, After::Sealed, E_NONE;
    // Uploading but expired: AbortUpload, never DeleteCiphertext.
    UploadingExpired / OpenRight => GONE, After::Gone(GoneReason::Expired), E_EXPIRED_UPLOAD;
    UploadingExpired / OpenWrong => GONE, After::Gone(GoneReason::Expired), E_EXPIRED_UPLOAD;
    UploadingExpired / ReopenRight => RGONE, After::Gone(GoneReason::Expired), E_EXPIRED_UPLOAD;
    UploadingExpired / ReopenWrong => RGONE, After::Gone(GoneReason::Expired), E_EXPIRED_UPLOAD;
    UploadingExpired / AckRight => AIGN, After::Gone(GoneReason::Expired), E_EXPIRED_UPLOAD;
    UploadingExpired / AckWrong => AIGN, After::Gone(GoneReason::Expired), E_EXPIRED_UPLOAD;
    UploadingExpired / Alarm => Obs::Alarm(None), After::Gone(GoneReason::Expired), E_EXPIRED_UPLOAD;
    UploadingExpired / Revoke => NOEFF, After::Gone(GoneReason::Expired), E_EXPIRED_UPLOAD;
    UploadingExpired / TakeDown => NOEFF, After::Gone(GoneReason::Expired), E_EXPIRED_UPLOAD;
    UploadingExpired / Metadata => M_GONE, After::Uploading, E_NONE;
    // Opening but the window has closed.
    OpeningWindowPassed / OpenRight => GONE, After::Gone(GoneReason::ReopenWindowClosed), E_WINDOW_CLOSED;
    OpeningWindowPassed / OpenWrong => GONE, After::Gone(GoneReason::ReopenWindowClosed), E_WINDOW_CLOSED;
    OpeningWindowPassed / ReopenRight => RGONE, After::Gone(GoneReason::ReopenWindowClosed), E_WINDOW_CLOSED;
    OpeningWindowPassed / ReopenWrong => RGONE, After::Gone(GoneReason::ReopenWindowClosed), E_WINDOW_CLOSED;
    OpeningWindowPassed / AckRight => AIGN, After::Gone(GoneReason::ReopenWindowClosed), E_WINDOW_CLOSED;
    OpeningWindowPassed / AckWrong => AIGN, After::Gone(GoneReason::ReopenWindowClosed), E_WINDOW_CLOSED;
    OpeningWindowPassed / Alarm => Obs::Alarm(None), After::Gone(GoneReason::ReopenWindowClosed), E_WINDOW_CLOSED;
    OpeningWindowPassed / Revoke => NOEFF, After::Gone(GoneReason::ReopenWindowClosed), E_WINDOW_CLOSED;
    OpeningWindowPassed / TakeDown => NOEFF, After::Gone(GoneReason::ReopenWindowClosed), E_WINDOW_CLOSED;
    OpeningWindowPassed / Metadata => M_GONE, After::Opening, E_NONE;
];

fn expires_for(setup: Setup) -> i64 {
    match setup {
        Setup::SealedExpired | Setup::UploadingExpired => T0,
        _ => EXP,
    }
}

fn now_for(setup: Setup) -> i64 {
    match setup {
        Setup::OpeningWindowPassed => T0 + WINDOW,
        _ => T0,
    }
}

fn build(setup: Setup) -> SealRecord {
    let new = NewSeal {
        id: SealId::parse(ID).unwrap(),
        created_at: T0,
        expires_at: expires_for(setup),
        burn: setup != Setup::SealedTtl,
        read_verifier: hash_token(&RIGHT_READ),
        password: false,
        size: 1_234,
        storage: Storage::Inline,
    };
    let mut rec = match setup {
        Setup::Uploading | Setup::UploadingExpired => {
            SealRecord::new_uploading(new, "upload-1".to_owned())
        }
        _ => SealRecord::new(new),
    };
    match setup {
        Setup::Opening | Setup::OpeningWindowPassed => {
            rec.state = State::Opening {
                opened_at: T0,
                reopen_hash: hash_token(&RIGHT_REOPEN),
            };
        }
        Setup::Gone => {
            rec.state = State::Gone {
                reason: GoneReason::Revoked,
                at: T0 - 5,
            };
        }
        _ => {}
    }
    rec
}

fn run(rec: &mut SealRecord, now: i64, cmd: Cmd) -> (Obs, Vec<Effect>) {
    match cmd {
        Cmd::OpenRight => {
            let (o, e) = rec.open(now, &RIGHT_READ, RIGHT_REOPEN);
            (Obs::Open(o), e)
        }
        Cmd::OpenWrong => {
            let (o, e) = rec.open(now, &WRONG_READ, RIGHT_REOPEN);
            (Obs::Open(o), e)
        }
        Cmd::ReopenRight => {
            let (o, e) = rec.reopen(now, &RIGHT_REOPEN);
            (Obs::Reopen(o), e)
        }
        Cmd::ReopenWrong => {
            let (o, e) = rec.reopen(now, &WRONG_REOPEN);
            (Obs::Reopen(o), e)
        }
        Cmd::AckRight => {
            let (o, e) = rec.ack(now, &RIGHT_REOPEN);
            (Obs::Ack(o), e)
        }
        Cmd::AckWrong => {
            let (o, e) = rec.ack(now, &WRONG_REOPEN);
            (Obs::Ack(o), e)
        }
        Cmd::Alarm => {
            let (a, e) = rec.alarm(now);
            (Obs::Alarm(a), e)
        }
        Cmd::Revoke => (Obs::EffectsOnly, rec.revoke(now)),
        Cmd::TakeDown => (Obs::EffectsOnly, rec.take_down(now)),
        Cmd::Metadata => (Obs::Metadata(rec.metadata(now).state), Vec::new()),
    }
}

fn after_of(state: &State) -> After {
    match state {
        State::Uploading { .. } => After::Uploading,
        State::Sealed => After::Sealed,
        State::Opening { .. } => After::Opening,
        State::Gone { reason, .. } => After::Gone(*reason),
    }
}

fn normalize(effects: &[Effect]) -> Vec<Eff> {
    effects
        .iter()
        .map(|e| match e {
            Effect::DeleteCiphertext => Eff::Delete,
            Effect::AbortUpload => Eff::Abort,
            Effect::SetAlarm(t) => Eff::Alarm(*t),
            Effect::RecordEvent(AuditEvent::Opened { at }) => Eff::Opened(*at),
            Effect::RecordEvent(AuditEvent::Reopened { at }) => Eff::Reopened(*at),
            Effect::RecordEvent(AuditEvent::WrongKey {
                at,
                failed_attempts,
            }) => Eff::WrongKey(*at, *failed_attempts),
            Effect::RecordEvent(AuditEvent::Gone { reason, at }) => Eff::Gone(*reason, *at),
        })
        .collect()
}

#[test]
fn every_state_command_pair() {
    for setup in ALL_SETUPS {
        for cmd in ALL_CMDS {
            assert!(
                ROWS.iter().any(|r| r.setup == setup && r.cmd == cmd),
                "table is missing {setup:?} / {cmd:?}"
            );
        }
    }

    for r in ROWS {
        let case = format!("{:?}/{:?}", r.setup, r.cmd);
        let mut rec = build(r.setup);
        let (outcome, effects) = run(&mut rec, now_for(r.setup), r.cmd);
        assert_eq!(outcome, r.outcome, "{case}: outcome");
        assert_eq!(after_of(&rec.state), r.after, "{case}: state");
        assert_eq!(normalize(&effects).as_slice(), r.effects, "{case}: effects");
    }
}

// ---------------------------------------------------------------------------
// The named properties D8 and spec §9 call out
// ---------------------------------------------------------------------------

/// A burn seal, two `open` calls at the same millisecond with the right token:
/// the first is granted, the second is gone.
///
/// This is exactly the property the Durable Object's serial (single-threaded)
/// execution relies on. The DO runs these calls one after another on one
/// `SealRecord`, so "atomic" in production is "sequential on one record" here
/// (D9, spec §9: "Exactly one of any number of concurrent opens wins").
#[test]
fn same_millisecond_two_openers_exactly_one_granted() {
    let mut rec = build(Setup::SealedBurn);
    let (first, _) = rec.open(T0, &RIGHT_READ, RIGHT_REOPEN);
    let (second, second_effects) = rec.open(T0, &RIGHT_READ, RIGHT_REOPEN);

    assert!(
        matches!(first, OpenOutcome::Granted { reopen_token: Some(t) } if t == RIGHT_REOPEN),
        "first opener must win"
    );
    assert_eq!(second, OpenOutcome::Gone, "second opener must be gone");
    assert!(second_effects.is_empty(), "the loser changes nothing");
    assert!(
        matches!(rec.state, State::Opening { .. }),
        "the winner's window must survive the loser"
    );
}

/// First open granted, the process "crashes", the CLI resumes from its pending
/// file (D8). Inside 60 s the reopen works; at and after 60 s it is gone and the
/// ciphertext is deleted. The window is half-open: `now == opened_at + 60_000`
/// is already too late.
#[test]
fn crash_window_resume() {
    let mut rec = build(Setup::SealedBurn);
    let (open, _) = rec.open(T0, &RIGHT_READ, RIGHT_REOPEN);
    assert!(matches!(open, OpenOutcome::Granted { .. }));

    let (inside, inside_effects) = rec.reopen(T0 + 59_900, &RIGHT_REOPEN);
    assert_eq!(inside, ReopenOutcome::Granted);
    assert_eq!(
        inside_effects,
        vec![Effect::RecordEvent(AuditEvent::Reopened {
            at: T0 + 59_900
        })],
        "a reopen records the event and deletes nothing"
    );

    let (outside, outside_effects) = rec.reopen(T0 + 60_100, &RIGHT_REOPEN);
    assert_eq!(outside, ReopenOutcome::Gone);
    assert_eq!(
        outside_effects,
        vec![
            Effect::DeleteCiphertext,
            Effect::RecordEvent(AuditEvent::Gone {
                reason: GoneReason::ReopenWindowClosed,
                at: T0 + 60_100,
            }),
        ],
        "window close deletes exactly once"
    );

    // The exact boundary: now == opened_at + REOPEN_WINDOW_MS is already past.
    let mut rec = build(Setup::SealedBurn);
    let _ = rec.open(T0, &RIGHT_READ, RIGHT_REOPEN);
    let (boundary, boundary_effects) = rec.reopen(T0 + REOPEN_WINDOW_MS, &RIGHT_REOPEN);
    assert_eq!(boundary, ReopenOutcome::Gone);
    assert!(boundary_effects.contains(&Effect::DeleteCiphertext));
}

/// Wrong keys back off 1s, 2s, 4s … capped at 5 minutes. Calls inside the
/// backoff are throttled and do not bump the counter or the state; the right
/// token still opens afterwards (D6, spec §4, spec §9).
#[test]
fn wrong_key_backoff() {
    let mut rec = build(Setup::SealedBurn);
    let mut now = T0;
    // 1s, 2s, 4s … doubling to the 5-minute cap, which holds thereafter.
    #[rustfmt::skip]
    let schedule = [1_000, 2_000, 4_000, 8_000, 16_000, 32_000, 64_000, 128_000, 256_000, 300_000, 300_000, 300_000];
    for (i, want) in schedule.iter().enumerate() {
        let (out, _) = rec.open(now, &WRONG_READ, RIGHT_REOPEN);
        assert_eq!(
            out,
            OpenOutcome::WrongKey {
                retry_after_ms: *want
            },
            "attempt {}",
            i + 1
        );
        assert_eq!(rec.failed_attempts, u32::try_from(i).unwrap() + 1);
        assert!(
            matches!(rec.state, State::Sealed),
            "a wrong key never burns"
        );
        now += want;
    }

    let (throttled, throttled_effects) = rec.open(now - 1, &RIGHT_READ, RIGHT_REOPEN);
    assert_eq!(throttled, OpenOutcome::Throttled { retry_after_ms: 1 });
    assert!(throttled_effects.is_empty());
    assert_eq!(
        rec.failed_attempts, 12,
        "throttling must not bump the count"
    );
    assert!(matches!(rec.state, State::Sealed));

    let (granted, _) = rec.open(now, &RIGHT_READ, RIGHT_REOPEN);
    assert!(matches!(granted, OpenOutcome::Granted { .. }));
    assert_eq!(rec.failed_attempts, 0, "success resets the counter");
    assert!(rec.next_attempt_at.is_none());
}

/// A non-burn seal is readable any number of times until it expires.
#[test]
fn non_burn_seal_reads_until_expiry() {
    let mut rec = build(Setup::SealedTtl);
    for i in 0..5_i64 {
        let (out, effects) = rec.open(T0 + i * 1_000, &RIGHT_READ, RIGHT_REOPEN);
        assert_eq!(out, OpenOutcome::Granted { reopen_token: None });
        assert!(matches!(rec.state, State::Sealed), "no state change");
        assert_eq!(
            effects,
            vec![Effect::RecordEvent(AuditEvent::Opened {
                at: T0 + i * 1_000
            })]
        );
    }
    assert_eq!(rec.reads, 5);

    let (expired, effects) = rec.open(EXP, &RIGHT_READ, RIGHT_REOPEN);
    assert_eq!(expired, OpenOutcome::Gone, "now >= expires_at is expired");
    assert!(matches!(
        rec.state,
        State::Gone {
            reason: GoneReason::Expired,
            ..
        }
    ));
    assert!(effects.contains(&Effect::DeleteCiphertext));
}

/// The persisted JSON is a stable shape (#8 stores it): hashes as lowercase
/// hex, `state`/`storage` internally tagged, reasons `snake_case`.
#[test]
fn persisted_shape_is_stable() {
    let json = serde_json::to_value(build(Setup::Opening)).unwrap();
    assert_eq!(json["id"], ID);
    assert_eq!(json["state"]["kind"], "opening");
    assert_eq!(json["state"]["opened_at"], T0);
    assert_eq!(json["storage"], serde_json::json!({ "kind": "inline" }));
    for (field, value) in [
        ("read_verifier", &json["read_verifier"]),
        ("state.reopen_hash", &json["state"]["reopen_hash"]),
    ] {
        let value = value.as_str().unwrap();
        assert_eq!(value.len(), 64, "{field} must be 64 hex characters");
        assert!(
            value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "{field} must be lowercase hex"
        );
    }

    let gone = serde_json::to_value(build(Setup::Gone)).unwrap();
    assert_eq!(gone["state"]["kind"], "gone");
    assert_eq!(gone["state"]["reason"], "revoked");

    let uploading = serde_json::to_value(build(Setup::Uploading)).unwrap();
    assert_eq!(uploading["state"]["kind"], "uploading");
}

#[test]
fn serde_round_trip() {
    for setup in ALL_SETUPS {
        let rec = build(setup);
        let json = serde_json::to_string(&rec).unwrap();
        let back: SealRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(rec, back, "round trip for {setup:?}");
    }

    assert_eq!(SealId::parse(ID).unwrap().as_str(), ID);
    assert_eq!(SealId::parse(ID).unwrap().to_string(), ID);
    assert!(SealId::parse("").is_err(), "empty");
    assert!(SealId::parse("short").is_err(), "too short");
    assert!(SealId::parse("Ab3xY9zQ0pLmm").is_err(), "too long");
    assert!(SealId::parse("Ab3xY9zQ0pL!").is_err(), "non-base62 byte");
    assert!(serde_json::from_str::<SealId>("\"bad\"").is_err());
    let id: SealId = serde_json::from_str("\"Ab3xY9zQ0pLm\"").unwrap();
    assert_eq!(id.as_str(), ID);
}

// ---------------------------------------------------------------------------
// The proptest
// ---------------------------------------------------------------------------

/// A proptest driving the real `SealRecord` through random interleavings of
/// commands from several clients. It is an invariant check over those
/// interleavings against a small tracking model (which client won the burn,
/// its token, whether the seal is gone, the destroy-effect count) — not a
/// second reference implementation of the machine. The six invariants are
/// checked after every step.
mod model {
    use proptest::prelude::*;

    use sealbin_core::{Effect, OpenOutcome, REOPEN_WINDOW_MS, ReopenOutcome};

    use super::{
        ID, NewSeal, RIGHT_READ, SealId, SealRecord, State, Storage, T0, WRONG_READ, WRONG_REOPEN,
        hash_token,
    };

    const CREATED: i64 = T0;

    #[derive(Clone, Copy, Debug)]
    enum Action {
        Open,
        Reopen,
        Ack,
        Alarm,
        Revoke,
        TakeDown,
    }

    static SEALER_ACTIONS: &[Action] = &[Action::Revoke, Action::TakeDown, Action::Alarm];
    static OPENER_ACTIONS: &[Action] = &[Action::Open, Action::Reopen, Action::Ack, Action::Alarm];

    #[derive(Clone, Debug)]
    struct Step {
        client: u8,
        action: Action,
        delta: i64,
    }

    /// Clients 1..=5 hold the right `read_token`; 6..=7 hold a wrong one;
    /// 0 is the sealer. Each passes its own reopen secret.
    const REOPEN_SECRETS: [[u8; 32]; 8] = [
        [10; 32], [11; 32], [12; 32], [13; 32], [14; 32], [15; 32], [16; 32], [17; 32],
    ];

    /// Weighted so same-millisecond opens and in-window reopens are common,
    /// while still crossing the 60 s window and short TTLs.
    fn delta_strategy() -> impl Strategy<Value = i64> {
        prop_oneof![
            3 => Just(0i64),
            3 => 1i64..=2_000,
            2 => 1i64..=70_000,
            1 => 50_000i64..=90_000,
        ]
    }

    fn step_strategy() -> impl Strategy<Value = Step> {
        (0u8..8, delta_strategy()).prop_flat_map(|(client, delta)| {
            let actions: &'static [Action] = if client == 0 {
                SEALER_ACTIONS
            } else {
                OPENER_ACTIONS
            };
            (0..actions.len()).prop_map(move |i| Step {
                client,
                action: actions[i],
                delta,
            })
        })
    }

    fn case_strategy() -> impl Strategy<Value = (bool, i64, bool, Vec<Step>)> {
        (
            any::<bool>(),
            1i64..=3_600_000,
            any::<bool>(),
            prop::collection::vec(step_strategy(), 1..=40),
        )
    }

    #[derive(Default)]
    struct Model {
        /// Successful opens that returned a reopen token (burn seals only).
        burn_open_grants: u32,
        /// Delete-vs-abort effects seen over the run (`AbortUpload` stands in
        /// for `DeleteCiphertext` while a seal is still `Uploading`).
        destroy_count: u32,
        /// The first opener: `(client, reopen_token, granted_at)`.
        holder: Option<(u8, [u8; 32], i64)>,
    }

    fn at_most_one_open_granted_for_burn_seal(burn: bool, model: &Model, ctx: &str) {
        let grants = model.burn_open_grants;
        let ok = if burn { grants <= 1 } else { grants == 0 };
        assert!(
            ok,
            "at_most_one_open_granted_for_burn_seal: {grants} token(s), burn={burn} ({ctx})"
        );
    }

    fn nothing_granted_after_gone(was_gone: bool, granted: bool, ctx: &str) {
        assert!(!(was_gone && granted), "nothing_granted_after_gone ({ctx})");
    }

    fn delete_ciphertext_emitted_exactly_once(count: u32, gone: bool, ctx: &str) {
        assert_eq!(
            count,
            u32::from(gone),
            "delete_ciphertext_emitted_exactly_once: {count} destroys ({ctx})"
        );
    }

    fn wrong_token_never_changes_state(settled: &State, after: &State, ctx: &str) {
        assert_eq!(settled, after, "wrong_token_never_changes_state ({ctx})");
    }

    fn no_open_granted_at_or_after_expires_at(now: i64, expires_at: i64, ctx: &str) {
        assert!(
            now < expires_at,
            "no_open_granted_at_or_after_expires_at: {now} >= {expires_at} ({ctx})"
        );
    }

    fn reopen_only_for_first_opener_within_window(model: &Model, client: u8, now: i64, ctx: &str) {
        let (holder_client, _token, granted_at) = model.holder.expect("reopen without a holder");
        assert!(
            holder_client == client && now < granted_at + REOPEN_WINDOW_MS,
            "reopen_only_for_first_opener_within_window ({ctx})"
        );
    }

    fn reopen_token_for(model: &Model, client: u8) -> [u8; 32] {
        match model.holder {
            Some((holder_client, token, _)) if holder_client == client => token,
            _ => WRONG_REOPEN,
        }
    }

    /// Counts the delete-or-abort effect; `AbortUpload` stands in for
    /// `DeleteCiphertext` while a seal is still `Uploading`.
    fn collect_destroy(model: &mut Model, effects: &[Effect]) {
        for effect in effects {
            if matches!(effect, Effect::DeleteCiphertext | Effect::AbortUpload) {
                model.destroy_count += 1;
            }
        }
    }

    fn apply_step(
        rec: &mut SealRecord,
        model: &mut Model,
        step: &Step,
        now: i64,
        expires_at: i64,
        ctx: &str,
    ) {
        // The state a wrong token is allowed to leave behind: whatever the
        // time-based settle alone would have done.
        let mut settled = rec.clone();
        let _settled = settled.alarm(now);

        let was_gone = matches!(rec.state, State::Gone { .. });
        let wrong_read = matches!(step.client, 6 | 7);
        let uses_wrong_reopen = matches!(step.action, Action::Reopen | Action::Ack)
            && model.holder.is_none_or(|(hc, _, _)| hc != step.client);

        let mut granted = false;
        let mut open_granted = false;

        match step.action {
            Action::Open => {
                let token = if wrong_read { WRONG_READ } else { RIGHT_READ };
                let (outcome, effects) =
                    rec.open(now, &token, REOPEN_SECRETS[usize::from(step.client)]);
                if let OpenOutcome::Granted { reopen_token } = &outcome {
                    granted = true;
                    open_granted = true;
                    if let Some(token) = reopen_token {
                        model.burn_open_grants += 1;
                        model.holder = Some((step.client, *token, now));
                    }
                }
                collect_destroy(model, &effects);
            }
            Action::Reopen => {
                let token = reopen_token_for(model, step.client);
                let (outcome, effects) = rec.reopen(now, &token);
                if matches!(outcome, ReopenOutcome::Granted) {
                    granted = true;
                    reopen_only_for_first_opener_within_window(model, step.client, now, ctx);
                }
                collect_destroy(model, &effects);
            }
            Action::Ack => {
                let token = reopen_token_for(model, step.client);
                let (_outcome, effects) = rec.ack(now, &token);
                collect_destroy(model, &effects);
            }
            Action::Alarm => {
                let (_next, effects) = rec.alarm(now);
                collect_destroy(model, &effects);
            }
            Action::Revoke => {
                let effects = rec.revoke(now);
                collect_destroy(model, &effects);
            }
            Action::TakeDown => {
                let effects = rec.take_down(now);
                collect_destroy(model, &effects);
            }
        }

        nothing_granted_after_gone(was_gone, granted, ctx);
        if wrong_read || uses_wrong_reopen {
            wrong_token_never_changes_state(&settled.state, &rec.state, ctx);
        }
        delete_ciphertext_emitted_exactly_once(
            model.destroy_count,
            matches!(rec.state, State::Gone { .. }),
            ctx,
        );
        if open_granted {
            no_open_granted_at_or_after_expires_at(now, expires_at, ctx);
        }
        at_most_one_open_granted_for_burn_seal(rec.burn, model, ctx);
    }

    fn run_model(burn: bool, ttl: i64, start_uploading: bool, steps: &[Step]) {
        let expires_at = CREATED + ttl;
        let new = NewSeal {
            id: SealId::parse(ID).unwrap(),
            created_at: CREATED,
            expires_at,
            burn,
            read_verifier: hash_token(&RIGHT_READ),
            password: false,
            size: 64,
            storage: Storage::Inline,
        };
        let mut rec = if start_uploading {
            SealRecord::new_uploading(new, "upload-1".to_owned())
        } else {
            SealRecord::new(new)
        };
        let mut model = Model::default();
        let mut now = CREATED;

        for (i, step) in steps.iter().enumerate() {
            now += step.delta;
            let ctx =
                format!("burn={burn} ttl={ttl} up={start_uploading} step={i} {step:?} now={now}");
            apply_step(&mut rec, &mut model, step, now, expires_at, &ctx);
        }
    }

    proptest! {
        // 10,000 cases, set here rather than behind an env var (no CI env var
        // exists for this).
        #![proptest_config(ProptestConfig::with_cases(10_000))]
        #[test]
        fn machine_model_check((burn, ttl, up, steps) in case_strategy()) {
            run_model(burn, ttl, up, &steps);
        }
    }
}
