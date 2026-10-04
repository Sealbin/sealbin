//! Deterministic generation of the committed test vectors.
//!
//! Included both by the `gen-vectors` example (which writes the files) and by
//! `tests/vectors.rs` (which regenerates and compares byte for byte). It lives
//! in the example's directory so the two never drift.

use core::fmt::Write as _;

use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng as _;
use serde_json::{Value, json};
use sha2::Sha256;

use sealbin_format::{Header, Ikm, KeySchedule, LinkKey, seal_with_ikm};

/// Where the committed vectors live, relative to this crate.
pub const VECTORS_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../spec/vectors");

/// The Appendix A password (ASCII; NFC normalisation is a no-op).
pub const PASSWORD: &str = "correct horse battery staple";

/// Plaintext chunk size in v1.
const CHUNK_SIZE: usize = 65_536;

/// Lowercase hex, no prefix, no separators.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(out, "{byte:02x}").expect("writing to a String cannot fail");
    }
    out
}

/// Decode lowercase or uppercase hex.
///
/// # Panics
///
/// If `text` has odd length or a non-hex character.
#[must_use]
pub fn unhex(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    assert!(
        bytes.len().is_multiple_of(2),
        "hex input must have even length"
    );
    let (pairs, _) = bytes.as_chunks::<2>();
    let mut out = Vec::with_capacity(pairs.len());
    for pair in pairs {
        let hi = hex_value(pair[0]);
        let lo = hex_value(pair[1]);
        out.push((hi << 4) | lo);
    }
    out
}

fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("invalid hex character"),
    }
}

fn array16(text: &str) -> [u8; 16] {
    let bytes = unhex(text);
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes);
    out
}

fn array32(text: &str) -> [u8; 32] {
    let bytes = unhex(text);
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

/// A deterministic, non-secret byte pattern of `len` bytes.
fn pattern(len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut state: u32 = 0x1234_5678;
    for _ in 0..len {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        out.push(state.to_le_bytes()[0]);
    }
    out
}

/// Every positive vector.
#[must_use]
pub fn basic() -> Vec<Value> {
    vec![
        appendix_a(),
        no_password(
            "empty-payload",
            "No password, envelope layer only: an empty payload is a single empty final chunk.",
            1,
            &[],
        ),
        no_password(
            "single-chunk",
            "No password, envelope layer only: exactly one 65,536-byte chunk. The plaintext is raw, not the §7 layout.",
            2,
            &pattern(CHUNK_SIZE),
        ),
        no_password(
            "single-chunk-plus-one",
            "No password, envelope layer only: one full chunk plus one byte, so the last chunk is 1 byte. Raw plaintext, not the §7 layout.",
            3,
            &pattern(CHUNK_SIZE + 1),
        ),
        no_password(
            "three-chunks",
            "No password, envelope layer only: two full chunks plus a short final one. Raw plaintext, not the §7 layout.",
            4,
            &pattern(2 * CHUNK_SIZE + 12_345),
        ),
    ]
}

/// The Appendix A worked example (spec), driven through the password seam.
fn appendix_a() -> Value {
    let k_link = array32("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    let salt = array16("202122232425262728292a2b2c2d2e2f");
    let nonce = array16("303132333435363738393a3b3c3d3e3f");
    let iterations = 600_000u32;

    let metadata = "{\"kind\":\"text\",\"content_type\":\"text/plain; charset=utf-8\",\"size\":13,\"created_at\":\"2026-10-02T12:00:00Z\"}";
    let content = b"hello, agent\n";
    let mut plaintext = Vec::new();
    plaintext.extend_from_slice(
        &u32::try_from(metadata.len())
            .expect("metadata is 104 bytes")
            .to_be_bytes(),
    );
    plaintext.extend_from_slice(metadata.as_bytes());
    plaintext.extend_from_slice(content);

    let mut p = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(PASSWORD.as_bytes(), &salt, iterations, &mut p);

    let link_key = LinkKey::from_bytes(k_link);
    let ikm = Ikm::from_link_key_and_password_key(&link_key, &p);
    let header = Header::from_parts(true, iterations, salt, nonce).expect("valid password header");
    let schedule = KeySchedule::derive(&ikm, &header);
    let envelope =
        seal_with_ikm(&ikm, &header, &plaintext).expect("sealing cannot exceed the chunk cap");

    json!({
        "name": "appendix-a-text-password",
        "description": "Appendix A: a password-protected text seal in a single chunk.",
        "inputs": {
            "k_link": hex(&k_link),
            "password": PASSWORD,
            "iterations": iterations,
            "salt": hex(&salt),
            "nonce": hex(&nonce),
            "chunk_size": CHUNK_SIZE,
            "plaintext": hex(&plaintext),
            "inner_metadata": {
                "kind": "text",
                "content_type": "text/plain; charset=utf-8",
                "size": 13,
                "created_at": "2026-10-02T12:00:00Z"
            },
            "content": hex(content)
        },
        "outputs": {
            "p": hex(&p),
            "ikm": hex(ikm.as_bytes()),
            "k_payload": hex(schedule.payload.as_bytes()),
            "read_token": hex(schedule.read_token.as_bytes()),
            "read_verifier": hex(&schedule.read_token.verifier()),
            "header": hex(&header.encode()),
            "aad": hex(&header.aad()),
            "envelope": hex(&envelope)
        }
    })
}

/// A no-password vector with a header drawn deterministically from `seed`.
fn no_password(name: &str, description: &str, seed: u8, plaintext: &[u8]) -> Value {
    let mut seed_bytes = [0u8; 32];
    seed_bytes[0] = seed;
    let mut rng = ChaCha20Rng::from_seed(seed_bytes);
    let link_key = LinkKey::generate(&mut rng);
    let header = Header::new(&mut rng, false);
    let ikm = Ikm::from_link_key(&link_key);
    let schedule = KeySchedule::derive(&ikm, &header);
    let envelope =
        seal_with_ikm(&ikm, &header, plaintext).expect("sealing cannot exceed the chunk cap");

    json!({
        "name": name,
        "description": description,
        "inputs": {
            "k_link": hex(link_key.as_bytes()),
            "password": Value::Null,
            "iterations": 0,
            "salt": hex(header.salt()),
            "nonce": hex(header.nonce()),
            "chunk_size": CHUNK_SIZE,
            "plaintext": hex(plaintext)
        },
        "outputs": {
            "p": Value::Null,
            "ikm": hex(ikm.as_bytes()),
            "k_payload": hex(schedule.payload.as_bytes()),
            "read_token": hex(schedule.read_token.as_bytes()),
            "read_verifier": hex(&schedule.read_token.verifier()),
            "header": hex(&header.encode()),
            "aad": hex(&header.aad()),
            "envelope": hex(&envelope)
        }
    })
}

/// A negative vector that feeds a specific envelope to `open_bytes`.
fn negative_envelope(
    name: &str,
    description: &str,
    expect_error: &str,
    key: &LinkKey,
    envelope: &[u8],
) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputs": {
            "k_link": hex(key.as_bytes()),
            "envelope": hex(envelope)
        },
        "expect_error": expect_error
    })
}

/// A negative vector that feeds a link to `Link::parse`.
fn negative_link(name: &str, description: &str, expect_error: &str, link: &str) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputs": { "link": link },
        "expect_error": expect_error
    })
}

/// The Appendix A link key, reused by the link negatives.
const LINK_KEY_HEX: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

/// Every negative vector.
#[must_use]
pub fn negative() -> Vec<Value> {
    let mut seed = [0u8; 32];
    seed[0] = 77;
    let mut rng = ChaCha20Rng::from_seed(seed);
    let key = LinkKey::generate(&mut rng);
    let header = Header::new(&mut rng, false);
    let ikm = Ikm::from_link_key(&key);
    let envelope =
        seal_with_ikm(&ikm, &header, b"negative vector payload").expect("sealing succeeds");

    let mut out = truncated_vectors(&key, &envelope, &header.encode());
    out.extend(header_vectors(&key, &envelope));
    out.extend(auth_vectors(&key, &ikm, &header, &envelope));
    out.extend(link_vectors());
    out
}

/// Inputs that end early: inside the header, with no chunk, or with a final
/// block too short to carry a tag.
fn truncated_vectors(key: &LinkKey, envelope: &[u8], header_bytes: &[u8; 49]) -> Vec<Value> {
    let mut out = vec![
        negative_envelope(
            "envelope-truncated-inside-header",
            "Input ends 20 bytes into the 49-byte header.",
            "envelope/truncated",
            key,
            &envelope[..20],
        ),
        negative_envelope(
            "envelope-truncated-no-chunks",
            "A valid 49-byte header with no chunk after it.",
            "envelope/truncated",
            key,
            header_bytes,
        ),
    ];
    let mut short_final = header_bytes.to_vec();
    short_final.extend_from_slice(&[0u8; 10]);
    out.push(negative_envelope(
        "envelope-truncated-short-final",
        "A final block of 10 bytes cannot hold a 16-byte tag.",
        "envelope/truncated",
        key,
        &short_final,
    ));
    out
}

/// Each header field broken in turn.
fn header_vectors(key: &LinkKey, envelope: &[u8]) -> Vec<Value> {
    let mut bad_magic = envelope.to_vec();
    bad_magic[0] = b'X';
    let mut bad_version = envelope.to_vec();
    bad_version[7] = 0x02;
    let mut bad_flags = envelope.to_vec();
    bad_flags[8] = 0x02;
    let mut bad_chunk_size = envelope.to_vec();
    bad_chunk_size[45..49].copy_from_slice(&32_768u32.to_be_bytes());
    let password_header =
        Header::from_parts(true, 600_000, [0x42; 16], [0x43; 16]).expect("valid password header");
    let mut zero_salt = password_header.encode().to_vec();
    zero_salt[13..29].copy_from_slice(&[0u8; 16]);
    zero_salt.extend_from_slice(&[0u8; 16]);

    vec![
        negative_envelope(
            "envelope-bad-magic",
            "The magic is not SEALBIN.",
            "envelope/bad-magic",
            key,
            &bad_magic,
        ),
        negative_envelope(
            "envelope-unsupported-version",
            "Version byte 0x02 is not v1.",
            "envelope/unsupported-version",
            key,
            &bad_version,
        ),
        negative_envelope(
            "envelope-unknown-flags",
            "Reserved flag bit 1 is set.",
            "envelope/unknown-flags",
            key,
            &bad_flags,
        ),
        negative_envelope(
            "envelope-bad-header-chunk-size",
            "chunk_size is 32,768, not 65,536.",
            "envelope/bad-header",
            key,
            &bad_chunk_size,
        ),
        negative_envelope(
            "envelope-bad-header-zero-salt",
            "The password flag is set but the salt is all zero.",
            "envelope/bad-header",
            key,
            &zero_salt,
        ),
    ]
}

/// A body that does not authenticate: the wrong key, a flipped bit, an extra
/// final chunk, or two chunks swapped.
fn auth_vectors(key: &LinkKey, ikm: &Ikm, header: &Header, envelope: &[u8]) -> Vec<Value> {
    let mut wrong = [0u8; 32];
    wrong[0] = 0xFF;

    let mut flipped = envelope.to_vec();
    let last = flipped.len() - 1;
    flipped[last] ^= 0x01;

    let mut empty_final = envelope.to_vec();
    empty_final.extend_from_slice(&[0u8; 16]);

    // A two-chunk envelope needs more than one chunk_size of plaintext.
    let two = seal_with_ikm(ikm, header, &pattern(CHUNK_SIZE + 1)).expect("sealing succeeds");
    let first_end = 49 + CHUNK_SIZE + 16;
    let mut swapped = two[..49].to_vec();
    swapped.extend_from_slice(&two[first_end..]);
    swapped.extend_from_slice(&two[49..first_end]);

    vec![
        negative_envelope(
            "envelope-auth-wrong-key",
            "A wrong K_link derives a wrong K_payload.",
            "envelope/auth-failed",
            &LinkKey::from_bytes(wrong),
            envelope,
        ),
        negative_envelope(
            "envelope-auth-flipped-tag",
            "One bit of the final chunk's tag is flipped.",
            "envelope/auth-failed",
            key,
            &flipped,
        ),
        negative_envelope(
            "envelope-auth-empty-final",
            "An empty final chunk is appended after the genuine final chunk.",
            "envelope/auth-failed",
            key,
            &empty_final,
        ),
        negative_envelope(
            "envelope-auth-swapped-chunks",
            "Two chunks of a multi-chunk seal are swapped.",
            "envelope/auth-failed",
            key,
            &swapped,
        ),
    ]
}

/// Link strings that must fail to parse.
fn link_vectors() -> Vec<Value> {
    vec![
        negative_link(
            "link-missing-key",
            "A fragment with no key parameter.",
            "link/missing-key",
            "https://sealb.in/s/k7Qx9pL2Hd4m#to=nobody",
        ),
        negative_link(
            "link-duplicate-key",
            "Two key parameters.",
            "link/duplicate-key",
            &format!("https://sealb.in/s/k7Qx9pL2Hd4m#key={LINK_KEY_HEX}&key={LINK_KEY_HEX}"),
        ),
        negative_link(
            "link-bad-key-42",
            "A 42-character key.",
            "link/bad-key",
            &format!(
                "https://sealb.in/s/k7Qx9pL2Hd4m#key={}",
                &LINK_KEY_HEX[..42]
            ),
        ),
        negative_link(
            "link-bad-id",
            "A seven-character id.",
            "link/bad-id",
            &format!("https://sealb.in/s/k7Qx9pL#key={LINK_KEY_HEX}"),
        ),
    ]
}

/// Render a vector array as the committed JSON: pretty, deterministic, with a
/// trailing newline.
///
/// Object keys are sorted first, so the output does not depend on whether
/// `serde_json` was built with the `preserve_order` feature — another crate in
/// the workspace turns it on, which would otherwise reorder the keys when the
/// whole workspace is tested together.
///
/// # Panics
///
/// If `serde_json` cannot serialise a `Value`, which cannot happen.
#[must_use]
pub fn render(vectors: &[Value]) -> String {
    let value = sorted(Value::Array(vectors.to_vec()));
    let mut text = serde_json::to_string_pretty(&value).expect("a Value array always serialises");
    text.push('\n');
    text
}

/// Rebuild `value` with every object's keys in sorted order.
fn sorted(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(String, Value)> = map
                .into_iter()
                .map(|(key, value)| (key, sorted(value)))
                .collect();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            Value::Object(entries.into_iter().collect())
        }
        Value::Array(items) => Value::Array(items.into_iter().map(sorted).collect()),
        other => other,
    }
}
