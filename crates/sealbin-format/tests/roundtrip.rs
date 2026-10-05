//! Stream-level properties: round trips, tamper detection, the chunk-framing
//! edge cases, and the memory bound.

use proptest::prelude::*;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng as _;
use sealbin_format::{
    Decryptor, Encryptor, FormatError, Header, Ikm, KeySchedule, Link, LinkKey, Opener, ReadToken,
    open_bytes, seal_bytes,
};

/// Plaintext chunk size.
const CHUNK_SIZE: usize = 65_536;
/// A full chunk on the wire.
const BLOCK_LEN: usize = CHUNK_SIZE + 16;

fn key() -> LinkKey {
    LinkKey::from_bytes([0x11; 32])
}

fn header() -> Header {
    Header::from_parts(false, 0, [0u8; 16], [0x22; 16]).unwrap()
}

fn encryptor() -> Encryptor {
    let ikm = Ikm::from_link_key(&key());
    let schedule = KeySchedule::derive(&ikm, &header());
    Encryptor::new(&schedule.payload, &header())
}

fn decryptor() -> Decryptor {
    let ikm = Ikm::from_link_key(&key());
    let schedule = KeySchedule::derive(&ikm, &header());
    Decryptor::new(&schedule.payload, &header())
}

/// A deterministic byte pattern.
fn pattern(len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut state: u32 = 0x9e37_79b9;
    for _ in 0..len {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        out.push(state.to_le_bytes()[0]);
    }
    out
}

/// Cut `data` into the given sizes, clamping the last piece to what is left.
fn cut<'a>(data: &'a [u8], sizes: &[usize]) -> Vec<&'a [u8]> {
    let mut pieces = Vec::new();
    let mut rest = data;
    for &size in sizes {
        if rest.is_empty() {
            break;
        }
        let take = size.min(rest.len());
        pieces.push(&rest[..take]);
        rest = &rest[take..];
    }
    if !rest.is_empty() {
        pieces.push(rest);
    }
    pieces
}

fn seal(plaintext: &[u8], sizes: &[usize]) -> Vec<u8> {
    let mut encryptor = encryptor();
    let mut envelope = header().encode().to_vec();
    for piece in cut(plaintext, sizes) {
        for chunk in encryptor.push(piece).unwrap() {
            envelope.extend_from_slice(&chunk);
        }
    }
    envelope.extend_from_slice(&encryptor.finish().unwrap());
    envelope
}

fn open(envelope: &[u8], sizes: &[usize]) -> Result<Vec<u8>, FormatError> {
    // The `Decryptor` is header-unaware: feed it only the body, cut at `sizes`.
    // `Opener` is the header-parsing path and is exercised elsewhere.
    let mut decryptor = decryptor();
    let mut plaintext = Vec::new();
    for piece in cut(&envelope[Header::LEN..], sizes) {
        plaintext.extend_from_slice(&decryptor.push(piece)?);
    }
    plaintext.extend_from_slice(&decryptor.finish()?);
    Ok(plaintext)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn round_trips_random_payloads(
        data in proptest::collection::vec(any::<u8>(), 0..=1_048_576),
        sizes in proptest::collection::vec(0usize..=200_000, 0..=16),
    ) {
        let envelope = seal(&data, &sizes);
        prop_assert_eq!(open(&envelope, &sizes).unwrap(), data);
    }

    #[test]
    fn opener_reassembles_the_header(
        data in proptest::collection::vec(any::<u8>(), 0..=300_000),
        sizes in proptest::collection::vec(0usize..=70_000, 0..=32),
    ) {
        let envelope = seal(&data, &[97, 4_000, 70_000]);
        let mut opener = Opener::from_link_key(&key());
        let mut plaintext = Vec::new();
        for piece in cut(&envelope, &sizes) {
            plaintext.extend_from_slice(&opener.push(piece).unwrap());
        }
        plaintext.extend_from_slice(&opener.finish().unwrap());
        prop_assert_eq!(plaintext, data);
    }
}

#[test]
fn any_flipped_byte_after_the_header_fails() {
    let plaintext = pattern(200);
    let envelope = seal(&plaintext, &[37, 90, 73]);
    assert_eq!(open(&envelope, &[64]).unwrap(), plaintext);
    for index in Header::LEN..envelope.len() {
        let mut tampered = envelope.clone();
        tampered[index] ^= 0x80;
        let error = open(&tampered, &[1_000]).unwrap_err();
        assert_eq!(error, FormatError::AuthFailed, "flipped byte {index}");
    }
}

#[test]
fn dropping_the_last_chunk_is_truncated_or_auth_failed() {
    // One chunk: dropping it leaves a header and no chunks at all -> truncated.
    let single = seal(&pattern(100), &[100]);
    let header_only = &single[..Header::LEN];
    let mut opener = Opener::from_link_key(&key());
    assert_eq!(opener.push(header_only).unwrap(), Vec::<u8>::new());
    assert_eq!(opener.finish().unwrap_err(), FormatError::Truncated);

    // Two chunks: dropping the final one leaves a chunk, so the framing
    // reclassifies the survivor and its nonce no longer matches -> auth-failed.
    let two = seal(&pattern(CHUNK_SIZE + 1), &[1_000_000]);
    let without_last = &two[..two.len() - (1 + 16)];
    assert_eq!(
        open(without_last, &[1_000]).unwrap_err(),
        FormatError::AuthFailed
    );
}

#[test]
fn empty_payload_round_trips() {
    let envelope = seal(&[], &[]);
    assert_eq!(envelope.len(), Header::LEN + 16);
    assert_eq!(open(&envelope, &[1, 1, 1]).unwrap(), Vec::<u8>::new());
}

#[test]
fn buffers_stay_bounded_over_64_mib() {
    let total = 64 * 1024 * 1024;
    let plaintext = pattern(total);
    let sizes = [1usize, 13, 4096, 65_535, 65_536, 65_537, 1 << 20];

    let mut encryptor = encryptor();
    let mut decryptor = decryptor();
    let mut recovered = Vec::with_capacity(total);

    let mut offset = 0;
    let mut step = 0;
    while offset < total {
        let size = sizes[step % sizes.len()].min(total - offset);
        for chunk in encryptor.push(&plaintext[offset..offset + size]).unwrap() {
            assert!(chunk.len() <= BLOCK_LEN);
            let released = decryptor.push(&chunk).unwrap();
            assert!(released.len() <= 2 * CHUNK_SIZE);
            recovered.extend_from_slice(&released);
        }
        assert!(encryptor.buffered_len() <= CHUNK_SIZE + 1);
        assert!(decryptor.buffered_len() <= BLOCK_LEN + 1);
        offset += size;
        step += 1;
    }
    recovered.extend_from_slice(&decryptor.push(&encryptor.finish().unwrap()).unwrap());
    recovered.extend_from_slice(&decryptor.finish().unwrap());
    assert_eq!(recovered.len(), total);
    assert_eq!(recovered, plaintext);
}

#[test]
fn sixteen_mib_round_trip() {
    let mut rng = ChaCha20Rng::from_seed([0x5A; 32]);
    let data = pattern(16 * 1024 * 1024);
    let envelope = seal_bytes(&mut rng, &key(), &data).unwrap();
    assert_eq!(open_bytes(&key(), &envelope).unwrap(), data);
}

#[test]
fn debug_never_leaks_a_secret() {
    const KEY_TEXT: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
    const LINK: &str =
        "https://sealb.in/s/k7Qx9pL2Hd4m#key=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

    let link = Link::parse(LINK).unwrap();
    let debug = format!("{link:?}");
    assert!(!debug.contains(KEY_TEXT));
    assert!(!debug.contains(&KEY_TEXT[12..32]));
    assert!(debug.contains("[redacted]"));

    let link_key = link.key().clone();
    let ikm = Ikm::from_link_key(&link_key);
    let schedule = KeySchedule::derive(&ikm, &header());
    assert_eq!(format!("{link_key:?}"), "LinkKey([redacted])");
    assert_eq!(format!("{ikm:?}"), "Ikm([redacted])");
    assert_eq!(format!("{:?}", schedule.payload), "PayloadKey([redacted])");
    assert_eq!(
        format!("{:?}", schedule.read_token),
        "ReadToken([redacted])"
    );
    assert_eq!(
        format!("{:?}", ReadToken::from_bytes([0u8; 32])),
        "ReadToken([redacted])"
    );
}
