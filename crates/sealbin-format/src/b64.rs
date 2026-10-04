//! A minimal, dependency-free base64url (RFC 4648 §5, no padding) codec for
//! exactly 32 bytes.
//!
//! The link key is the only value in the format that is base64url-encoded by
//! this crate: 32 bytes encode to exactly 43 characters. The codec is
//! deliberately narrow — it accepts only the 43-character canonical form and
//! nothing else — so it cannot be mistaken for a general-purpose base64.

/// The base64url alphabet, `A-Z a-z 0-9 - _`.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Number of base64url characters a 32-byte value encodes to.
pub(crate) const ENCODED_LEN: usize = 43;

/// The only 16 characters a canonical 43rd character may take: those whose
/// 6-bit value has the low two bits clear, so the final 32 bytes are exact
/// (spec §1, `AEIMQUYcgkosw048`).
const CANONICAL_LAST: &[u8; 16] = b"AEIMQUYcgkosw048";

/// Decode one base64url character to its 6-bit value, or `None` if it is not
/// in the alphabet. `+`, `/` and `=` are rejected: the format is URL-safe and
/// unpadded.
fn value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

/// Encode 32 bytes as exactly 43 base64url characters.
#[must_use]
pub(crate) fn encode_32(bytes: &[u8; 32]) -> [u8; ENCODED_LEN] {
    let mut out = [0u8; ENCODED_LEN];
    let mut src = 0;
    let mut dst = 0;
    // Ten full groups of three bytes become forty characters ...
    while src < 30 {
        let triple = (u32::from(bytes[src]) << 16)
            | (u32::from(bytes[src + 1]) << 8)
            | u32::from(bytes[src + 2]);
        out[dst] = ALPHABET[((triple >> 18) & 63) as usize];
        out[dst + 1] = ALPHABET[((triple >> 12) & 63) as usize];
        out[dst + 2] = ALPHABET[((triple >> 6) & 63) as usize];
        out[dst + 3] = ALPHABET[(triple & 63) as usize];
        src += 3;
        dst += 4;
    }
    // ... and the final two bytes become three characters, the last encoding
    // only the low four bits of the last byte.
    let last = u32::from(bytes[30]);
    let final_byte = u32::from(bytes[31]);
    out[dst] = ALPHABET[(last >> 2) as usize];
    out[dst + 1] = ALPHABET[(((last & 3) << 4) | (final_byte >> 4)) as usize];
    out[dst + 2] = ALPHABET[((final_byte & 15) << 2) as usize];
    out
}

/// Decode exactly 43 canonical base64url characters to 32 bytes, or `None`.
///
/// Rejects: any length other than 43, any character outside the base64url
/// alphabet (including `+`, `/` and `=`), and a non-canonical final character
/// (spec §1).
#[must_use]
pub(crate) fn decode_32(text: &str) -> Option<[u8; 32]> {
    let bytes = text.as_bytes();
    if bytes.len() != ENCODED_LEN {
        return None;
    }
    if !CANONICAL_LAST.contains(&bytes[ENCODED_LEN - 1]) {
        return None;
    }
    let mut out = [0u8; 32];
    let mut src = 0;
    let mut dst = 0;
    while dst < 30 {
        let first = value(bytes[src])?;
        let second = value(bytes[src + 1])?;
        let third = value(bytes[src + 2])?;
        let fourth = value(bytes[src + 3])?;
        out[dst] = (first << 2) | (second >> 4);
        out[dst + 1] = (second << 4) | (third >> 2);
        out[dst + 2] = (third << 6) | fourth;
        src += 4;
        dst += 3;
    }
    // bytes[40], bytes[41]: the last three characters carry two bytes.
    let first = value(bytes[40])?;
    let second = value(bytes[41])?;
    let third = value(bytes[42])?;
    out[30] = (first << 2) | (second >> 4);
    out[31] = (second << 4) | (third >> 2);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::{decode_32, encode_32};

    #[test]
    fn round_trips_zero_and_one() {
        let zero = [0u8; 32];
        let encoded = encode_32(&zero);
        assert_eq!(
            core::str::from_utf8(&encoded).unwrap(),
            "A".repeat(42) + "A"
        );
        assert_eq!(
            decode_32(core::str::from_utf8(&encoded).unwrap()),
            Some(zero)
        );

        let mut one = [0u8; 32];
        one[31] = 1;
        let encoded = encode_32(&one);
        // The final character carries bits 4..8 of the last byte: 1 << 2 == 4.
        assert!(encoded.ends_with(b"E"));
        assert_eq!(
            decode_32(core::str::from_utf8(&encoded).unwrap()),
            Some(one)
        );
    }

    #[test]
    fn rejects_non_canonical_and_bad_input() {
        let good = encode_32(&[7u8; 32]);
        let good = core::str::from_utf8(&good).unwrap();
        assert!(decode_32(good).is_some());
        // Flip the last character to a non-canonical one ('B' has the low two
        // bits set, so it does not encode a whole number of bytes).
        let mut bad = good.as_bytes().to_vec();
        bad[42] = b'B';
        assert!(decode_32(core::str::from_utf8(&bad).unwrap()).is_none());
        // Short and long.
        assert!(decode_32(&good[..42]).is_none());
        assert!(decode_32(&format!("{good}A")).is_none());
        // Standard-base64 characters and padding are not in the alphabet.
        for &standard in b"+/=" {
            let mut bytes = good.as_bytes().to_vec();
            bytes[0] = standard;
            assert!(decode_32(core::str::from_utf8(&bytes).unwrap()).is_none());
        }
    }
}
