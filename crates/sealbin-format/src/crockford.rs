//! Crockford base32 (spec §14): the key id alphabet.
//!
//! Crockford's alphabet drops `i`, `l`, `o` and `u`, so a hand-copied id cannot
//! quietly turn one character into another. This module is the only place in
//! the crate that knows the alphabet, exactly as [`crate::b64`] is the only
//! place that knows base64url. It is deliberately narrow: it encodes an
//! arbitrary byte string and decodes the canonical form of a 16-byte value,
//! which is the size of a key id.

/// The Crockford base32 alphabet in lower case, 32 characters:
/// `0123456789abcdefghjkmnpqrstvwxyz`.
pub(crate) const ALPHABET: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";

/// Characters that decode as the digit they resemble. Crockford allows these
/// on input; the encoder never emits them, so a canonical encoding still round
/// trips.
const ALIASES: [(u8, u8); 4] = [(b'i', b'1'), (b'l', b'1'), (b'o', b'0'), (b'u', b'v')];

/// The number of characters a 16-byte value encodes to: 128 bits rounded up to
/// a whole number of five-bit groups.
pub(crate) const KEY_ID_CHARS: usize = 26;

/// Encode a byte string as unpadded Crockford base32, most significant bit
/// first.
///
/// Five bits of input become one character. When the input is not a whole
/// number of five-bit groups the last character carries only the bits that
/// remain, left aligned; 16 bytes therefore become exactly 26 characters, of
/// which the last encodes three bits.
#[must_use]
pub(crate) fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    // A 16-bit window: at most 4 buffered bits plus the 8 of the next byte.
    let mut window = 0u32;
    let mut bits = 0u32;
    for byte in bytes {
        window = (window << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(symbol((window >> bits) & 0x1f));
        }
    }
    if bits > 0 {
        // The bits above `bits` have already been consumed; only the ones
        // below are part of the last group, and they are left aligned in it.
        let remaining = window & ((1 << bits) - 1);
        out.push(symbol((remaining << (5 - bits)) & 0x1f));
    }
    out
}

/// Decode a 26-character key id back to its 16 bytes.
///
/// Upper case is accepted, and the four alias characters decode as the digit
/// they resemble; any other character is rejected. The final character carries
/// the last three bits, left aligned in its five-bit group, so its low two bits
/// are outside the 128 and MUST be zero: exactly one canonical string decodes
/// to any 16 bytes.
pub(crate) fn decode_16(text: &str) -> Option<[u8; 16]> {
    if text.len() != KEY_ID_CHARS {
        return None;
    }
    let mut out = [0u8; 16];
    let mut written = 0;
    let mut window = 0u32;
    let mut bits = 0u32;
    for (index, byte) in text.bytes().enumerate() {
        let mut group = u32::from(value(byte)?);
        let width = if index == KEY_ID_CHARS - 1 {
            if group & 0b11 != 0 {
                return None;
            }
            group >>= 2;
            3
        } else {
            5
        };
        window = (window << width) | group;
        bits += width;
        while bits >= 8 && written < out.len() {
            bits -= 8;
            out[written] = u8::try_from((window >> bits) & 0xff).ok()?;
            written += 1;
        }
    }
    Some(out)
}

/// The alphabet character for a five-bit group.
///
/// # Panics
///
/// Never: the caller has masked the argument to five bits, which is always a
/// valid index into a 32-character alphabet.
fn symbol(value: u32) -> char {
    char::from(ALPHABET[usize::try_from(value).expect("five bits fit in a usize")])
}

/// One input character to its five-bit value, or `None` if it is not in the
/// alphabet and not an alias.
fn value(byte: u8) -> Option<u8> {
    let lower = byte.to_ascii_lowercase();
    let resolved = ALIASES
        .iter()
        .find(|(from, _)| *from == lower)
        .map_or(lower, |(_, to)| *to);
    let index = ALPHABET
        .iter()
        .position(|candidate| *candidate == resolved)?;
    u8::try_from(index).ok()
}

#[cfg(test)]
mod tests {
    use super::{KEY_ID_CHARS, decode_16, encode};

    #[test]
    fn sixteen_bytes_are_twenty_six_characters() {
        let encoded = encode(&[0u8; 16]);
        assert_eq!(encoded.len(), KEY_ID_CHARS);
        assert_eq!(encoded, "0".repeat(KEY_ID_CHARS));
    }

    #[test]
    fn round_trips_every_leading_byte() {
        for high in 0..=u8::MAX {
            let mut bytes = [0u8; 16];
            bytes[0] = high;
            bytes[15] = high.reverse_bits();
            let encoded = encode(&bytes);
            assert_eq!(decode_16(&encoded), Some(bytes), "{high:02x}");
        }
    }

    #[test]
    fn round_trips_the_all_ones_value() {
        let bytes = [0xffu8; 16];
        let encoded = encode(&bytes);
        // 128 ones is 25 groups of five ones, which is the last character of
        // the alphabet, and a final group of three ones left aligned, which is
        // `11100` — the fourth character from the end of the alphabet.
        assert_eq!(encoded, format!("{}w", "z".repeat(25)));
        assert_eq!(decode_16(&encoded), Some(bytes));
    }

    #[test]
    fn decoding_accepts_case_and_the_four_aliases() {
        let mut bytes = [0u8; 16];
        // The first byte encodes as the leading characters `1` then `0`.
        bytes[0] = 0x08;
        let encoded = encode(&bytes);
        assert!(encoded.starts_with("10"), "{encoded}");
        assert_eq!(decode_16(&encoded.to_uppercase()), Some(bytes));
        assert_eq!(decode_16(&replace_at(&encoded, 0, 'i')), Some(bytes));
        assert_eq!(decode_16(&replace_at(&encoded, 0, 'l')), Some(bytes));
        assert_eq!(decode_16(&replace_at(&encoded, 1, 'o')), Some(bytes));
        // `u` stands for `v`, and neither ever appears in an encoding.
        let mut v = "u".repeat(KEY_ID_CHARS);
        v.replace_range(25..26, "v");
        assert_eq!(decode_16(&v), decode_16(&"v".repeat(KEY_ID_CHARS)));
    }

    fn replace_at(text: &str, at: usize, to: char) -> String {
        let mut chars: Vec<char> = text.chars().collect();
        chars[at] = to;
        chars.into_iter().collect()
    }

    #[test]
    fn rejects_bad_length_characters_and_trailing_bits() {
        let encoded = encode(&[0u8; 16]);
        assert!(decode_16(&encoded[..25]).is_none());
        let mut long = encoded.clone();
        long.push('0');
        assert!(decode_16(&long).is_none());
        let mut bad = encoded.clone();
        bad.replace_range(0..1, "*");
        assert!(decode_16(&bad).is_none());
        // The last character of 16 zero bytes is `0`; `z` puts two bits below
        // the last three, which are outside the 128 bits.
        let mut wide = encoded.clone();
        wide.replace_range(25..26, "z");
        assert!(decode_16(&wide).is_none());
    }
}
