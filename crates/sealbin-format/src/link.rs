//! The v1 link: `https://<host>/s/<id>#key=<k>` (spec §1, D4).
//!
//! The fragment never reaches a server, so the link is parsed and its key
//! decoded entirely client-side. `http://` is accepted only for `localhost`
//! and `127.0.0.1`, so the dev and test pages work without weakening the rule
//! that a real link is HTTPS.

use core::fmt;
use core::str::FromStr;

use rand_core::CryptoRng;

use crate::b64;
use crate::error::FormatError;
use crate::secret::define_key_type;

/// The base62 alphabet, `0-9 A-Z a-z` (spec §1).
const BASE62: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// A 12-character base62 seal id (spec §1, D4).
///
/// Ids are generated server-side and are public; they carry no secret.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SealId([u8; 12]);

/// Is `byte` one of the 62 base62 characters?
fn is_base62(byte: u8) -> bool {
    byte.is_ascii_digit() || byte.is_ascii_uppercase() || byte.is_ascii_lowercase()
}

impl SealId {
    /// Length of a seal id in characters.
    pub const LEN: usize = 12;

    /// Draw a uniform 12-character base62 id from `rng`.
    ///
    /// Rejection sampling keeps every character uniform: bytes below 248 (62 ×
    /// 4) map onto the 62-symbol alphabet, the rest are discarded. The loop
    /// draws 16 bytes at a time so a CSPRNG call is not made per character.
    #[must_use]
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let mut id = [0u8; Self::LEN];
        let mut filled = 0;
        while filled < Self::LEN {
            let mut drawn = [0u8; 16];
            rng.fill_bytes(&mut drawn);
            for byte in drawn {
                if byte < 248 {
                    id[filled] = BASE62[usize::from(byte % 62)];
                    filled += 1;
                    if filled == Self::LEN {
                        break;
                    }
                }
            }
        }
        Self(id)
    }

    /// Borrow the id as its 12-character string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        id_str(&self.0)
    }
}

/// Borrow a 12-byte seal id as ASCII.
///
/// Private, so the impossible panic (every constructor admits only base62
/// bytes) is not part of [`SealId::as_str`]'s documented contract.
fn id_str(id: &[u8; SealId::LEN]) -> &str {
    core::str::from_utf8(id).expect("a seal id is base62 ASCII")
}

impl fmt::Display for SealId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for SealId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SealId({})", self.as_str())
    }
}

impl FromStr for SealId {
    type Err = FormatError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let bytes = text.as_bytes();
        if bytes.len() != Self::LEN || !bytes.iter().copied().all(is_base62) {
            return Err(FormatError::BadId);
        }
        let mut id = [0u8; Self::LEN];
        id.copy_from_slice(bytes);
        Ok(Self(id))
    }
}

define_key_type!(
    /// The 32-byte link key `K_link`, carried in the fragment (spec §3).
    ///
    /// A bearer secret: it zeroises on drop and never appears in `Debug`,
    /// `Display` or any serialised form.
    LinkKey,
    "LinkKey"
);

impl LinkKey {
    /// Draw a fresh link key from `rng`.
    #[must_use]
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self::from_bytes(bytes)
    }

    /// Decode a 43-character canonical base64url key, or [`FormatError::BadKey`].
    fn from_b64(text: &str) -> Result<Self, FormatError> {
        b64::decode_32(text)
            .map(Self::from_bytes)
            .ok_or(FormatError::BadKey)
    }

    /// The canonical base64url encoding, 43 characters.
    fn encode_b64(&self) -> [u8; b64::ENCODED_LEN] {
        b64::encode_32(self.as_bytes())
    }
}

/// A parsed sealbin link.
///
/// `origin` is the scheme and authority (`https://host[:port]`) so that
/// re-rendering the link round-trips exactly.
#[derive(Clone)]
pub struct Link {
    origin: String,
    id: SealId,
    key: LinkKey,
}

impl Link {
    /// Parse a v1 link (spec §1).
    ///
    /// # Errors
    ///
    /// - [`FormatError::BadLink`] for an unknown scheme, an authority with user
    ///   information, no host or a bad port, `http` on a host that is not
    ///   `localhost` or `127.0.0.1`, or a path that is not `/s/<id>`. The
    ///   scheme is matched case-insensitively and normalised to lower case in
    ///   [`Link::origin`].
    /// - [`FormatError::BadId`] when the id is not 12 base62 characters.
    /// - [`FormatError::MissingKey`] when there is no fragment, or the fragment
    ///   has no `key` parameter. A missing fragment is reported as a missing
    ///   key, because it can never carry one.
    /// - [`FormatError::DuplicateKey`] for a second `key`.
    /// - [`FormatError::BadKey`] for a `key` that is not 43 canonical base64url
    ///   characters, percent-encoded, or decoding to other than 32 bytes.
    pub fn parse(text: &str) -> Result<Self, FormatError> {
        let (scheme, rest) = text.split_once("://").ok_or(FormatError::BadLink)?;
        // RFC 3986 §3.1: a scheme is case-insensitive. Normalise it so `origin`
        // is canonical.
        let scheme = if scheme.eq_ignore_ascii_case("https") {
            "https"
        } else if scheme.eq_ignore_ascii_case("http") {
            "http"
        } else {
            return Err(FormatError::BadLink);
        };
        let (before_fragment, fragment) = rest.split_once('#').ok_or(FormatError::MissingKey)?;
        let (authority, path) = before_fragment
            .split_once('/')
            .ok_or(FormatError::BadLink)?;
        // The authority is `host [":" port]` (spec §1): a v1 link carries no
        // user information (RFC 3986 §3.2.2 begins at the host), and a host is
        // required. Rejecting both keeps `user@host` from smuggling a
        // non-loopback `http` host past the check below, or leaking into
        // `origin`.
        if authority.contains('@') {
            return Err(FormatError::BadLink);
        }
        let (host, port) = split_authority(authority).ok_or(FormatError::BadLink)?;
        if host.is_empty() || port.is_some_and(|port| !valid_port(port)) {
            return Err(FormatError::BadLink);
        }
        if scheme == "http" && host != "localhost" && host != "127.0.0.1" {
            return Err(FormatError::BadLink);
        }
        let id = path
            .strip_prefix("s/")
            .ok_or(FormatError::BadLink)?
            .parse::<SealId>()?;
        let key = parse_key_parameter(fragment)?;
        Ok(Self {
            origin: format!("{scheme}://{authority}"),
            id,
            key,
        })
    }

    /// The scheme and authority, e.g. `https://sealb.in`.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// The seal id.
    #[must_use]
    pub fn id(&self) -> SealId {
        self.id
    }

    /// The link key.
    #[must_use]
    pub fn key(&self) -> &LinkKey {
        &self.key
    }

    /// The link with no fragment: the URL a client would fetch.
    #[must_use]
    pub fn without_key(&self) -> String {
        format!("{}/s/{}", self.origin, self.id)
    }
}

impl fmt::Display for Link {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let encoded = self.key.encode_b64();
        let encoded = core::str::from_utf8(&encoded).expect("base64url is ASCII");
        write!(f, "{}/s/{}#key={encoded}", self.origin, self.id)
    }
}

impl fmt::Debug for Link {
    /// Prints the origin and id but never the key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Link")
            .field("origin", &self.origin)
            .field("id", &self.id)
            .field("key", &"[redacted]")
            .finish()
    }
}

/// Split an authority into its host and optional port, `host [":" port]`.
///
/// Returns `None` for a malformed authority: an unterminated IPv6 bracket, or
/// trailing bytes after the `]` that are not a `:port`. An empty host comes
/// back as `("", None)`; the caller rejects it.
///
/// `Link::parse` rejects an authority with user information before calling
/// this, so there is none to strip.
fn split_authority(authority: &str) -> Option<(&str, Option<&str>)> {
    if let Some(rest) = authority.strip_prefix('[') {
        // IPv6 literal: the host is between the brackets, and any port follows
        // the closing bracket.
        let (host, after) = rest.split_once(']')?;
        if after.is_empty() {
            Some((host, None))
        } else {
            Some((host, Some(after.strip_prefix(':')?)))
        }
    } else {
        match authority.split_once(':') {
            Some((host, port)) => Some((host, Some(port))),
            None => Some((authority, None)),
        }
    }
}

/// A port is 1-5 ASCII digits with a value in `1..=65535` (RFC 3986 §3.2.3).
fn valid_port(port: &str) -> bool {
    !port.is_empty()
        && port.len() <= 5
        && port.bytes().all(|byte| byte.is_ascii_digit())
        && port
            .parse::<u32>()
            .is_ok_and(|value| (1..=65_535).contains(&value))
}

/// Find the single `key` parameter in a fragment, ignoring every other name.
fn parse_key_parameter(fragment: &str) -> Result<LinkKey, FormatError> {
    let mut key: Option<LinkKey> = None;
    for parameter in fragment.split('&') {
        let (name, value) = parameter.split_once('=').unwrap_or((parameter, ""));
        if name == "key" {
            if key.is_some() {
                return Err(FormatError::DuplicateKey);
            }
            key = Some(LinkKey::from_b64(value)?);
        }
    }
    key.ok_or(FormatError::MissingKey)
}

#[cfg(test)]
mod tests {
    use super::{Link, LinkKey, SealId};
    use crate::error::FormatError;

    const KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
    const LINK: &str =
        "https://sealb.in/s/k7Qx9pL2Hd4m#key=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

    #[test]
    fn appendix_a_link_parses_and_round_trips() {
        let link = Link::parse(LINK).unwrap();
        assert_eq!(link.id().as_str(), "k7Qx9pL2Hd4m");
        assert_eq!(link.origin(), "https://sealb.in");
        let mut expected = [0u8; 32];
        for (i, byte) in expected.iter_mut().enumerate() {
            *byte = u8::try_from(i).unwrap();
        }
        assert_eq!(link.key().as_bytes(), &expected);
        assert_eq!(link.to_string(), LINK);
        assert_eq!(link.without_key(), "https://sealb.in/s/k7Qx9pL2Hd4m");
    }

    #[test]
    fn http_is_accepted_only_for_loopback() {
        assert!(Link::parse(&format!("http://localhost:8787/s/k7Qx9pL2Hd4m#key={KEY}")).is_ok());
        assert!(Link::parse(&format!("http://127.0.0.1/s/k7Qx9pL2Hd4m#key={KEY}")).is_ok());
        let err = Link::parse(&format!("http://example.com/s/k7Qx9pL2Hd4m#key={KEY}")).unwrap_err();
        assert_eq!(err, FormatError::BadLink);
    }

    #[test]
    fn scheme_is_case_insensitive_and_normalised() {
        let link = Link::parse(&format!("HTTPS://sealb.in/s/k7Qx9pL2Hd4m#key={KEY}")).unwrap();
        assert_eq!(link.origin(), "https://sealb.in");
        assert_eq!(
            link.to_string(),
            format!("https://sealb.in/s/k7Qx9pL2Hd4m#key={KEY}")
        );
        assert!(Link::parse(&format!("HtTp://localhost/s/k7Qx9pL2Hd4m#key={KEY}")).is_ok());
    }

    #[test]
    fn ports_are_validated() {
        for port in ["1", "8443", "65535"] {
            let text = format!("https://sealb.in:{port}/s/k7Qx9pL2Hd4m#key={KEY}");
            let link =
                Link::parse(&text).unwrap_or_else(|_| panic!("port {port} should be accepted"));
            assert_eq!(link.origin(), format!("https://sealb.in:{port}"));
        }
        for port in ["0", "65536", "999999", "80x", ""] {
            let text = format!("https://sealb.in:{port}/s/k7Qx9pL2Hd4m#key={KEY}");
            assert_eq!(
                Link::parse(&text).unwrap_err(),
                FormatError::BadLink,
                "port {port:?}"
            );
        }
    }

    #[test]
    fn userinfo_and_empty_host_are_rejected() {
        // A v1 authority has no user information (spec §1).
        assert_eq!(
            Link::parse(&format!(
                "https://evil.com@sealb.in/s/k7Qx9pL2Hd4m#key={KEY}"
            ))
            .unwrap_err(),
            FormatError::BadLink
        );
        // The loopback check must not read the userinfo as the host.
        assert_eq!(
            Link::parse(&format!(
                "http://localhost:8787@evil.com/s/k7Qx9pL2Hd4m#key={KEY}"
            ))
            .unwrap_err(),
            FormatError::BadLink
        );
        // A host is required, even when a port is present.
        assert_eq!(
            Link::parse(&format!("https://:8443/s/k7Qx9pL2Hd4m#key={KEY}")).unwrap_err(),
            FormatError::BadLink
        );
    }

    #[test]
    fn bad_scheme_and_path_are_bad_link() {
        assert_eq!(
            Link::parse(&format!("ftp://sealb.in/s/k7Qx9pL2Hd4m#key={KEY}")).unwrap_err(),
            FormatError::BadLink
        );
        assert_eq!(
            Link::parse(&format!("https://sealb.in/x/k7Qx9pL2Hd4m#key={KEY}")).unwrap_err(),
            FormatError::BadLink
        );
    }

    #[test]
    fn missing_fragment_is_missing_key() {
        assert_eq!(
            Link::parse("https://sealb.in/s/k7Qx9pL2Hd4m").unwrap_err(),
            FormatError::MissingKey
        );
        assert_eq!(
            Link::parse("https://sealb.in/s/k7Qx9pL2Hd4m#").unwrap_err(),
            FormatError::MissingKey
        );
        assert_eq!(
            Link::parse("https://sealb.in/s/k7Qx9pL2Hd4m#foo=bar").unwrap_err(),
            FormatError::MissingKey
        );
    }

    #[test]
    fn duplicate_key_is_rejected() {
        let text = format!("https://sealb.in/s/k7Qx9pL2Hd4m#key={KEY}&key={KEY}");
        assert_eq!(Link::parse(&text).unwrap_err(), FormatError::DuplicateKey);
    }

    #[test]
    fn bad_keys_are_rejected() {
        // 42 characters.
        assert_eq!(
            Link::parse(&format!(
                "https://sealb.in/s/k7Qx9pL2Hd4m#key={}",
                &KEY[..42]
            ))
            .unwrap_err(),
            FormatError::BadKey
        );
        // 44 characters.
        assert_eq!(
            Link::parse(&format!("https://sealb.in/s/k7Qx9pL2Hd4m#key={KEY}A")).unwrap_err(),
            FormatError::BadKey
        );
        // 43 characters, but a non-canonical last character.
        let mut non_canonical = KEY.to_owned();
        non_canonical.pop();
        non_canonical.push('B');
        assert_eq!(
            Link::parse(&format!(
                "https://sealb.in/s/k7Qx9pL2Hd4m#key={non_canonical}"
            ))
            .unwrap_err(),
            FormatError::BadKey
        );
        // Percent-encoded.
        assert_eq!(
            Link::parse(&format!(
                "https://sealb.in/s/k7Qx9pL2Hd4m#key={}%3D",
                &KEY[..42]
            ))
            .unwrap_err(),
            FormatError::BadKey
        );
    }

    #[test]
    fn bad_ids_are_rejected() {
        let too_short = format!("https://sealb.in/s/k7Qx9pL2Hd4#key={KEY}");
        let too_long = format!("https://sealb.in/s/k7Qx9pL2Hd4mm#key={KEY}");
        let non_base62 = format!("https://sealb.in/s/k7Qx9pL2Hd4-#key={KEY}");
        assert_eq!(Link::parse(&too_short).unwrap_err(), FormatError::BadId);
        assert_eq!(Link::parse(&too_long).unwrap_err(), FormatError::BadId);
        assert_eq!(Link::parse(&non_base62).unwrap_err(), FormatError::BadId);
    }

    #[test]
    fn unknown_parameters_are_ignored() {
        let text = format!("https://sealb.in/s/k7Qx9pL2Hd4m#to=nobody&key={KEY}&v=2");
        let link = Link::parse(&text).unwrap();
        assert_eq!(link.to_string(), LINK);
    }

    #[test]
    fn debug_never_shows_the_key() {
        let link = Link::parse(LINK).unwrap();
        let debug = format!("{link:?}");
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains(KEY));
        assert!(!debug.contains(&KEY[..20]));
    }

    #[test]
    fn secret_types_redact() {
        let key = LinkKey::from_bytes([1u8; 32]);
        assert_eq!(format!("{key:?}"), "LinkKey([redacted])");
    }

    #[test]
    fn seal_id_generation_is_base62() {
        use rand_chacha::rand_core::SeedableRng as _;
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([9u8; 32]);
        for _ in 0..64 {
            let id = SealId::generate(&mut rng);
            assert_eq!(id.as_str().len(), SealId::LEN);
            assert!(id.as_str().bytes().all(super::is_base62));
        }
    }
}
