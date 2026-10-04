//! The error type for the format.
//!
//! One enum covers every failure the link, header and envelope layers can
//! report. Each variant maps to the stable name the spec gives it in §1 and
//! §6; [`FormatError::code`] returns that name. No variant carries data, so an
//! error can never leak key material, a fragment or a password into a log.

/// A failure in the link, header or envelope layer.
///
/// The variants are unit variants on purpose: an error message must never
/// contain the fragment, the key or the password (spec §13, "Never log a link
/// containing `#key=`").
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FormatError {
    /// No `key` parameter in the fragment (spec §1).
    #[error("the link has no key parameter")]
    MissingKey,
    /// The `key` is not 43 canonical base64url characters decoding to 32 bytes.
    #[error("the link key is not a canonical 32-byte base64url value")]
    BadKey,
    /// More than one `key` parameter.
    #[error("the link has more than one key parameter")]
    DuplicateKey,
    /// The `id` is not 12 base62 characters.
    #[error("the link id is not 12 base62 characters")]
    BadId,
    /// The link is malformed in a way not covered by a more specific name:
    /// an unknown scheme, a non-loopback `http` host, or a path that is not
    /// `/s/<id>`. No spec name covers this, so it carries the local code
    /// `link/bad-link`.
    #[error("the link is not a valid sealbin link")]
    BadLink,
    /// The first 7 bytes of the header are not `SEALBIN`.
    #[error("the envelope magic is not SEALBIN")]
    BadMagic,
    /// The version byte is not `0x01`.
    #[error("the envelope version is not supported")]
    UnsupportedVersion,
    /// A reserved flag bit is set.
    #[error("the envelope flags set a reserved bit")]
    UnknownFlags,
    /// A header field violates the spec's rules: `chunk_size` is not 65,536,
    /// or the iterations/salt rules of §5 are broken.
    #[error("the envelope header is invalid")]
    BadHeader,
    /// Input ends inside the header, fewer than 16 bytes remain for a chunk,
    /// or there are no chunks.
    #[error("the envelope is truncated")]
    Truncated,
    /// An AES-GCM tag did not verify. This covers a chunk-boundary truncation,
    /// reordered chunks, trailing bytes, an empty chunk after the genuine final
    /// one, and a wrong key or password.
    #[error("the envelope failed authentication")]
    AuthFailed,
    /// A writer exceeded the v1 cap of fewer than 2^32 chunks.
    #[error("the payload has too many chunks for a v1 seal")]
    TooManyChunks,
}

impl FormatError {
    /// The stable name the spec gives this error, or the crate's local code.
    ///
    /// The `link/*` and `envelope/*` names are the ones in
    /// `spec/handoff-format.md` §1 and §6. `link/bad-link` and
    /// `envelope/too-many-chunks` are not spec names: they are local codes for
    /// cases the spec folds into a broader rule or leaves unspecified.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::MissingKey => "link/missing-key",
            Self::BadKey => "link/bad-key",
            Self::DuplicateKey => "link/duplicate-key",
            Self::BadId => "link/bad-id",
            Self::BadLink => "link/bad-link",
            Self::BadMagic => "envelope/bad-magic",
            Self::UnsupportedVersion => "envelope/unsupported-version",
            Self::UnknownFlags => "envelope/unknown-flags",
            Self::BadHeader => "envelope/bad-header",
            Self::Truncated => "envelope/truncated",
            Self::AuthFailed => "envelope/auth-failed",
            Self::TooManyChunks => "envelope/too-many-chunks",
        }
    }
}
