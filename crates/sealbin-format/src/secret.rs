//! The shared shape of the 32-byte secret key types.
//!
//! Every key the format handles — the link key, the payload key, the read
//! token — is a 32-byte secret with the same rules: it zeroises on drop, its
//! `Debug` output is `Name([redacted])`, it has no `Display` and no `Serialize`
//! (so it cannot be formatted or serialised into a log or a request body), and
//! it compares in constant time. One macro keeps those rules in one place.

macro_rules! define_key_type {
    ($(#[$meta:meta])* $name:ident, $label:literal) => {
        $(#[$meta])*
        #[derive(Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Wrap 32 raw bytes.
            #[must_use]
            pub fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            /// Borrow the raw bytes.
            #[must_use]
            pub fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(concat!($label, "([redacted])"))
            }
        }

        impl subtle::ConstantTimeEq for $name {
            fn ct_eq(&self, other: &Self) -> subtle::Choice {
                subtle::ConstantTimeEq::ct_eq(&self.0[..], &other.0[..])
            }
        }

        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                bool::from(subtle::ConstantTimeEq::ct_eq(self, other))
            }
        }

        impl Eq for $name {}
    };
}

pub(crate) use define_key_type;
