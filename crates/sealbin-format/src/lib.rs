//! The sealbin handoff format.
//!
//! One crate holds the link, the envelope, the chunked AEAD, the KDFs, the read
//! token and the bundle — the wire format specified in `spec/`, nothing else.
//!
//! Rules (design decisions D4–D6):
//! - **Pure.** No I/O, no clocks, no randomness except through a caller-supplied
//!   RNG. Everything here is a function of its inputs and a byte slice.
//! - **Portable.** Compiles native and for `wasm32-unknown-unknown`: a browser
//!   must be able to open a link with no plugin, so no native-only crypto.
//! - **Frozen.** The crypto changes only with a spec change in `spec/` and new
//!   test vectors, in the same pull request.
