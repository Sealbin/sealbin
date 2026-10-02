//! `@sealbin/crypto`: the wasm-bindgen wrapper over `sealbin-format`.
//!
//! The browser open page (`/s/`) runs this so a link with no plugin can be
//! opened client-side, and the npm package `@sealbin/crypto` wraps it (D1, #5).
//!
//! At the scaffold (#1) this is an empty package: the bindings and the
//! wasm-bindgen dependency arrive with #5, which owns the browser build.
