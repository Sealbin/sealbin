//! The sealbin server domain, with no harness types.
//!
//! The seal state machine (`sealed -> opening -> gone`, D8), the plans as data
//! (D13) and the id and limit rules live here. It deliberately depends on
//! nothing from the Cratefield harness (D1), so the rules are testable as plain
//! Rust and usable from the CLI.
