//! Harness modules for sealbin: seals, agents, accounts, billing, audit, teams.
//!
//! Each is a feature-free [`cratefield_core::Module`] (D1, D10). This crate
//! talks to the harness; the domain rules live in `sealbin-core` and the wire
//! format in `sealbin-format`.

pub mod seals;

pub use seals::Seals;
