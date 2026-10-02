//! The sealbin Worker — the venture.
//!
//! It composes the harness, defines the `SealObject` Durable Object class (one
//! per seal, the authority on its state — D9) and ships `wrangler.toml` and
//! `migrations/` (issues #7–#8).
//!
//! At the scaffold (#1) it is a single `#[event(fetch)]` answering `503` with
//! `not yet`. The crate is a `cdylib`: `worker-build` builds it for
//! `wasm32-unknown-unknown`, and it must also compile natively so
//! `cargo test --workspace` and `cargo clippy --workspace --all-targets` see it.
use worker::{Context, Env, Request, Response, Result, event};

#[event(fetch)]
async fn fetch(_req: Request, _env: Env, _ctx: Context) -> Result<Response> {
    Response::error("not yet", 503)
}
