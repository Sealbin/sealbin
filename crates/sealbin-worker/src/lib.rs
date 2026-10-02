//! The sealbin Worker — the venture.
//!
//! It composes the harness (D1), defines the `SealObject` Durable Object
//! class (one per seal, the authority on its state — D9) and ships
//! `wrangler.toml`, `migrations/` and the two browser pages (#7–#8).
//!
//! Routing is thin: `/s/*` and `/activate*` are static pages from the `ASSETS`
//! binding, everything else is the harness (`serve`), which owns `/__health`,
//! `/.well-known/sealbin` and `/v1/*` (D3, D10). The crate is a `cdylib` built
//! for `wasm32-unknown-unknown`; it must also compile natively so
//! `cargo test --workspace` and `cargo clippy --workspace --all-targets` see it.

use std::sync::OnceLock;
use std::time::Duration;

use cratefield_core::{ConfigError, Harness, Venture, VentureEnv};
use cratefield_runtime_cloudflare::{Cloudflare, Limit, serve, serve_scheduled};
use sealbin_server::Seals;
use worker::{
    Context, DurableObject, Env, Method, Request, Response, Result, ScheduleContext,
    ScheduledEvent, State, console_error, durable_object, event,
};

/// The one composed harness for the isolate. Both handlers take it from here:
/// building it per request would re-validate every module's ports on every
/// invocation. `build` is fallible, so the error is cached too and every
/// request answers `500` rather than panicking.
static INSTANCE: OnceLock<std::result::Result<(Harness, Cloudflare), ConfigError>> =
    OnceLock::new();

/// Composes the venture. Reads only config vars, never a secret.
fn build(env: &Env) -> std::result::Result<(Harness, Cloudflare), ConfigError> {
    // The link host: `https://sealb.in` hosted, the deployment's own URL when
    // self-hosted (D3). `SEALBIN_API_URL` is the seals module's own key for
    // `/.well-known/sealbin` and is not read here.
    let public_url = var_or(env, "SEALBIN_PUBLIC_URL", "https://sealb.in");
    let venture_env = env
        .var("ENV")
        .ok()
        .and_then(|value| VentureEnv::parse(&value.to_string()))
        .unwrap_or_default();

    let venture = Venture::new("sealbin", "sealb.in")
        .public_url(public_url.clone())
        // The browser pages are same-origin with the API when hosted; naming
        // the link host keeps `*` out of the allowlist (D2, §6).
        .cors_origins([public_url])
        .env(venture_env);

    let runtime = Cloudflare::new()
        .db("DB")
        .blob("SEALS")
        // One port slot for two limiters: the D1 per-key limiter wins where
        // both resolve, so this binding is the coarse fallback for a
        // deployment whose `DB` is missing.
        .rate_limiter("RATE_LIMITER")
        .d1_rate_limiter("DB", rate_limit_policy);

    let harness = Harness::builder()
        .venture(venture)
        .module(Seals::new())
        .runtime(runtime.clone())
        .build()?;

    Ok((harness, runtime))
}

/// A config var, or `default` when unset or empty.
fn var_or(env: &Env, name: &str, default: &str) -> String {
    env.var(name)
        .map(|value| value.to_string())
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| default.to_owned())
}

/// The placeholder per-key budget: one flat minute for every key. Issue #15
/// replaces it with the per-plan ceilings from `sealbin-core` (D13).
#[allow(clippy::unnecessary_wraps)] // `None` means unlimited — the real policy uses it.
fn rate_limit_policy(_key: &str) -> Option<Limit> {
    Some(Limit {
        max: 60,
        period: Duration::from_secs(60),
    })
}

/// Serves `page` (an asset path in `web/dist/`) for the original request.
async fn asset(env: &Env, req: &Request, page: &str) -> Result<Response> {
    // Rewrite the path, keep the request's own origin: the assets binding sees
    // the host it fronted, so `html_handling` sees a consistent URL.
    let mut url = req.url()?;
    url.set_path(page);
    url.set_query(None);
    env.assets("ASSETS")?.fetch(url.to_string(), None).await
}

/// The fetch handler: pages first, harness for everything else.
#[event(fetch)]
async fn fetch(req: Request, env: Env, ctx: Context) -> Result<Response> {
    let path = req.path();
    if matches!(req.method(), Method::Get | Method::Head) {
        if path.starts_with("/s/") {
            return asset(&env, &req, "/open.html").await;
        }
        if path.starts_with("/activate") {
            return asset(&env, &req, "/activate.html").await;
        }
    }

    let (harness, runtime) = match INSTANCE.get_or_init(|| build(&env)) {
        Ok(pair) => pair,
        Err(err) => {
            console_error!("sealbin: harness composition failed: {err}");
            return Response::error("sealbin is misconfigured", 500);
        }
    };
    serve(harness, runtime, req, env, ctx).await
}

/// The scheduled handler: the harness fans the cron out to every module.
#[event(scheduled)]
async fn scheduled(event: ScheduledEvent, env: Env, ctx: ScheduleContext) {
    let (harness, runtime) = match INSTANCE.get_or_init(|| build(&env)) {
        Ok(pair) => pair,
        Err(err) => {
            console_error!("sealbin: harness composition failed: {err}");
            return;
        }
    };
    serve_scheduled(harness, runtime, event, env, ctx).await;
}

/// One Durable Object per seal, named by the seal id: the authority on the
/// seal's state and, later, its ciphertext (D9). #7 ships the class so the
/// binding, migration and bundle exist; #8 fills in the state machine.
#[durable_object(fetch)]
pub struct SealObject {
    #[expect(dead_code, reason = "read by the seal state machine in #8")]
    state: State,
    #[expect(dead_code, reason = "read by the seal state machine in #8")]
    env: Env,
}

impl DurableObject for SealObject {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }

    // The trait requires `async`; #8 awaits the seal state machine here.
    #[allow(clippy::unused_async_trait_impl)]
    async fn fetch(&self, _req: Request) -> Result<Response> {
        Response::error("not implemented", 501)
    }
}
