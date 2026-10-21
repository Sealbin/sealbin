//! The `seals` module (D10): the `/.well-known/sealbin` discovery document.
//!
//! The seal routes land in later issues; this module ships the document every
//! client resolves the API from (D3) and the `SEALBIN_API_URL` contract.

use std::sync::{Arc, RwLock};

use cratefield_core::axum::extract::State;
use cratefield_core::axum::http::{HeaderValue, Uri, header};
use cratefield_core::axum::response::{IntoResponse, Response};
use cratefield_core::axum::routing::get;
use cratefield_core::axum::{Json, Router};
use cratefield_core::{Config, ConfigError, Migrations, Module, ModuleContext, Port, Problem};

/// The deployment's public API base URL (D3). Read raw, not `SEALS_*`: it is
/// deployment-wide.
const API_URL_KEY: &str = "SEALBIN_API_URL";

/// Envelope versions published as `formats` (D5: v1 only).
const FORMATS: [u8; 1] = [1];

/// Largest ciphertext kept inline in its Durable Object rather than in R2 (D9).
const MAX_INLINE_BYTES: u64 = 1_048_576; // 1 MiB

/// Largest part accepted by the multipart upload path (D9).
const MAX_PART_BYTES: u64 = 52_428_800; // 50 MiB

/// How long a client may cache `/.well-known/sealbin` (D3).
const CACHE_MAX_AGE_SECS: u32 = 3_600;

/// The `seals` module. Compose it with [`Seals::new`].
#[derive(Default)]
pub struct Seals {
    /// The validated API base URL, for the well-known handler.
    ///
    /// Neither `well_known` nor a request handler gets the deployment config,
    /// so `router(ctx)` — rebuilt per request by `Harness::router` — stashes it
    /// here, and the well-known router shares the same `Arc`.
    api_url: Arc<RwLock<Option<String>>>,
}

impl Seals {
    /// A fresh `seals` module.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl Module for Seals {
    fn name(&self) -> &'static str {
        "seals"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn requires(&self) -> &'static [Port] {
        &[Port::Db, Port::Clock, Port::IdGen]
    }

    fn optional(&self) -> &'static [Port] {
        &[Port::Blob, Port::RateLimiter]
    }

    fn migrations(&self) -> Migrations {
        Migrations::EMPTY
    }

    fn validate_config(&self, cfg: &dyn Config) -> Result<(), ConfigError> {
        let mut errors = ConfigError::new();
        match cfg.get(API_URL_KEY) {
            None => errors.push(format!(
                "`{API_URL_KEY}` is required: set it to the deployment's public API base \
                 URL, e.g. `https://api.sealb.in`"
            )),
            Some(raw) => {
                if let Err(reason) = normalise_api_url(&raw) {
                    errors.push(format!("`{API_URL_KEY}` {reason}"));
                }
            }
        }
        errors.into_result()
    }

    fn router(&self, ctx: ModuleContext) -> Router {
        // The one hook that sees the config (see `Seals::api_url`); the write is
        // idempotent, so re-stashing per request is cheap.
        let resolved = ctx
            .config
            .get(API_URL_KEY)
            .and_then(|raw| normalise_api_url(&raw).ok());
        if let Ok(mut slot) = self.api_url.write() {
            *slot = resolved;
        }
        Router::new() // the seal routes land in later issues
    }

    fn well_known(&self) -> Option<Router> {
        Some(
            Router::new()
                .route("/sealbin", get(sealbin_document))
                .with_state(Arc::clone(&self.api_url)),
        )
    }
}

/// `GET /.well-known/sealbin` (D3): public, cacheable, names no secret.
async fn sealbin_document(State(api_url): State<Arc<RwLock<Option<String>>>>) -> Response {
    let Some(api) = api_url.read().ok().and_then(|slot| slot.clone()) else {
        return Problem::not_ready(format!("`{API_URL_KEY}` is not configured")).into_response();
    };
    let mut response = Json(serde_json::json!({
        "api": api,
        "formats": FORMATS,
        "limits": {
            "max_inline_bytes": MAX_INLINE_BYTES,
            "max_part_bytes": MAX_PART_BYTES,
        },
    }))
    .into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_str(&format!("public, max-age={CACHE_MAX_AGE_SECS}"))
            .expect("static Cache-Control value is valid"),
    );
    response
}

/// Parses the configured API URL, returning the normalised value (trailing `/`
/// removed) or a lower-case reason it was rejected. Accepted: absolute
/// `https://`, or `http://` on a loopback host (a local `wrangler dev` or a
/// test). Rejected: no host, userinfo, a query, a fragment, any other scheme.
fn normalise_api_url(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("is empty".into());
    }
    // `http::Uri` does not model fragments; refuse one outright.
    if trimmed.contains('#') {
        return Err("must not carry a fragment".into());
    }
    let uri: Uri = trimmed
        .parse()
        .map_err(|_| "is not a valid absolute URL".to_string())?;
    let Some(authority) = uri.authority() else {
        return Err("must be absolute: `<scheme>://<host>`".into());
    };
    if authority.as_str().contains('@') {
        return Err("must not carry userinfo".into());
    }
    if authority.host().is_empty() {
        return Err("has no host".into());
    }
    if uri.query().is_some() {
        return Err("must not carry a query".into());
    }
    match uri.scheme_str() {
        Some("https") => {}
        Some("http") if is_loopback_host(authority.host()) => {}
        Some("http") => {
            return Err("must be https:// (http:// is allowed only for a loopback host)".into());
        }
        _ => return Err("must be an https:// URL".into()),
    }
    Ok(trimmed.trim_end_matches('/').to_owned())
}

/// Loopback for the `http://` exemption above.
fn is_loopback_host(host: &str) -> bool {
    let host = host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(host);
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<core::net::IpAddr>()
        .is_ok_and(|addr| addr.is_loopback())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cratefield_core::MapConfig;
    use cratefield_core::axum::http::{Method, StatusCode};
    use cratefield_testing::{TestHarness, request};

    fn config(api_url: &str) -> MapConfig {
        MapConfig::from_pairs([(API_URL_KEY, api_url)])
    }

    fn kit(api_url: &str) -> TestHarness {
        TestHarness::with_ports(vec![Box::new(Seals::new())], |ports| {
            ports.config = Arc::new(config(api_url));
        })
    }

    #[test]
    fn the_module_is_named_seals() {
        assert_eq!(Seals::new().name(), "seals");
    }

    #[pollster::test]
    async fn the_well_known_document_carries_the_configured_api_and_a_cache_directive() {
        let response = request(
            &kit("https://api.sealb.in/").router,
            Method::GET,
            "/.well-known/sealbin",
            None,
        )
        .await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(
            response
                .headers
                .get(header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("public, max-age=3600")
        );
        assert_eq!(
            response.json(),
            serde_json::json!({
                "api": "https://api.sealb.in",
                "formats": [1],
                "limits": {"max_inline_bytes": 1_048_576, "max_part_bytes": 52_428_800},
            })
        );
    }

    #[test]
    fn sealbin_api_url_is_validated_and_the_error_names_the_key() {
        let missing = Seals::new()
            .validate_config(&MapConfig::default())
            .expect_err("missing SEALBIN_API_URL is rejected");
        assert!(missing.to_string().contains(API_URL_KEY), "{missing}");

        for bad in [
            "",
            "not a url",
            "ftp://api.sealb.in",
            "https://",
            "https://user:pass@api.sealb.in",
            "https://api.sealb.in/?a=1",
            "https://api.sealb.in/#frag",
            "http://api.sealb.in",
        ] {
            let err = Seals::new()
                .validate_config(&config(bad))
                .expect_err("invalid SEALBIN_API_URL is rejected");
            assert!(err.to_string().contains(API_URL_KEY), "{bad}: {err}");
        }

        // `http://` is accepted only on a loopback host.
        for good in [
            "http://localhost:8787",
            "http://127.0.0.1:8787",
            "http://127.5.5.5",
            "http://[::1]:8787",
            "https://api.sealb.in",
        ] {
            Seals::new()
                .validate_config(&config(good))
                .unwrap_or_else(|err| panic!("{good} should be accepted: {err}"));
        }
    }

    #[pollster::test]
    async fn the_empty_router_answers_404() {
        let response = request(
            &kit("https://api.sealb.in").router,
            Method::GET,
            "/v1/seals/x",
            None,
        )
        .await;
        assert_eq!(response.status, StatusCode::NOT_FOUND);
    }
}
