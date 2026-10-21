//! The seals routes (D9–D14): create, open, reopen, ack, metadata, delete.

use std::sync::Arc;

use cratefield_core::axum::extract::{Path, State};
use cratefield_core::axum::http::{HeaderMap, StatusCode};
use cratefield_core::axum::response::IntoResponse;
use cratefield_core::axum::routing::{delete, get, post};
use cratefield_core::axum::{Json, Router};
use cratefield_core::{ModuleContext, Problem};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::SEAL_TOO_LARGE;
use crate::directory::Directory;

/// The seals router's state: access to the Directory for auth and database.
pub(crate) struct SealsState {
    dir: Directory,
}

/// Request body for POST /v1/seals (D9): create a new seal.
#[derive(Debug, Deserialize)]
pub struct CreateSealRequest {
    /// The plaintext, which may be up to 1 MiB.
    pub body: String,
    /// Whether the first open burns the seal (default: true).
    #[serde(default = "default_burn")]
    pub burn: bool,
    /// Seconds until the unopened seal expires (60–604800, default: 86400).
    #[serde(default = "default_ttl")]
    pub ttl: u32,
    /// Whether a password is required (always false for anonymous seals).
    #[serde(default)]
    #[allow(dead_code)]
    pub password: bool,
}

fn default_burn() -> bool {
    true
}

fn default_ttl() -> u32 {
    86400 // 24 hours
}

/// Response body for POST /v1/seals (D9).
#[derive(Debug, Serialize)]
pub struct CreateSealResponse {
    /// The seal's unique identifier.
    pub id: String,
    /// Public URL: https://<api-url>/s/<id> (no fragment).
    pub url: String,
    /// When the unopened seal expires (unix milliseconds).
    pub expires_at: i64,
    /// Whether the first open burns the seal.
    pub burn: bool,
    /// Ciphertext size in bytes.
    pub size: u64,
}

/// Request body for POST /v1/seals/{id}/open (D10).
#[derive(Debug, Deserialize)]
pub struct OpenSealRequest {
    /// The 64-hex `read_token`.
    #[allow(dead_code)]
    pub read_token: String,
}

/// Response body for POST /v1/seals/{id}/open (D10).
#[derive(Debug, Serialize)]
#[allow(dead_code)]
pub struct OpenSealResponse {
    /// The ciphertext envelope (v1).
    pub envelope: String,
}

/// Request body for POST /v1/seals/{id}/reopen (D10).
#[derive(Debug, Deserialize)]
pub struct ReopenSealRequest {
    /// The `reopen_token` from the open response's header (64 hex).
    #[allow(dead_code)]
    pub reopen_token: String,
}

/// Request body for POST /v1/seals/{id}/ack (D10).
#[derive(Debug, Deserialize)]
pub struct AckSealRequest {
    /// The `reopen_token` from the open response's header (64 hex).
    #[allow(dead_code)]
    pub reopen_token: String,
}

/// Response body for GET /v1/seals/{id} (D10): seal metadata.
#[derive(Debug, Serialize)]
pub struct SealMetadata {
    /// `sealed` or `gone`.
    pub state: String,
    /// Ciphertext size in bytes.
    pub size: u64,
    /// When the unopened seal expires (unix milliseconds).
    pub expires_at: i64,
    /// Whether the first open burns the seal.
    pub burn: bool,
    /// Whether a password is required.
    pub password: bool,
}

/// Build the seals router with all routes.
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn router(ctx: ModuleContext) -> Router {
    let state = Arc::new(SealsState {
        dir: Directory::from_ports(
            &ctx,
            Arc::new(crate::directory::AllowAll),
            Arc::new(crate::directory::NoSealRevoker),
        ),
    });

    Router::new()
        .route("/", post(create_seal))
        .route("/{id}", get(get_seal_metadata))
        .route("/{id}", delete(delete_seal))
        .route("/{id}/open", post(open_seal))
        .route("/{id}/reopen", post(reopen_seal))
        .route("/{id}/ack", post(ack_seal))
        .with_state(state)
}

/// POST /v1/seals (D9): Create a new seal.
async fn create_seal(
    State(state): State<Arc<SealsState>>,
    headers: HeaderMap,
    Json(req): Json<CreateSealRequest>,
) -> Result<impl IntoResponse, Problem> {
    // Authenticate as seals:write
    let _caller = state.dir.resolve_writer(&headers).await?;

    // Validate TTL range (60s–max 604800s, i.e., 7 days)
    if req.ttl < 60 || req.ttl > 604_800 {
        return Err(Problem::validation_failed(
            "TTL must be between 60 and 604800 seconds",
        ));
    }

    // Validate body size (max 1 MiB)
    if req.body.len() > 1_048_576 {
        return Err(Problem::new(&SEAL_TOO_LARGE));
    }

    // TODO: Generate seal ID, create SealRecord, store in D1, return 201
    // For now, return a placeholder
    let response = CreateSealResponse {
        id: "seal_01".to_string(),
        url: "https://api.sealb.in/s/seal_01".to_string(),
        expires_at: 0,
        burn: req.burn,
        size: req.body.len() as u64,
    };

    Ok((StatusCode::CREATED, Json(response)))
}

/// GET /v1/seals/{id} (D10): Get seal metadata (public, no auth).
async fn get_seal_metadata(
    State(_state): State<Arc<SealsState>>,
    Path(_id): Path<String>,
) -> Result<Json<SealMetadata>, Problem> {
    // TODO: Look up seal in seals_index, return metadata
    Err(Problem::new(&super::SEAL_NOT_FOUND))
}

/// DELETE /v1/seals/{id} (D9): Delete a seal (owner only).
async fn delete_seal(
    State(state): State<Arc<SealsState>>,
    Path(_id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, Problem> {
    // Authenticate as any scope
    let _caller = state.dir.authenticate(&headers).await?;

    // TODO: Verify caller owns the seal, then revoke it
    Ok(StatusCode::NO_CONTENT)
}

/// POST /v1/seals/{id}/open (D10): Open a seal.
async fn open_seal(
    State(_state): State<Arc<SealsState>>,
    Path(_id): Path<String>,
    Json(_req): Json<OpenSealRequest>,
) -> Result<impl IntoResponse, Problem> {
    // TODO: Parse read_token (64 hex), call SealActor::Open, return envelope + reopen token header
    let response = json!({
        "envelope": "v1...",
    });

    Ok((
        StatusCode::OK,
        [(
            "Sealbin-Reopen-Token",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )],
        Json(response),
    ))
}

/// POST /v1/seals/{id}/reopen (D10): Reopen a seal within the window.
async fn reopen_seal(
    State(_state): State<Arc<SealsState>>,
    Path(_id): Path<String>,
    Json(_req): Json<ReopenSealRequest>,
) -> Result<impl IntoResponse, Problem> {
    // TODO: Parse reopen_token, call SealActor::Reopen, return envelope
    let response = json!({
        "envelope": "v1...",
    });

    Ok(Json(response))
}

/// POST /v1/seals/{id}/ack (D10): Acknowledge read, ending the window.
async fn ack_seal(
    State(_state): State<Arc<SealsState>>,
    Path(_id): Path<String>,
    Json(_req): Json<AckSealRequest>,
) -> Result<StatusCode, Problem> {
    // TODO: Parse reopen_token, call SealActor::Ack
    Ok(StatusCode::NO_CONTENT)
}
