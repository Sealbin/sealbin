//! The `agents` module (D10, D12): an account's keys — listed, minted, renamed
//! and revoked.
//!
//! It owns the `agents` rows and the harness `api_keys` table; every rule about
//! them lives in `crate::directory`.

use std::sync::Arc;

use cratefield_core::axum::extract::{Path, State};
use cratefield_core::axum::http::{HeaderMap, StatusCode};
use cratefield_core::axum::response::{IntoResponse, Response};
use cratefield_core::axum::routing::{get, patch};
use cratefield_core::axum::{Json, Router};
use cratefield_core::{
    Config, ConfigError, DataKind, Disposition, Migrations, Module, ModuleContext, PersonalDataSet,
    Port, Problem, SqlMigration, assert_migration_set,
};
use serde::Deserialize;
use serde_json::json;

use crate::directory::{
    AllowAll, Directory, NewAgent, NoSealRevoker, PlanGate, SCOPE_AGENTS_MANAGE, check_name,
};

const MIGRATIONS: [SqlMigration; 2] = [
    SqlMigration::new(
        "0001",
        "agents",
        include_str!("../../migrations/sqlite/0001_agents.sql"),
    ),
    SqlMigration::new(
        "0002",
        "api_keys",
        include_str!("../../migrations/sqlite/0002_api_keys.sql"),
    ),
];

const _: () = assert_migration_set(&MIGRATIONS);

/// Who is personal data here (D12): an agent row is a key a person holds, and
/// the key row identifies the account it speaks for.
const PERSONAL_DATA: [PersonalDataSet; 2] = [
    PersonalDataSet {
        table: "agents",
        subject: "account",
        kind: DataKind::Usage,
        disposition: Disposition::Erase,
        description: "The names and kinds of the account's agents, and when each was created and revoked.",
        redacted: &[],
        subject_via: None,
    },
    PersonalDataSet {
        table: "api_keys",
        subject: "subject",
        kind: DataKind::Identifier,
        disposition: Disposition::Erase,
        description: "One row per agent key: the account it speaks for, its scopes and when it was last used. The key itself is stored only as a hash.",
        redacted: &["secret_hash"],
        subject_via: None,
    },
];

/// The `agents` module. Compose it with [`Agents::new`].
pub struct Agents {
    plan_gate: Arc<dyn PlanGate>,
}

impl Agents {
    /// A fresh `agents` module: every plan unlimited (D13).
    #[must_use]
    pub fn new() -> Self {
        Self {
            plan_gate: Arc::new(AllowAll),
        }
    }

    /// Uses `plan_gate` for the D13 new-agent ceilings.
    #[must_use]
    pub fn with_plan_gate(mut self, plan_gate: Arc<dyn PlanGate>) -> Self {
        self.plan_gate = plan_gate;
        self
    }
}

impl Default for Agents {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for Agents {
    fn name(&self) -> &'static str {
        "agents"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn requires(&self) -> &'static [Port] {
        &[Port::Db, Port::Clock]
    }

    fn tables(&self) -> &'static [&'static str] {
        &["agents", "api_keys"]
    }

    fn personal_data(&self) -> &'static [PersonalDataSet] {
        &PERSONAL_DATA
    }

    fn migrations(&self) -> Migrations {
        Migrations::sqlite(&MIGRATIONS)
    }

    /// Nothing to validate: this module reads no deployment config.
    fn validate_config(&self, _cfg: &dyn Config) -> Result<(), ConfigError> {
        Ok(())
    }

    fn router(&self, ctx: ModuleContext) -> Router {
        let state = Arc::new(AgentsState {
            dir: Directory::from_ports(&ctx, Arc::clone(&self.plan_gate), Arc::new(NoSealRevoker)),
        });
        Router::new()
            .route("/", get(list).post(create))
            .route("/{prefix}", patch(rename).delete(revoke))
            .with_state(state)
    }
}

/// The `agents` router's state. Erasure is the `accounts` module's route, so no
/// seal revoker is reachable from here.
struct AgentsState {
    dir: Directory,
}

/// `GET /v1/agents` (D10): the caller's keys. No column here can disclose a
/// token — only a hash of one was ever stored, and it is not selected.
async fn list(
    State(state): State<Arc<AgentsState>>,
    headers: HeaderMap,
) -> Result<Response, Problem> {
    let caller = state.dir.authenticate(&headers).await?;
    let agents: Vec<_> = state
        .dir
        .list_agents(&caller.account)
        .await?
        .iter()
        .map(crate::directory::Agent::json)
        .collect();
    Ok(Json(json!({ "agents": agents })).into_response())
}

/// `POST /v1/agents` (D11): mints another key for the caller's own account.
/// Needs `agents:manage` — a key with only `seals:write` may seal but not grow
/// the account's authority.
async fn create(
    State(state): State<Arc<AgentsState>>,
    headers: HeaderMap,
    Json(body): Json<NewAgent>,
) -> Result<Response, Problem> {
    let caller = state.dir.authenticate(&headers).await?;
    caller.require_scope(SCOPE_AGENTS_MANAGE)?;
    let mut spec = body.validate()?;
    // A key cannot mint one in an environment the caller cannot reach: the new
    // key carries the caller's mode, whatever the body asked for (D12).
    spec.mode = caller.mode;
    let issued = state
        .dir
        .issue_agent(
            &caller.account,
            &spec.name,
            spec.kind.as_deref(),
            &spec.scopes,
            spec.mode,
        )
        .await?;
    Ok((StatusCode::CREATED, Json(issued.json())).into_response())
}

/// `PATCH /v1/agents/{prefix}` (D11): renames the caller's own key, or any of
/// the account's when it carries `agents:manage`.
async fn rename(
    State(state): State<Arc<AgentsState>>,
    headers: HeaderMap,
    Path(prefix): Path<String>,
    Json(body): Json<Rename>,
) -> Result<Response, Problem> {
    let caller = state.dir.authenticate(&headers).await?;
    state.dir.authorize_agent(&caller, &prefix).await?;
    let name = check_name(&body.name)?;
    state
        .dir
        .rename_agent(&caller.account, &prefix, &name)
        .await?;
    Ok(Json(json!({ "prefix": prefix, "name": name })).into_response())
}

/// `DELETE /v1/agents/{prefix}` (D11): revokes the caller's own key, or any of
/// the account's with `agents:manage`. Idempotent; the key dies at once.
async fn revoke(
    State(state): State<Arc<AgentsState>>,
    headers: HeaderMap,
    Path(prefix): Path<String>,
) -> Result<Response, Problem> {
    let caller = state.dir.authenticate(&headers).await?;
    state.dir.authorize_agent(&caller, &prefix).await?;
    state.dir.revoke_agent(&caller.account, &prefix).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// The `PATCH /v1/agents/{prefix}` body.
#[derive(Debug, Deserialize)]
struct Rename {
    name: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::testkit::{
        RecordingGate, delete, get, is_live_token, kit, kit_with, new_account, new_agent, patch,
        post,
    };
    use cratefield_core::axum::http::Method;
    use cratefield_testing::request;

    /// The list is a safe view of a key: no token, no hash — and it needs a
    /// key to read at all.
    #[pollster::test]
    async fn the_agent_list_carries_no_token_and_no_hash() {
        let kit = kit();
        let anonymous = request(&kit.router, Method::GET, "/v1/agents", None).await;
        assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);

        let account = new_account(&kit).await;
        let (prefix, token) = new_agent(&kit, &account, "laptop", &[]).await;
        let listed = get(&kit, "/v1/agents", &token).await;
        assert_eq!(listed.status, StatusCode::OK, "{:?}", listed.body());
        let body = String::from_utf8(listed.body().to_vec()).expect("the body is UTF-8 JSON");
        assert!(
            !body.contains("token"),
            "the list leaked a token field: {body}"
        );
        assert!(
            !body.contains("secret"),
            "the list leaked a hash field: {body}"
        );
        assert!(!body.contains(&token), "the list leaked the token itself");
        let listed = listed.json();
        assert_eq!(listed["agents"][0]["prefix"], prefix.as_str());
        assert_eq!(listed["agents"][0]["name"], "laptop");
        assert_eq!(listed["agents"][0]["revoked_at"], serde_json::Value::Null);
    }

    /// Minting a key through the API needs `agents:manage`, and the body's
    /// vocabulary is checked, not quietly granted.
    #[pollster::test]
    async fn creating_an_agent_needs_agents_manage() {
        let kit = kit();
        let account = new_account(&kit).await;
        let (_, plain) = new_agent(&kit, &account, "seal-only", &[]).await;
        let refused = post(&kit, "/v1/agents", &plain, r#"{"name":"escalated"}"#).await;
        assert_eq!(
            refused.status,
            StatusCode::FORBIDDEN,
            "{:?}",
            refused.body()
        );
        assert_eq!(refused.json()["title"], "API key lacks the required scope");

        let (_, manager) = new_agent(&kit, &account, "manager", &["agents:manage"]).await;
        let minted = post(
            &kit,
            "/v1/agents",
            &manager,
            r#"{"name":"ci-runner","kind":"ci","scopes":["seals:write"]}"#,
        )
        .await;
        assert_eq!(minted.status, StatusCode::CREATED, "{:?}", minted.body());
        let issued = minted.json();
        assert_eq!(issued["name"], "ci-runner");
        assert!(is_live_token(issued["token"].as_str().expect("token")));

        let bad = post(
            &kit,
            "/v1/agents",
            &manager,
            r#"{"name":"nope","scopes":["seals:destroy"]}"#,
        )
        .await;
        assert_eq!(bad.status, StatusCode::BAD_REQUEST);
    }

    /// A key may rename and revoke itself with no scope beyond authentication;
    /// a manager may revoke the same key again, and the retired name is free.
    #[pollster::test]
    async fn an_agent_renames_itself_and_a_manager_revokes_it() {
        let kit = kit();
        let account = new_account(&kit).await;
        let (prefix, token) = new_agent(&kit, &account, "laptop", &[]).await;
        let (_, manager) = new_agent(&kit, &account, "manager", &["agents:manage"]).await;
        let path = format!("/v1/agents/{prefix}");

        let renamed = patch(&kit, &path, &token, r#"{"name":"laptop-2"}"#).await;
        assert_eq!(renamed.status, StatusCode::OK, "{:?}", renamed.body());

        let revoked = delete(&kit, &path, &token).await;
        assert_eq!(revoked.status, StatusCode::NO_CONTENT);
        // Once it is gone, a manager can revoke it again: the revoke is
        // idempotent.
        let again = delete(&kit, &path, &manager).await;
        assert_eq!(again.status, StatusCode::NO_CONTENT);

        // The key stops verifying at once, and the retired name stays listed,
        // marked revoked, while the name itself is free for a new agent.
        let dead = get(&kit, "/v1/agents", &token).await;
        assert_eq!(dead.status, StatusCode::UNAUTHORIZED);
        let listed = get(&kit, "/v1/agents", &manager).await;
        let retired = listed.json()["agents"]
            .as_array()
            .expect("an agents array")
            .iter()
            .find(|agent| agent["prefix"] == prefix.as_str())
            .expect("the retired agent is still listed")
            .clone();
        assert_eq!(retired["name"], "laptop-2");
        assert!(retired["revoked_at"].is_string(), "{retired}");
        let reused = post(&kit, "/v1/agents", &manager, r#"{"name":"laptop-2"}"#).await;
        assert_eq!(reused.status, StatusCode::CREATED, "{:?}", reused.body());
    }

    /// Another account's agent is a 404, never a 403: whether it exists is not
    /// ours to tell.
    #[pollster::test]
    async fn another_accounts_agent_is_not_found() {
        let kit = kit();
        let first = new_account(&kit).await;
        let second = new_account(&kit).await;
        let (victim, _) = new_agent(&kit, &first, "laptop", &[]).await;
        let (_, intruder) = new_agent(&kit, &second, "manager", &["agents:manage"]).await;
        let path = format!("/v1/agents/{victim}");

        let renamed = patch(&kit, &path, &intruder, r#"{"name":"stolen"}"#).await;
        assert_eq!(renamed.status, StatusCode::NOT_FOUND);
        let revoked = delete(&kit, &path, &intruder).await;
        assert_eq!(revoked.status, StatusCode::NOT_FOUND);

        // The second account's list shows the second account's key only.
        let listed = get(&kit, "/v1/agents", &intruder).await;
        let agents = listed.json();
        assert_eq!(agents["agents"].as_array().expect("array").len(), 1);
        assert_ne!(agents["agents"][0]["prefix"], victim.as_str());

        // A key of the second account *without* `agents:manage` is a 404 too,
        // not a 403: the scope gate is never reached for a prefix the account
        // does not hold.
        let (_, outsider) = new_agent(&kit, &second, "plain", &[]).await;
        let rejected = patch(&kit, &path, &outsider, r#"{"name":"stolen"}"#).await;
        assert_eq!(
            rejected.status,
            StatusCode::NOT_FOUND,
            "{:?}",
            rejected.body()
        );
        let rejected = delete(&kit, &path, &outsider).await;
        assert_eq!(
            rejected.status,
            StatusCode::NOT_FOUND,
            "{:?}",
            rejected.body()
        );
    }

    /// The plan gate is consulted before a key is minted, and it answers
    /// `/me`'s ceiling without refusing a read (D13).
    #[pollster::test]
    async fn the_plan_gate_refuses_a_new_agent() {
        let gate = Arc::new(RecordingGate::new(Some(0)));
        let plan_gate: Arc<dyn PlanGate> = gate.clone();
        let kit = kit_with(plan_gate, Arc::new(NoSealRevoker));
        let account = new_account(&kit).await;
        let (_, token) = new_agent(&kit, &account, "manager", &["agents:manage"]).await;

        // The account is set up; the plan is now full for the next agent.
        gate.deny();
        let refused = post(&kit, "/v1/agents", &token, r#"{"name":"one-too-many"}"#).await;
        assert_eq!(
            refused.status,
            StatusCode::FORBIDDEN,
            "{:?}",
            refused.body()
        );
        assert_eq!(refused.json()["title"], "Plan agent limit reached");
        assert!(gate.calls() >= 1, "the gate was never consulted");

        let me = get(&kit, "/v1/accounts/me", &token).await;
        assert_eq!(me.status, StatusCode::OK, "{:?}", me.body());
        assert_eq!(me.json()["agents"]["limit"], 0);
    }
}
