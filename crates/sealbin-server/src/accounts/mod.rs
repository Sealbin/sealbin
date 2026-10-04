//! The `accounts` module (D10, D11): the account row, the caller's `/me` view,
//! the admin bootstrap, and the erasure entry point.
//!
//! The rules live in `crate::directory`; this module is the routes over them.

use std::sync::Arc;

use cratefield_core::axum::body::Bytes;
use cratefield_core::axum::extract::{Path, State};
use cratefield_core::axum::http::{HeaderMap, StatusCode};
use cratefield_core::axum::response::{IntoResponse, Response};
use cratefield_core::axum::routing::{delete, get, post};
use cratefield_core::axum::{Json, Router};
use cratefield_core::{
    Config, ConfigError, DataKind, Disposition, IdGen, Migrations, Module, ModuleContext,
    PersonalDataSet, Port, Problem, SqlMigration, assert_migration_set, require_admin,
};
use serde::Deserialize;
use serde_json::json;

use crate::directory::{
    Account, AllowAll, DEFAULT_PLAN, Directory, NewAgent, NoSealRevoker, PLANS, PlanGate,
    SealRevoker,
};

const MIGRATIONS: [SqlMigration; 1] = [SqlMigration::new(
    "0001",
    "accounts",
    include_str!("../../migrations/sqlite/0001_accounts.sql"),
)];

const _: () = assert_migration_set(&MIGRATIONS);

/// What the `accounts` table holds (D11): the id, plan and email of a person's
/// account; erasing one removes the row and disables every key it holds.
const PERSONAL_DATA: [PersonalDataSet; 1] = [PersonalDataSet {
    table: "accounts",
    subject: "id",
    kind: DataKind::Contact,
    disposition: Disposition::Erase,
    description: "The account's id, plan and email address; erasing an account removes the row and disables every key it holds.",
    redacted: &[],
    subject_via: None,
}];

/// The `accounts` module. Compose it with [`Accounts::new`].
pub struct Accounts {
    plan_gate: Arc<dyn PlanGate>,
    seal_revoker: Arc<dyn SealRevoker>,
}

impl Accounts {
    /// A fresh `accounts` module: every plan unlimited (D13) and no seal
    /// revoker, until a deployment injects one.
    #[must_use]
    pub fn new() -> Self {
        Self {
            plan_gate: Arc::new(AllowAll),
            seal_revoker: Arc::new(NoSealRevoker),
        }
    }

    /// Uses `plan_gate` for the D13 new-agent ceilings.
    #[must_use]
    pub fn with_plan_gate(mut self, plan_gate: Arc<dyn PlanGate>) -> Self {
        self.plan_gate = plan_gate;
        self
    }

    /// Uses `seal_revoker` to revoke an erased account's seals.
    #[must_use]
    pub fn with_seal_revoker(mut self, seal_revoker: Arc<dyn SealRevoker>) -> Self {
        self.seal_revoker = seal_revoker;
        self
    }
}

impl Default for Accounts {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for Accounts {
    fn name(&self) -> &'static str {
        "accounts"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn requires(&self) -> &'static [Port] {
        &[Port::Db, Port::Clock, Port::IdGen]
    }

    fn tables(&self) -> &'static [&'static str] {
        &["accounts"]
    }

    fn personal_data(&self) -> &'static [PersonalDataSet] {
        &PERSONAL_DATA
    }

    fn migrations(&self) -> Migrations {
        Migrations::sqlite(&MIGRATIONS)
    }

    /// Nothing to validate: `ADMIN_TOKEN` unset is a legal deployment — every
    /// admin route is simply disabled (D11).
    fn validate_config(&self, _cfg: &dyn Config) -> Result<(), ConfigError> {
        Ok(())
    }

    fn router(&self, ctx: ModuleContext) -> Router {
        let state = Arc::new(AccountsState {
            dir: Directory::from_ports(
                &ctx,
                Arc::clone(&self.plan_gate),
                Arc::clone(&self.seal_revoker),
            ),
            config: Arc::clone(&ctx.config),
            id_gen: ctx
                .ports
                .id_gen
                .clone()
                .expect("`IdGen` is a required port"),
        });
        Router::new()
            .route("/me", get(me))
            .route("/admin/accounts", get(admin_accounts).post(admin_create))
            .route("/admin/accounts/{id}/agents", post(admin_create_agent))
            .route("/admin/accounts/{id}/plan", post(admin_set_plan))
            .route("/admin/accounts/{id}", delete(admin_erase))
            .with_state(state)
    }
}

/// The `accounts` router's state: the store, the config `ADMIN_TOKEN` comes
/// from, and the id generator.
struct AccountsState {
    dir: Directory,
    config: Arc<dyn Config>,
    id_gen: Arc<dyn IdGen>,
}

/// `GET /v1/accounts/me` (D10): the caller's account, its active-agent count
/// and the plan's ceiling. The key's own subject is the account id, so no id
/// appears in the path.
async fn me(
    State(state): State<Arc<AccountsState>>,
    headers: HeaderMap,
) -> Result<Response, Problem> {
    let caller = state.dir.authenticate(&headers).await?;
    Ok(Json(state.dir.view_for(&caller.account).await?).into_response())
}

/// `POST /v1/accounts/admin/accounts` (D11): the bootstrap — the first account
/// exists because an operator with `ADMIN_TOKEN` made it.
async fn admin_create(
    State(state): State<Arc<AccountsState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Problem> {
    require_admin(state.config.as_ref(), &headers)?;
    let body: NewAccount = parse_body(&body)?;
    let plan = body.plan.unwrap_or_else(|| DEFAULT_PLAN.to_owned());
    check_plan(&plan)?;
    let email = body
        .email
        .map(|email| email.trim().to_owned())
        .filter(|email| !email.is_empty());
    let account = state
        .dir
        .create_account(&state.id_gen.ulid(), email.as_deref(), &plan)
        .await?;
    Ok((StatusCode::CREATED, Json(account.json())).into_response())
}

/// `GET /v1/accounts/admin/accounts` (D10): every account, admin only.
async fn admin_accounts(
    State(state): State<Arc<AccountsState>>,
    headers: HeaderMap,
) -> Result<Response, Problem> {
    require_admin(state.config.as_ref(), &headers)?;
    let accounts: Vec<_> = state
        .dir
        .accounts()
        .await?
        .iter()
        .map(Account::json)
        .collect();
    Ok(Json(json!({ "accounts": accounts })).into_response())
}

/// `POST /v1/accounts/admin/accounts/{id}/agents` (D11): mint an agent key for
/// an account on its behalf; the token is shown once, here.
async fn admin_create_agent(
    State(state): State<Arc<AccountsState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, Problem> {
    require_admin(state.config.as_ref(), &headers)?;
    let body: NewAgent = parse_body(&body)?;
    let spec = body.validate()?;
    let issued = state
        .dir
        .issue_agent(
            &id,
            &spec.name,
            spec.kind.as_deref(),
            &spec.scopes,
            spec.mode,
        )
        .await?;
    Ok((StatusCode::CREATED, Json(issued.json())).into_response())
}

/// `POST /v1/accounts/admin/accounts/{id}/plan` (D13): move an account between
/// plans.
async fn admin_set_plan(
    State(state): State<Arc<AccountsState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, Problem> {
    require_admin(state.config.as_ref(), &headers)?;
    let body: SetPlan = parse_body(&body)?;
    check_plan(&body.plan)?;
    let account = state.dir.set_plan(&id, &body.plan).await?;
    Ok(Json(account.json()).into_response())
}

/// `DELETE /v1/accounts/admin/accounts/{id}` (D14): erase an account — every
/// key revoked, its seals revoked, its rows gone.
async fn admin_erase(
    State(state): State<Arc<AccountsState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, Problem> {
    require_admin(state.config.as_ref(), &headers)?;
    state.dir.erase_account(&id).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// The `POST /admin/accounts` body (D11). Both fields are optional: the id is
/// minted and the plan defaults to Free.
#[derive(Debug, Deserialize)]
struct NewAccount {
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    plan: Option<String>,
}

/// The `POST /admin/accounts/{id}/plan` body (D13).
#[derive(Debug, Deserialize)]
struct SetPlan {
    plan: String,
}

/// Reads a JSON body *after* `require_admin` has run. The routes take `Bytes`
/// rather than `Json` so that an unauthenticated caller is refused 401/403
/// before its bytes are parsed — never a 400 that would leak the shape of the
/// body to a caller without the token.
fn parse_body<T: serde::de::DeserializeOwned>(body: &Bytes) -> Result<T, Problem> {
    serde_json::from_slice(body)
        .map_err(|err| Problem::validation_failed(format!("request body is not valid JSON: {err}")))
}

/// Rejects a plan outside [`PLANS`] (D13).
fn check_plan(plan: &str) -> Result<(), Problem> {
    if PLANS.contains(&plan) {
        Ok(())
    } else {
        Err(Problem::validation_failed(format!(
            "unknown plan `{plan}`: expected one of {}",
            PLANS.join(", ")
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::testkit::{
        ADMIN, RecordingRevoker, delete, disable, get, is_live_token, kit, kit_with, new_account,
        new_agent, post,
    };
    use cratefield_core::MapConfig;
    use cratefield_core::Statement;
    use cratefield_core::axum::http::Method;
    use cratefield_testing::{TestHarness, request};

    /// The admin bootstrap end to end: an operator creates an account, sees it
    /// listed, mints a live agent key for it, and that key's `/me` is the
    /// account view.
    #[pollster::test]
    async fn an_admin_bootstraps_an_account_and_mints_a_live_key() {
        let kit = kit();
        let created = post(
            &kit,
            "/v1/accounts/admin/accounts",
            ADMIN,
            r#"{"email":"owner@example.com","plan":"pro"}"#,
        )
        .await;
        assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body());
        let created = created.json();
        assert_eq!(created["plan"], "pro");
        assert_eq!(created["status"], "active");
        assert_eq!(created["email"], "owner@example.com");
        let id = created["id"].as_str().expect("the id is a string");

        let listed = get(&kit, "/v1/accounts/admin/accounts", ADMIN).await;
        assert_eq!(listed.json()["accounts"][0]["id"], id);

        // A plan outside D13's three is refused.
        let bad_plan = post(
            &kit,
            "/v1/accounts/admin/accounts",
            ADMIN,
            r#"{"plan":"enterprise"}"#,
        )
        .await;
        assert_eq!(bad_plan.status, StatusCode::BAD_REQUEST);
        // ...and an operator can move the account between the three it allows.
        let moved = post(
            &kit,
            &format!("/v1/accounts/admin/accounts/{id}/plan"),
            ADMIN,
            r#"{"plan":"team"}"#,
        )
        .await;
        assert_eq!(moved.status, StatusCode::OK, "{:?}", moved.body());
        assert_eq!(moved.json()["plan"], "team");

        // A minted key is `sb_live_…`, and `/me` counts it against the plan
        // ceiling, which the default gate leaves unlimited.
        let account = new_account(&kit).await;
        let (prefix, token) = new_agent(&kit, &account, "laptop", &[]).await;
        assert!(prefix.starts_with("sb_live_"), "{prefix}");
        assert!(is_live_token(&token), "unexpected token shape");
        let me = get(&kit, "/v1/accounts/me", &token).await;
        assert_eq!(me.status, StatusCode::OK);
        let body = me.json();
        assert_eq!(body["id"], account.as_str());
        assert_eq!(body["plan"], DEFAULT_PLAN);
        assert_eq!(body["agents"]["active"], 1);
        assert_eq!(body["agents"]["limit"], serde_json::Value::Null);
        assert_eq!(body["usage"], json!({}));
    }

    /// The admin plane needs `ADMIN_TOKEN`; `/me` needs a key.
    #[pollster::test]
    async fn admin_routes_need_the_admin_token() {
        let kit = kit();
        let wrong = get(&kit, "/v1/accounts/admin/accounts", "not-the-token").await;
        assert_eq!(wrong.status, StatusCode::FORBIDDEN);

        // The token is checked before the body is read: a malformed body from a
        // caller without it is still 403, never 400.
        let malformed = post(&kit, "/v1/accounts/admin/accounts", "not-the-token", "{").await;
        assert_eq!(malformed.status, StatusCode::FORBIDDEN);

        // With `ADMIN_TOKEN` unset the whole admin plane is disabled, and its
        // answer must not reveal that it was never switched on.
        let unset = TestHarness::with_ports(
            vec![Box::new(Accounts::new()), Box::new(crate::Agents::new())],
            |ports| ports.config = Arc::new(MapConfig::default()),
        );
        let disabled = get(&unset, "/v1/accounts/admin/accounts", ADMIN).await;
        assert_eq!(disabled.status, StatusCode::UNAUTHORIZED);

        // No key, no `/me`.
        let anonymous = request(&kit.router, Method::GET, "/v1/accounts/me", None).await;
        assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
    }

    /// A disabled account's valid key is refused with the D11 problem.
    #[pollster::test]
    async fn a_disabled_account_is_refused_at_me() {
        let kit = kit();
        let account = new_account(&kit).await;
        let (_, token) = new_agent(&kit, &account, "laptop", &[]).await;
        disable(&kit, &account).await;

        let response = get(&kit, "/v1/accounts/me", &token).await;
        assert_eq!(response.status, StatusCode::FORBIDDEN);
        assert_eq!(response.json()["title"], "Account disabled");
    }

    /// Erasure kills every key at once, reaches the seal revoker, and leaves no
    /// rows behind.
    #[pollster::test]
    async fn erasing_an_account_kills_every_key_and_reaches_the_seal_revoker() {
        let revoker = Arc::new(RecordingRevoker::default());
        let seal_revoker: Arc<dyn SealRevoker> = revoker.clone();
        let kit = kit_with(Arc::new(AllowAll), seal_revoker);
        let account = new_account(&kit).await;
        let (_, token) = new_agent(&kit, &account, "laptop", &[]).await;

        let path = format!("/v1/accounts/admin/accounts/{account}");
        let erased = delete(&kit, &path, ADMIN).await;
        assert_eq!(erased.status, StatusCode::NO_CONTENT, "{:?}", erased.body());

        // The key was killed, the revoker was told, and no row survived: the
        // declaration is `Erase`, not `Anonymise` (D12).
        let dead = get(&kit, "/v1/accounts/me", &token).await;
        assert_eq!(dead.status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            revoker.accounts.lock().expect("lock").as_slice(),
            [account.as_str()]
        );
        let listed = get(&kit, "/v1/accounts/admin/accounts", ADMIN).await;
        assert_eq!(listed.json()["accounts"], json!([]));
        let keys = kit
            .db
            .query(&Statement::new("SELECT prefix FROM api_keys"))
            .await
            .expect("the key rows read");
        assert!(keys.is_empty(), "erasure left key rows behind");
    }
}
