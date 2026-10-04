//! The account/agent store (D11–D13) that both modules route to: the harness
//! `ApiKeys` table, the `accounts` and `agents` rows that own it, and the rules
//! tying them together. Everything here is crate-internal.

use std::sync::Arc;

use cratefield_core::axum::http::{HeaderMap, StatusCode};
use cratefield_core::{
    ApiKeyError, ApiKeyMode, ApiKeys, Clock, Database, DbError, ModuleContext, Problem, ProblemDef,
    RandomBytes, RandomError, Row, SLUGS, Statement, bearer_token,
};
use sea_query::Value as SeaValue;
use serde::Deserialize;
use serde_json::{Value as Json, json};
use time::format_description::well_known::Rfc3339;

/// The `ApiKeys` namespace every sealbin key is issued under (D12).
pub(crate) const NAMESPACE: &str = "sb";

/// The harness key table (D12). The `agents` module owns it in `tables()`.
pub(crate) const API_KEY_TABLE: &str = "api_keys";

/// May create a seal (D11).
pub(crate) const SCOPE_SEALS_WRITE: &str = "seals:write";

/// May read seals with an open's attributes attached (D11).
pub(crate) const SCOPE_SEALS_READ_ATTRIBUTED: &str = "seals:read-attributed";

/// May create, rename and revoke the account's other agents (D11).
pub(crate) const SCOPE_AGENTS_MANAGE: &str = "agents:manage";

/// May read the account's audit log (D11).
pub(crate) const SCOPE_AUDIT_READ: &str = "audit:read";

/// Every scope a key may be issued.
pub(crate) const ALL_SCOPES: [&str; 4] = [
    SCOPE_SEALS_WRITE,
    SCOPE_SEALS_READ_ATTRIBUTED,
    SCOPE_AGENTS_MANAGE,
    SCOPE_AUDIT_READ,
];

/// Scopes a key gets when the caller names none: what sealing needs, and
/// nothing administrative (D11).
pub(crate) const DEFAULT_SCOPES: [&str; 2] = [SCOPE_SEALS_WRITE, SCOPE_SEALS_READ_ATTRIBUTED];

/// Kinds an agent may carry (D12). Advisory: the kind names the caller's
/// intent, never a permission.
pub(crate) const KINDS: [&str; 3] = ["machine", "agent", "ci"];

/// Plans an account may be on (D13). What each *allows* lives behind
/// [`PlanGate`], so a self-hosted deployment raises the ceilings.
pub(crate) const PLANS: [&str; 3] = ["free", "pro", "team"];

/// The plan a new account starts on (D13).
pub(crate) const DEFAULT_PLAN: &str = "free";

/// Longest agent name accepted, in characters (D12).
pub(crate) const MAX_NAME_CHARS: usize = 64;

/// 403: the account's plan does not allow another active agent (D13).
pub const AGENT_LIMIT: ProblemDef = ProblemDef {
    slug: "plan/agent-limit",
    status: StatusCode::FORBIDDEN,
    title: "Plan agent limit reached",
    description: "The account already holds as many active agents as its plan allows.",
};

/// 403: the key verified, but its account is disabled.
pub const ACCOUNT_DISABLED: ProblemDef = ProblemDef {
    slug: "account/disabled",
    status: StatusCode::FORBIDDEN,
    title: "Account disabled",
    description: "The API key is valid but the account it speaks for is disabled.",
};

/// 409: an active agent of the account already answers to that name.
pub const NAME_TAKEN: ProblemDef = ProblemDef {
    slug: "agents/name-taken",
    status: StatusCode::CONFLICT,
    title: "Agent name already in use",
    description: "An active agent of this account already has that name.",
};

/// The OS entropy source key material is minted from — `getrandom`, which is
/// `crypto.getRandomValues` on wasm.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsRandom;

impl RandomBytes for OsRandom {
    /// Panics on a failed draw: no key is worth minting without entropy, and
    /// `RandomError` has no constructor outside `cratefield-core` (D12).
    fn fill(&self, dest: &mut [u8]) -> Result<(), RandomError> {
        getrandom::fill(dest).unwrap_or_else(|err| panic!("entropy source failed: {err}"));
        Ok(())
    }
}

/// What a plan allows (D13). The default is [`AllowAll`]; a hosted deployment
/// swaps in the ceilings with [`Agents::with_plan_gate`](crate::Agents::with_plan_gate).
pub trait PlanGate: Send + Sync {
    /// The plan's ceiling for the `/me` view, or `None` for unlimited.
    fn agent_limit(&self, plan: &str) -> Option<u64>;

    /// Whether `plan` may hold one more active agent, given `active_agents`;
    /// the default refuses at [`agent_limit`](Self::agent_limit).
    ///
    /// # Errors
    ///
    /// [`AGENT_LIMIT`] when the plan is full. A gate backed by a store of its
    /// own may raise any [`Problem`]; it is passed through unchanged.
    fn check_new_agent(&self, plan: &str, active_agents: u64) -> Result<(), Problem> {
        match self.agent_limit(plan) {
            Some(limit) if active_agents >= limit => Err(Problem::new(&AGENT_LIMIT)),
            _ => Ok(()),
        }
    }
}

/// Every plan is unlimited: the self-hosted default (D13).
#[derive(Debug, Clone, Copy, Default)]
pub struct AllowAll;

impl PlanGate for AllowAll {
    fn agent_limit(&self, _plan: &str) -> Option<u64> {
        None
    }
}

/// Revokes an account's seals on erasure (D14). The seal store lands in #9.
pub trait SealRevoker: Send + Sync {
    /// Revokes every seal `account` owns; erasure is retried by the operator,
    /// not aborted by one seal.
    fn revoke_account(&self, account: &str);
}

/// Revokes nothing, and says so: the default until #9 lands the seal store.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoSealRevoker;

impl SealRevoker for NoSealRevoker {
    fn revoke_account(&self, _account: &str) {}
}

/// The columns of an `accounts` row, in the order [`Account::from_row`] reads.
const ACCOUNT_COLUMNS: &str = "id, plan, email, status, created_at";

/// One `accounts` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Account {
    pub(crate) id: String,
    pub(crate) plan: String,
    pub(crate) email: Option<String>,
    pub(crate) status: String,
    pub(crate) created_at: String,
}

impl Account {
    /// The admin and `/me` view of the row; carries no secret.
    pub(crate) fn json(&self) -> Json {
        json!({
            "id": self.id,
            "plan": self.plan,
            "email": self.email,
            "status": self.status,
            "created_at": self.created_at,
        })
    }

    fn from_row(row: &Row) -> Result<Self, Problem> {
        Ok(Self {
            id: column(row, "id")?,
            plan: column(row, "plan")?,
            email: optional(row, "email"),
            status: column(row, "status")?,
            created_at: column(row, "created_at")?,
        })
    }
}

/// One `agents` row, joined to its key's scopes and last use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Agent {
    pub(crate) prefix: String,
    pub(crate) name: String,
    pub(crate) kind: Option<String>,
    pub(crate) scopes: Vec<String>,
    pub(crate) created_at: String,
    pub(crate) last_used_at: Option<String>,
    pub(crate) revoked_at: Option<String>,
}

impl Agent {
    /// The list view (D10). No column here can disclose a token: only the hash
    /// of one was ever stored, and it is not selected.
    pub(crate) fn json(&self) -> Json {
        json!({
            "prefix": self.prefix,
            "name": self.name,
            "kind": self.kind,
            "scopes": self.scopes,
            "created_at": self.created_at,
            "last_used_at": self.last_used_at,
            "revoked_at": self.revoked_at,
        })
    }

    fn from_row(row: &Row) -> Result<Self, Problem> {
        Ok(Self {
            prefix: column(row, "prefix")?,
            name: column(row, "name")?,
            kind: optional(row, "kind"),
            scopes: scopes_of(row),
            created_at: column(row, "created_at")?,
            last_used_at: optional(row, "last_used_at"),
            revoked_at: optional(row, "revoked_at"),
        })
    }
}

/// A newly minted agent. `token` exists in the one response that carries it,
/// and in no log line: the store keeps only its hash.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct IssuedAgent {
    pub(crate) prefix: String,
    pub(crate) token: String,
    pub(crate) name: String,
}

impl std::fmt::Debug for IssuedAgent {
    /// As `IssuedKey` in cratefield-core: the plaintext token is redacted.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedAgent")
            .field("prefix", &self.prefix)
            .field("name", &self.name)
            .field("token", &"[redacted]")
            .finish()
    }
}

impl IssuedAgent {
    /// The `201` body (D11): the only time the token is shown.
    pub(crate) fn json(&self) -> Json {
        json!({ "prefix": self.prefix, "token": self.token, "name": self.name })
    }
}

/// Who a request's API key speaks for. Public only because
/// [`Directory::resolve_writer`] returns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    pub(crate) account: String,
    pub(crate) prefix: String,
    pub(crate) scopes: Vec<String>,
    pub(crate) mode: ApiKeyMode,
}

impl Caller {
    /// Whether the key carries `scope`; scopes are exact-match strings.
    pub(crate) fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|granted| granted == scope)
    }

    /// The gate for one scope: 403 `api-key-forbidden` when it is missing.
    pub(crate) fn require_scope(&self, scope: &str) -> Result<(), Problem> {
        if self.has_scope(scope) {
            Ok(())
        } else {
            Err(Problem::new(&SLUGS.api_key_forbidden)
                .with_detail(format!("this key lacks the required scope `{scope}`")))
        }
    }
}

/// A `POST` body that mints an agent key (D11, D12).
#[derive(Debug, Deserialize)]
pub(crate) struct NewAgent {
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) kind: Option<String>,
    #[serde(default)]
    pub(crate) scopes: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) mode: Option<String>,
}

/// The validated parts of a [`NewAgent`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AgentSpec {
    pub(crate) name: String,
    pub(crate) kind: Option<String>,
    pub(crate) scopes: Vec<String>,
    pub(crate) mode: ApiKeyMode,
}

impl NewAgent {
    /// Checks and fills the body against the vocabulary above: an absent or
    /// empty `scopes` means [`DEFAULT_SCOPES`], an absent `mode` means live.
    ///
    /// # Errors
    ///
    /// 400 `validation-failed` naming the field that was wrong.
    pub(crate) fn validate(self) -> Result<AgentSpec, Problem> {
        let name = check_name(&self.name)?;
        let kind = match trimmed(self.kind.as_deref()) {
            None => None,
            Some(kind) if KINDS.contains(&kind) => Some(kind.to_owned()),
            Some(other) => return Err(unknown("kind", other, &KINDS)),
        };
        let mut scopes: Vec<String> = Vec::new();
        for scope in self.scopes.unwrap_or_default() {
            if !ALL_SCOPES.contains(&scope.as_str()) {
                return Err(unknown("scope", &scope, &ALL_SCOPES));
            }
            if !scopes.contains(&scope) {
                scopes.push(scope);
            }
        }
        if scopes.is_empty() {
            scopes = DEFAULT_SCOPES
                .iter()
                .map(|scope| (*scope).to_owned())
                .collect();
        }
        let mode = match trimmed(self.mode.as_deref()) {
            None | Some("live") => ApiKeyMode::Live,
            Some("test") => ApiKeyMode::Test,
            Some(other) => return Err(unknown("mode", other, &["live", "test"])),
        };
        Ok(AgentSpec {
            name,
            kind,
            scopes,
            mode,
        })
    }
}

/// Trims and checks an agent name. Every route that writes one — mint, rename —
/// applies this, so a name that cannot be minted cannot be renamed into either.
/// 400 `validation-failed` when it is empty or over [`MAX_NAME_CHARS`].
pub(crate) fn check_name(name: &str) -> Result<String, Problem> {
    let name = name.trim();
    if name.is_empty() {
        return Err(Problem::validation_failed("`name` must not be empty"));
    }
    if name.chars().count() > MAX_NAME_CHARS {
        return Err(Problem::validation_failed(format!(
            "`name` is longer than {MAX_NAME_CHARS} characters"
        )));
    }
    Ok(name.to_owned())
}

/// The store the `accounts` and `agents` modules share: the `ApiKeys` table
/// plus the two tables that own it. Its methods are crate-internal except
/// [`Directory::resolve_writer`], which #9's seal routes call.
pub struct Directory {
    keys: ApiKeys,
    db: Arc<dyn Database>,
    clock: Arc<dyn Clock>,
    plan_gate: Arc<dyn PlanGate>,
    seal_revoker: Arc<dyn SealRevoker>,
}

impl Directory {
    /// A store over the ports, issuing keys under [`NAMESPACE`] and table
    /// [`API_KEY_TABLE`], with `plan_gate` deciding new-agent ceilings and
    /// `seal_revoker` reached by [`Directory::erase_account`].
    pub(crate) fn new(
        db: Arc<dyn Database>,
        clock: Arc<dyn Clock>,
        rng: Arc<dyn RandomBytes>,
        plan_gate: Arc<dyn PlanGate>,
        seal_revoker: Arc<dyn SealRevoker>,
    ) -> Self {
        let keys = ApiKeys::new(Arc::clone(&db), Arc::clone(&clock), rng, API_KEY_TABLE);
        Self {
            keys,
            db,
            clock,
            plan_gate,
            seal_revoker,
        }
    }

    /// The store a module's `router(ctx)` builds: the ports this module
    /// requires and OS entropy, under `plan_gate`/`seal_revoker`. Panics only
    /// when `ctx` lacks `Db` or `Clock`, which the harness refuses to compose a
    /// module without — so no request can reach that.
    pub(crate) fn from_ports(
        ctx: &ModuleContext,
        plan_gate: Arc<dyn PlanGate>,
        seal_revoker: Arc<dyn SealRevoker>,
    ) -> Self {
        Self::new(
            ctx.ports.db.clone().expect("`Db` is a required port"),
            ctx.ports.clock.clone().expect("`Clock` is a required port"),
            Arc::new(OsRandom),
            plan_gate,
            seal_revoker,
        )
    }

    /// Every account, oldest first.
    pub(crate) async fn accounts(&self) -> Result<Vec<Account>, Problem> {
        self.query(
            &format!("SELECT {ACCOUNT_COLUMNS} FROM accounts ORDER BY created_at"),
            vec![],
        )
        .await?
        .rows
        .iter()
        .map(Account::from_row)
        .collect()
    }

    /// Creates an account row for `id`, a `ULID` the caller minted.
    pub(crate) async fn create_account(
        &self,
        id: &str,
        email: Option<&str>,
        plan: &str,
    ) -> Result<Account, Problem> {
        let created_at = stamp(self.clock.as_ref())?;
        self.execute(
            "INSERT INTO accounts (id, created_at, plan, email) VALUES (?, ?, ?, ?)",
            vec![
                id.into(),
                created_at.as_str().into(),
                plan.into(),
                email.into(),
            ],
        )
        .await?;
        Ok(Account {
            id: id.to_owned(),
            plan: plan.to_owned(),
            email: email.map(str::to_owned),
            status: "active".to_owned(),
            created_at,
        })
    }

    /// Sets `id`'s plan, answering the updated row; 404 when there is none.
    pub(crate) async fn set_plan(&self, id: &str, plan: &str) -> Result<Account, Problem> {
        let changed = self
            .execute(
                "UPDATE accounts SET plan = ? WHERE id = ?",
                vec![plan.into(), id.into()],
            )
            .await?;
        if changed == 0 {
            return Err(no_account());
        }
        self.find_account(id).await?.ok_or_else(no_account)
    }

    /// The caller behind `headers`. Every key fault — missing, malformed,
    /// unknown, revoked — is one 401; a disabled account is 403.
    pub(crate) async fn authenticate(&self, headers: &HeaderMap) -> Result<Caller, Problem> {
        let unauthorized = || Problem::new(&SLUGS.api_key_unauthorized);
        let Some(token) = bearer_token(headers) else {
            return Err(unauthorized());
        };
        let Some(principal) = self.keys.verify(token).await.map_err(Problem::from)? else {
            return Err(unauthorized());
        };
        // A key whose account row is gone — an erasure that half-ran — speaks
        // for nobody, exactly as an unknown key does.
        let Some(account) = self.find_account(&principal.subject).await? else {
            return Err(unauthorized());
        };
        if account.status != "active" {
            return Err(Problem::new(&ACCOUNT_DISABLED));
        }
        Ok(Caller {
            account: account.id,
            prefix: principal.prefix,
            scopes: principal.scopes,
            mode: principal.mode,
        })
    }

    /// The `seals:write` caller behind `headers`, for #9's `POST /v1/seals`
    /// (D7): which account and agent a new seal belongs to, and in which mode.
    ///
    /// # Errors
    ///
    /// Everything `Directory::authenticate` raises, and 403 when the key lacks
    /// `seals:write`.
    pub async fn resolve_writer(&self, headers: &HeaderMap) -> Result<Caller, Problem> {
        let caller = self.authenticate(headers).await?;
        caller.require_scope(SCOPE_SEALS_WRITE)?;
        Ok(caller)
    }

    /// Mints a key for `account` and records its agent row, answering the token
    /// once: 404 unknown account, 403 disabled or over limit, 409 name taken.
    pub(crate) async fn issue_agent(
        &self,
        account: &str,
        name: &str,
        kind: Option<&str>,
        scopes: &[String],
        mode: ApiKeyMode,
    ) -> Result<IssuedAgent, Problem> {
        let row = self.find_account(account).await?.ok_or_else(no_account)?;
        if row.status != "active" {
            return Err(Problem::new(&ACCOUNT_DISABLED));
        }
        let active = self.active_agent_count(account).await?;
        // Check-then-insert, not one transaction (ADR 0004): creates racing
        // here can each see room for one and overshoot the ceiling by up to
        // the number of racers. The name's partial unique index is enforced by
        // the insert below; #15 can make the agent limit atomic too.
        self.plan_gate.check_new_agent(&row.plan, active)?;

        let granted: Vec<&str> = scopes.iter().map(String::as_str).collect();
        let issued = self
            .keys
            .issue(NAMESPACE, account, &granted, mode)
            .await
            .map_err(key_error)?;
        let created_at = stamp(self.clock.as_ref())?;
        let inserted = self
            .execute(
                "INSERT INTO agents (prefix, account, name, kind, created_at) \
                 VALUES (?, ?, ?, ?, ?)",
                vec![
                    issued.prefix.as_str().into(),
                    account.into(),
                    name.into(),
                    kind.into(),
                    created_at.as_str().into(),
                ],
            )
            .await;
        if let Err(err) = inserted {
            // The row just written was the only record of the key, so a failed
            // insert — a name the partial unique index now holds, or a store
            // error — must not leave a live credential nobody can see. Revoke
            // it; if even that fails, report the store failure.
            self.keys.revoke(&issued.prefix).await.map_err(key_error)?;
            return Err(conflict(err, &NAME_TAKEN));
        }
        Ok(IssuedAgent {
            prefix: issued.prefix,
            token: issued.token,
            name: name.to_owned(),
        })
    }

    /// `account`'s agents, oldest first, each with its key's scopes and last
    /// use. Revoked agents stay listed: the name they retired is worth seeing.
    pub(crate) async fn list_agents(&self, account: &str) -> Result<Vec<Agent>, Problem> {
        self.query(
            "SELECT a.prefix AS prefix, a.name AS name, a.kind AS kind, \
             a.created_at AS created_at, a.revoked_at AS revoked_at, \
             k.scopes AS scopes, k.last_used_at AS last_used_at \
             FROM agents AS a LEFT JOIN api_keys AS k ON k.prefix = a.prefix \
             WHERE a.account = ? ORDER BY a.created_at",
            vec![account.into()],
        )
        .await?
        .rows
        .iter()
        .map(Agent::from_row)
        .collect()
    }

    /// Confirms `caller` may rename or revoke `prefix`. Ownership is resolved
    /// first — a prefix `caller`'s account does not hold is a 404, whether or
    /// not it exists elsewhere — and only then the scope: the key itself, or
    /// any of the account's with `agents:manage` (D11), else 403.
    pub(crate) async fn authorize_agent(
        &self,
        caller: &Caller,
        prefix: &str,
    ) -> Result<(), Problem> {
        let owned = self
            .query(
                "SELECT prefix FROM agents WHERE prefix = ? AND account = ?",
                vec![prefix.into(), caller.account.as_str().into()],
            )
            .await?;
        if owned.is_empty() {
            return Err(no_agent());
        }
        if prefix == caller.prefix {
            Ok(())
        } else {
            caller.require_scope(SCOPE_AGENTS_MANAGE)
        }
    }

    /// Renames `account`'s agent `prefix`: 404 when the account has no active
    /// agent with that prefix — another account's agent is a 404, never a 403,
    /// because whether it exists is not ours to tell — and 409 when the name is
    /// taken.
    pub(crate) async fn rename_agent(
        &self,
        account: &str,
        prefix: &str,
        name: &str,
    ) -> Result<(), Problem> {
        match self
            .execute(
                "UPDATE agents SET name = ? \
                 WHERE prefix = ? AND account = ? AND revoked_at IS NULL",
                vec![name.into(), prefix.into(), account.into()],
            )
            .await
        {
            Ok(0) => Err(no_agent()),
            Ok(_) => Ok(()),
            Err(err) => Err(conflict(err, &NAME_TAKEN)),
        }
    }

    /// Revokes `account`'s agent `prefix`: the key stops verifying at once and
    /// the row keeps the retired name. Idempotent; 404 when the account has no
    /// such agent.
    pub(crate) async fn revoke_agent(&self, account: &str, prefix: &str) -> Result<(), Problem> {
        // Read the *key's* revoked_at, not the row's: a retry after a revoke
        // that failed must re-attempt the key when it is still live, and only
        // an already-dead key short-circuits.
        let rows = self
            .query(
                "SELECT k.revoked_at AS revoked_at FROM agents AS a \
                 LEFT JOIN api_keys AS k ON k.prefix = a.prefix \
                 WHERE a.prefix = ? AND a.account = ?",
                vec![prefix.into(), account.into()],
            )
            .await?;
        match rows.first() {
            None => return Err(no_agent()),
            Some(row) if optional(row, "revoked_at").is_some() => return Ok(()),
            Some(_) => {}
        }
        // The key goes first, and its failure stops the write: a revoked row
        // whose key still verified would be the worse half-state. An agent
        // whose key row is gone is nothing left to revoke.
        match self.keys.revoke(prefix).await {
            Ok(()) | Err(ApiKeyError::UnknownKey(_)) => {}
            Err(err) => return Err(key_error(err)),
        }
        self.execute(
            "UPDATE agents SET revoked_at = ? \
             WHERE prefix = ? AND account = ? AND revoked_at IS NULL",
            vec![
                stamp(self.clock.as_ref())?.into(),
                prefix.into(),
                account.into(),
            ],
        )
        .await?;
        Ok(())
    }

    /// The `/me` body (D10): the account, its active agents against the plan
    /// ceiling, and the usage map — empty until #15 meters anything.
    pub(crate) async fn view_for(&self, id: &str) -> Result<Json, Problem> {
        let account = self.find_account(id).await?.ok_or_else(no_account)?;
        let active = self.active_agent_count(id).await?;
        let limit = self.plan_gate.agent_limit(&account.plan);
        Ok(json!({
            "id": account.id,
            "plan": account.plan,
            "agents": { "active": active, "limit": limit },
            "usage": {},
        }))
    }

    /// Erases an account: every key revoked and then deleted, its seals revoked
    /// through [`SealRevoker`], then its agents and account rows gone.
    /// Idempotent.
    pub(crate) async fn erase_account(&self, account: &str) -> Result<(), Problem> {
        let rows = self
            .query(
                "SELECT prefix FROM api_keys WHERE subject = ?",
                vec![account.into()],
            )
            .await?;
        // Seals and keys first, in that order: nothing an account owns should
        // keep working the moment its row is gone.
        self.seal_revoker.revoke_account(account);
        for row in &rows.rows {
            if let Some(prefix) = optional(row, "prefix") {
                let _ = self.keys.revoke(&prefix).await;
            }
        }
        for (table, column) in [(API_KEY_TABLE, "subject"), ("agents", "account")] {
            self.execute(
                &format!("DELETE FROM {table} WHERE {column} = ?"),
                vec![account.into()],
            )
            .await?;
        }
        self.execute("DELETE FROM accounts WHERE id = ?", vec![account.into()])
            .await?;
        Ok(())
    }

    /// The account row `id`, when it exists.
    async fn find_account(&self, id: &str) -> Result<Option<Account>, Problem> {
        self.query(
            &format!("SELECT {ACCOUNT_COLUMNS} FROM accounts WHERE id = ?"),
            vec![id.into()],
        )
        .await?
        .first()
        .map(Account::from_row)
        .transpose()
    }

    /// Active agents `account` holds.
    async fn active_agent_count(&self, account: &str) -> Result<u64, Problem> {
        let found = self
            .query(
                "SELECT prefix FROM agents WHERE account = ? AND revoked_at IS NULL",
                vec![account.into()],
            )
            .await?;
        Ok(u64::try_from(found.len()).unwrap_or(u64::MAX))
    }

    /// A parameterised statement, values bound positionally (ADR 0004).
    async fn query(
        &self,
        sql: &str,
        values: Vec<SeaValue>,
    ) -> Result<cratefield_core::Rows, DbError> {
        self.db.query(&Statement::with_values(sql, values)).await
    }

    /// A statement that changes rows, answering how many it touched.
    async fn execute(&self, sql: &str, values: Vec<SeaValue>) -> Result<u64, DbError> {
        self.db.execute(&Statement::with_values(sql, values)).await
    }
}

/// 404 for an account that is not there — one answer for every route.
fn no_account() -> Problem {
    Problem::not_found().with_detail("no such account")
}

/// 404 for an agent the caller's account does not hold.
fn no_agent() -> Problem {
    Problem::not_found().with_detail("no such agent")
}

/// 400 naming an out-of-vocabulary `value` for `field`.
fn unknown(field: &str, value: &str, allowed: &[&str]) -> Problem {
    Problem::validation_failed(format!(
        "unknown {field} `{value}`: expected one of {}",
        allowed.join(", ")
    ))
}

/// A trimmed non-empty string, or `None` for absent and blank alike.
fn trimmed(text: Option<&str>) -> Option<&str> {
    text.map(str::trim).filter(|text| !text.is_empty())
}

/// RFC 3339 UTC for a clock reading — the harness `ApiKeys` writes its own
/// timestamps with, so `ORDER BY created_at` sorts both tables together.
fn stamp(clock: &dyn Clock) -> Result<String, Problem> {
    clock.now().format(&Rfc3339).map_err(|err| {
        Problem::internal().with_detail(format!("clock reading is not RFC 3339: {err}"))
    })
}

/// A NOT NULL text column; absent or NULL is a schema mismatch, never an empty
/// string that would quietly authenticate nobody.
fn column(row: &Row, name: &str) -> Result<String, Problem> {
    optional(row, name)
        .ok_or_else(|| Problem::internal().with_detail(format!("row has no `{name}` column")))
}

/// A nullable text column.
fn optional(row: &Row, name: &str) -> Option<String> {
    row.get::<Option<String>>(name).flatten()
}

/// The space-separated `scopes` column as a list — the `ApiKeys` storage shape.
fn scopes_of(row: &Row) -> Vec<String> {
    optional(row, "scopes")
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_owned)
        .collect()
}

/// `def` when `err` is a uniqueness violation, 500 otherwise. Both engines put
/// the word `unique` in the message, and `DbError`'s display keeps it.
fn conflict(err: DbError, def: &ProblemDef) -> Problem {
    if err.to_string().to_ascii_lowercase().contains("unique") {
        Problem::new(def)
    } else {
        Problem::from(err)
    }
}

/// A key-store failure: 500 with no detail. The only ways to reach it are a
/// namespace or scope bug in this crate, an entropy failure, or a store
/// failure — none of them the caller's to fix, and none worth echoing back.
fn key_error(_err: ApiKeyError) -> Problem {
    Problem::internal()
}

/// Test scaffolding shared by this module's tests and the `accounts` and
/// `agents` route tests: the assembled kit, the request helpers they all need,
/// and the recording doubles.
#[cfg(test)]
pub(crate) mod testkit {
    use super::*;
    use cratefield_core::MapConfig;
    use cratefield_core::axum::http::Method;
    use cratefield_testing::{TestHarness, TestResponse, request_as};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    /// The `ADMIN_TOKEN` the route tests configure (D11). Obviously fake: no
    /// real token ever appears in this file or in a log line.
    pub(crate) const ADMIN: &str = "test-admin-token-0123456789abcdef";

    /// A kit with both modules mounted and `ADMIN_TOKEN` set, so the
    /// `accounts`, `agents` and `api_keys` migrations are applied.
    pub(crate) fn kit() -> TestHarness {
        kit_with(Arc::new(AllowAll), Arc::new(NoSealRevoker))
    }

    /// The same, with a `plan_gate` and `seal_revoker` injected into every
    /// module that consults them, so the same double sees every call.
    pub(crate) fn kit_with(
        plan_gate: Arc<dyn PlanGate>,
        seal_revoker: Arc<dyn SealRevoker>,
    ) -> TestHarness {
        TestHarness::with_ports(
            vec![
                Box::new(
                    crate::Accounts::new()
                        .with_plan_gate(Arc::clone(&plan_gate))
                        .with_seal_revoker(seal_revoker),
                ),
                Box::new(crate::Agents::new().with_plan_gate(plan_gate)),
            ],
            |ports| ports.config = Arc::new(MapConfig::from_pairs([("ADMIN_TOKEN", ADMIN)])),
        )
    }

    /// The four requests the route tests make, each `token` a bearer.
    pub(crate) async fn get(kit: &TestHarness, path: &str, token: &str) -> TestResponse {
        request_as(&kit.router, Method::GET, path, token, None).await
    }

    /// See [`get`].
    pub(crate) async fn post(
        kit: &TestHarness,
        path: &str,
        token: &str,
        body: &str,
    ) -> TestResponse {
        request_as(&kit.router, Method::POST, path, token, Some(body)).await
    }

    /// See [`get`].
    pub(crate) async fn patch(
        kit: &TestHarness,
        path: &str,
        token: &str,
        body: &str,
    ) -> TestResponse {
        request_as(&kit.router, Method::PATCH, path, token, Some(body)).await
    }

    /// See [`get`].
    pub(crate) async fn delete(kit: &TestHarness, path: &str, token: &str) -> TestResponse {
        request_as(&kit.router, Method::DELETE, path, token, None).await
    }

    /// Creates an account through the admin route, returning its id.
    pub(crate) async fn new_account(kit: &TestHarness) -> String {
        let created = post(kit, "/v1/accounts/admin/accounts", ADMIN, "{}").await;
        assert_eq!(
            created.status,
            StatusCode::CREATED,
            "account creation failed: {:?}",
            created.body()
        );
        created.json()["id"]
            .as_str()
            .expect("the response carries an id")
            .to_owned()
    }

    /// Mints an agent for `account` through the admin route, with `scopes`
    /// named (empty asks for [`DEFAULT_SCOPES`]), returning `(prefix, token)`.
    pub(crate) async fn new_agent(
        kit: &TestHarness,
        account: &str,
        name: &str,
        scopes: &[&str],
    ) -> (String, String) {
        let path = format!("/v1/accounts/admin/accounts/{account}/agents");
        let body = json!({ "name": name, "scopes": scopes }).to_string();
        let created = post(kit, &path, ADMIN, &body).await;
        assert_eq!(
            created.status,
            StatusCode::CREATED,
            "agent creation failed: {:?}",
            created.body()
        );
        let issued = created.json();
        let field = |name: &str| {
            issued[name]
                .as_str()
                .expect("the response carries the field")
                .to_owned()
        };
        (field("prefix"), field("token"))
    }

    /// Flips an account's status in place, as an operator would (D11).
    pub(crate) async fn disable(kit: &TestHarness, account: &str) {
        kit.db
            .execute(&Statement::with_values(
                "UPDATE accounts SET status = 'disabled' WHERE id = ?",
                vec![account.into()],
            ))
            .await
            .expect("the status update runs");
    }

    /// The `sb_live_<16 hex>_<64 hex>` shape (D12): lengths, then hex digits.
    pub(crate) fn is_live_token(token: &str) -> bool {
        let Some(rest) = token.strip_prefix("sb_live_") else {
            return false;
        };
        let Some((id, secret)) = rest.split_once('_') else {
            return false;
        };
        let hex = |text: &str, len: usize| {
            text.len() == len && text.bytes().all(|byte| byte.is_ascii_hexdigit())
        };
        hex(id, 16) && hex(secret, 64)
    }

    /// A [`PlanGate`] that counts its calls and can start refusing (D13).
    #[derive(Debug)]
    pub(crate) struct RecordingGate {
        calls: AtomicU64,
        denying: AtomicBool,
        limit: Option<u64>,
    }

    impl RecordingGate {
        /// A gate that allows, reporting `limit` from `/me`.
        pub(crate) fn new(limit: Option<u64>) -> Self {
            Self {
                calls: AtomicU64::new(0),
                denying: AtomicBool::new(false),
                limit,
            }
        }

        /// Refuses every further new agent, as a full plan does; `calls` is how
        /// many times a new agent has been checked against this gate.
        pub(crate) fn deny(&self) {
            self.denying.store(true, Ordering::SeqCst);
        }

        /// See [`RecordingGate::deny`].
        pub(crate) fn calls(&self) -> u64 {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl PlanGate for RecordingGate {
        fn check_new_agent(&self, _plan: &str, _active_agents: u64) -> Result<(), Problem> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.denying.load(Ordering::SeqCst) {
                Err(Problem::new(&AGENT_LIMIT))
            } else {
                Ok(())
            }
        }

        fn agent_limit(&self, _plan: &str) -> Option<u64> {
            self.limit
        }
    }

    /// A [`SealRevoker`] that records the accounts it was asked to erase.
    #[derive(Debug, Default)]
    pub(crate) struct RecordingRevoker {
        pub(crate) accounts: Mutex<Vec<String>>,
    }

    impl SealRevoker for RecordingRevoker {
        fn revoke_account(&self, account: &str) {
            self.accounts
                .lock()
                .expect("the revoker lock is not poisoned")
                .push(account.to_owned());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cratefield_core::Module;
    use cratefield_core::axum::http::HeaderValue;
    use cratefield_core::axum::http::header::AUTHORIZATION;

    /// The `Authorization: Bearer …` headers a request carries. Built by hand
    /// because these tests drive the store directly rather than a route.
    fn bearer(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).expect("a valid header value"),
        );
        headers
    }

    /// A store over `kit`'s database, with the same gate and revoker the
    /// modules were composed with.
    fn store(kit: &cratefield_testing::TestHarness) -> Directory {
        Directory::new(
            kit.db.clone(),
            Arc::new(kit.clock.clone()),
            Arc::new(OsRandom),
            Arc::new(AllowAll),
            Arc::new(NoSealRevoker),
        )
    }

    /// The two schema rules every module is held to: the tables it claims are
    /// exactly the ones its migrations create, and every one of those is
    /// declared as personal data — or declared, explicitly, to hold nobody.
    #[test]
    fn both_modules_declare_their_tables_and_create_only_those() {
        let modules: [Box<dyn Module>; 2] = [
            Box::new(crate::Accounts::new()),
            Box::new(crate::Agents::new()),
        ];
        for module in modules {
            let unlisted = cratefield_core::unlisted_tables(module.as_ref());
            assert!(
                unlisted.is_empty(),
                "{} creates {unlisted:?} outside `tables()`",
                module.name()
            );
            let undeclared = cratefield_core::undeclared_tables(module.as_ref());
            assert!(
                undeclared.is_empty(),
                "{} owns {undeclared:?} with no personal-data declaration",
                module.name()
            );
        }
    }

    /// The checked-in DDL is the harness's own, so the two cannot drift.
    #[test]
    fn the_api_keys_migration_matches_the_harness_ddl() {
        let kit = testkit::kit();
        let keys = ApiKeys::new(
            kit.db.clone(),
            Arc::new(kit.clock.clone()),
            Arc::new(OsRandom),
            API_KEY_TABLE,
        );
        let ddl = keys.create_table_sql();
        let migration = include_str!("../migrations/sqlite/0002_api_keys.sql");
        assert!(
            migration.contains(&ddl),
            "the migration drifted from `ApiKeys::create_table_sql`:\n{ddl}"
        );
    }

    /// The writer a seal route will resolve (D7): `seals:write`, and an account
    /// that is still active.
    #[pollster::test]
    async fn the_writer_resolver_needs_seals_write_and_an_active_account() {
        let kit = testkit::kit();
        let dir = store(&kit);
        let account = dir
            .create_account("01ACCOUNT", Some("owner@example.com"), DEFAULT_PLAN)
            .await
            .expect("the account is created");

        // A key that authenticates but lacks `seals:write` may not write.
        let auditor = dir
            .issue_agent(
                &account.id,
                "auditor",
                None,
                &[SCOPE_AUDIT_READ.to_owned()],
                ApiKeyMode::Live,
            )
            .await
            .expect("the key is issued");
        let refused = dir
            .resolve_writer(&bearer(&auditor.token))
            .await
            .expect_err("a key without `seals:write` cannot write");
        assert_eq!(refused.status, StatusCode::FORBIDDEN);
        assert_eq!(refused.slug, SLUGS.api_key_forbidden.slug);

        let writer = dir
            .issue_agent(
                &account.id,
                "laptop",
                Some("machine"),
                &[SCOPE_SEALS_WRITE.to_owned()],
                ApiKeyMode::Live,
            )
            .await
            .expect("the key is issued");
        let resolved = dir
            .resolve_writer(&bearer(&writer.token))
            .await
            .expect("a `seals:write` key writes");
        assert_eq!(resolved.account, account.id);
        assert_eq!(resolved.prefix, writer.prefix);
        assert_eq!(resolved.mode, ApiKeyMode::Live);

        // Disabling the account refuses the writer even though the key and its
        // scope are intact (D11).
        testkit::disable(&kit, &account.id).await;
        let disabled = dir
            .resolve_writer(&bearer(&writer.token))
            .await
            .expect_err("a disabled account cannot write");
        assert_eq!(disabled.status, StatusCode::FORBIDDEN);
        assert_eq!(disabled.slug, "account/disabled");
    }
}
