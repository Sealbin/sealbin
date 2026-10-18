//! The `billing` module (D10, #16): subscriptions, customer portal,
//! webhooks, downgrades and disputes through the `Payments` port.
//!
//! Works with Polar (Merchant of Record) and Stripe via Cratefield's
//! `Payments` port. Disabled in self-host mode (routes answer 404 and
//! the module declares no Payments requirement there).

use std::sync::Arc;
use std::time::Duration;

use cratefield_core::axum::body::Bytes;
use cratefield_core::axum::extract::State;
use cratefield_core::axum::http::{HeaderMap, StatusCode};
use cratefield_core::axum::response::{IntoResponse, Response};
use cratefield_core::axum::routing::post;
use cratefield_core::axum::{Json, Router};
use cratefield_core::{
    AnyError, BoxFuture, Clock, Config, ConfigError, DataKind, Database, DbError, Disposition,
    IdGen, Inbox, Mailer, Message, Migrations, Module, ModuleContext, Outbox, Payments,
    PaymentsError, PersonalDataSet, Port, PortalSessionRequest, Problem, RoutePolicy, SqlMigration,
    Statement, SubscriptionCheckoutRequest, WebhookEvent, assert_migration_set,
};
use sea_query::Value as SeaValue;
use sealbin_core::{Plan, on_plan_change};
use serde::Deserialize;
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::directory::{AllowAll, Directory, NoSealRevoker, PlanGate, SealRevoker};

const MIGRATIONS: [SqlMigration; 1] = [SqlMigration::new(
    "0001",
    "billing",
    include_str!("../../migrations/sqlite/0001_billing.sql"),
)];

const _: () = assert_migration_set(&MIGRATIONS);

const PERSONAL_DATA: [PersonalDataSet; 1] = [PersonalDataSet {
    table: "billing_customers",
    subject: "account_id",
    kind: DataKind::Financial,
    disposition: Disposition::Erase,
    description: "Billing customer identifiers, subscription ids, and status; erasing an account removes billing records.",
    redacted: &[],
    subject_via: None,
}];

/// The sender address for billing notification emails (D14, #16).
pub const BILLING_SENDER: &str = "no-reply@send.sealb.in";

/// The grace period for past-due subscriptions before dropping to Free (7 days, #16).
pub const PAST_DUE_GRACE_SECS: i64 = 7 * 24 * 3600;

/// The `billing` module. Compose with [`Billing::new`] for hosted mode,
/// or [`Billing::self_host`] for self-hosted mode.
pub struct Billing {
    self_host: bool,
    plan_gate: Arc<dyn PlanGate>,
    seal_revoker: Arc<dyn SealRevoker>,
}

impl Billing {
    /// Hosted mode: requires `Payments`, `Db`, `Mailer`, `Clock`, `IdGen`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            self_host: false,
            plan_gate: Arc::new(AllowAll),
            seal_revoker: Arc::new(NoSealRevoker),
        }
    }

    /// Self-host mode: routes answer 404, declares no Payments requirement.
    #[must_use]
    pub fn self_host() -> Self {
        Self {
            self_host: true,
            plan_gate: Arc::new(AllowAll),
            seal_revoker: Arc::new(NoSealRevoker),
        }
    }

    /// Sets self-host mode.
    #[must_use]
    pub fn with_self_host(mut self, self_host: bool) -> Self {
        self.self_host = self_host;
        self
    }

    /// Injects `plan_gate`.
    #[must_use]
    pub fn with_plan_gate(mut self, plan_gate: Arc<dyn PlanGate>) -> Self {
        self.plan_gate = plan_gate;
        self
    }

    /// Injects `seal_revoker`.
    #[must_use]
    pub fn with_seal_revoker(mut self, seal_revoker: Arc<dyn SealRevoker>) -> Self {
        self.seal_revoker = seal_revoker;
        self
    }

    /// Scheduled maintenance job: drops expired past-due subscriptions to Free
    /// after 7 days grace, and drains the outbox to send queued notification emails.
    ///
    /// # Errors
    ///
    /// Returns [`AnyError`] if database queries, batch commits, or outbox operations fail.
    pub async fn run_scheduled_job(
        db: Arc<dyn Database>,
        clock: Arc<dyn Clock>,
        id_gen: Arc<dyn IdGen>,
        mailer: Option<Arc<dyn Mailer>>,
    ) -> Result<(), AnyError> {
        let now = clock.now();
        let now_str = rfc3339(now);
        let cutoff = now - Duration::from_secs(PAST_DUE_GRACE_SECS as u64);
        let cutoff_str = rfc3339(cutoff);

        let outbox = Outbox::new("billing_outbox");

        // 1. Find all accounts past due longer than 7 days
        let stmts = Statement::with_values(
            "SELECT account_id, plan FROM billing_customers WHERE status = 'past_due' AND updated_at <= ?",
            vec![cutoff_str.into()],
        );
        let rows = db
            .query(&stmts)
            .await
            .map_err(|e| Box::new(e) as AnyError)?;

        for row in rows.rows {
            let account_id: String = match row.get("account_id") {
                Some(SeaValue::String(Some(s))) => *s,
                _ => continue,
            };
            let old_plan_str: String = match row.get("plan") {
                Some(SeaValue::String(Some(s))) => *s,
                _ => "pro".to_owned(),
            };
            let old_plan = Plan::parse(&old_plan_str).unwrap_or(Plan::Pro);

            // Fetch customer email for notice
            let acc_rows = db
                .query(&Statement::with_values(
                    "SELECT email FROM accounts WHERE id = ?",
                    vec![account_id.clone().into()],
                ))
                .await
                .map_err(|e| Box::new(e) as AnyError)?;
            let email = acc_rows.rows.first().and_then(|r| match r.get("email") {
                Some(SeaValue::String(Some(e))) => Some(*e),
                _ => None,
            });

            // Transition to Free: exactly one transition and email per past-due drop
            let mut batch = vec![
                Statement::with_values(
                    "UPDATE billing_customers SET plan = 'free', status = 'past_due_dropped', updated_at = ? WHERE account_id = ? AND status = 'past_due'",
                    vec![now_str.clone().into(), account_id.clone().into()],
                ),
                Statement::with_values(
                    "UPDATE accounts SET plan = 'free' WHERE id = ?",
                    vec![account_id.clone().into()],
                ),
            ];

            if let Some(ref em) = email {
                let outbox_id = id_gen.ulid();
                let payload = json!({
                    "to": em,
                    "subject": "Sealbin: Account downgraded to Free",
                    "text": "Your account has been downgraded to Free after the grace period ended.",
                    "html": "<p>Your account has been downgraded to Free after the grace period ended.</p>"
                }).to_string();
                batch.push(outbox.enqueue_statement(
                    &outbox_id,
                    "downgraded_to_free",
                    &payload,
                    Some(&account_id),
                    &now_str,
                ));
            }

            // Apply plan change effect
            let _ = on_plan_change(old_plan, Plan::Free);
            db.batch_atomic(&batch)
                .await
                .map_err(|e| Box::new(e) as AnyError)?;
        }

        // 2. Drain outbox and send queued emails
        if let Some(mailer_port) = mailer {
            let lease_until = rfc3339(now + Duration::from_secs(300));
            let due = outbox
                .claim_due(db.as_ref(), &now_str, &lease_until, 20)
                .await
                .map_err(|e| Box::new(e) as AnyError)?;
            for record in due {
                if let Ok(data) = serde_json::from_str::<EmailPayload>(&record.payload) {
                    let msg =
                        Message::new(data.to, BILLING_SENDER, data.subject, data.text, data.html);
                    let _ = mailer_port.send(msg).await;
                }
                outbox
                    .complete(db.as_ref(), &record.id)
                    .await
                    .map_err(|e| Box::new(e) as AnyError)?;
            }
        }

        Ok(())
    }
}

impl Default for Billing {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for Billing {
    fn name(&self) -> &'static str {
        "billing"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn requires(&self) -> &'static [Port] {
        if self.self_host {
            &[Port::Db, Port::Clock, Port::IdGen]
        } else {
            &[
                Port::Db,
                Port::Payments,
                Port::Mailer,
                Port::Clock,
                Port::IdGen,
            ]
        }
    }

    fn tables(&self) -> &'static [&'static str] {
        &[
            "billing_customers",
            "billing_inbox",
            "billing_outbox",
            "billing_audit",
        ]
    }

    fn personal_data(&self) -> &'static [PersonalDataSet] {
        &PERSONAL_DATA
    }

    fn migrations(&self) -> Migrations {
        Migrations::sqlite(&MIGRATIONS)
    }

    fn public_writes(&self) -> bool {
        !self.self_host
    }

    fn public_write_policy(&self) -> RoutePolicy {
        RoutePolicy::Signature
    }

    fn validate_config(&self, cfg: &dyn Config) -> Result<(), ConfigError> {
        if self.self_host {
            return Ok(());
        }
        let mut errors = ConfigError::new();
        // Check if price configuration is present for Pro and Team
        let has_pro = cfg.get("POLAR_PRICE_PRO").is_some()
            || cfg.get("POLAR_PRICE_PRO_ANNUAL").is_some()
            || cfg.get("STRIPE_PRICE_PRO").is_some();
        let has_team = cfg.get("POLAR_PRICE_TEAM").is_some()
            || cfg.get("POLAR_PRICE_TEAM_ANNUAL").is_some()
            || cfg.get("STRIPE_PRICE_TEAM").is_some();

        if !has_pro && cfg.get("TEST_MODE").is_none() {
            errors.push("`POLAR_PRICE_PRO` or `STRIPE_PRICE_PRO` is required for billing");
        }
        if !has_team && cfg.get("TEST_MODE").is_none() {
            errors.push("`POLAR_PRICE_TEAM` or `STRIPE_PRICE_TEAM` is required for billing");
        }
        errors.into_result()
    }

    fn router(&self, ctx: ModuleContext) -> Router {
        if self.self_host {
            // In self-host mode, routes answer 404 (acceptance criterion 6)
            return Router::new().fallback(|| async { StatusCode::NOT_FOUND });
        }

        let state = Arc::new(BillingState {
            dir: Directory::from_ports(
                &ctx,
                Arc::clone(&self.plan_gate),
                Arc::clone(&self.seal_revoker),
            ),
            db: ctx.ports.db.clone().expect("`Db` is required"),
            payments: ctx.ports.payments.clone().expect("`Payments` is required"),
            mailer: ctx.ports.mailer.clone(),
            clock: ctx.ports.clock.clone().expect("`Clock` is required"),
            id_gen: ctx.ports.id_gen.clone().expect("`IdGen` is required"),
            config: Arc::clone(&ctx.config),
            inbox: Inbox::new("billing_inbox"),
            outbox: Outbox::new("billing_outbox"),
        });

        Router::new()
            .route("/checkout", post(checkout))
            .route("/portal", post(portal))
            .route("/stripe-webhook", post(webhook))
            .route("/polar-webhook", post(webhook))
            .route("/webhook", post(webhook))
            .with_state(state)
    }

    fn scheduled<'a>(
        &'a self,
        ctx: &'a ModuleContext,
        _reason: &'a str,
    ) -> BoxFuture<'a, Result<(), AnyError>> {
        Box::pin(async move {
            if self.self_host {
                return Ok(());
            }
            let db = ctx.ports.db.clone().expect("`Db` is required");
            let clock = ctx.ports.clock.clone().expect("`Clock` is required");
            let id_gen = ctx.ports.id_gen.clone().expect("`IdGen` is required");
            let mailer = ctx.ports.mailer.clone();
            Self::run_scheduled_job(db, clock, id_gen, mailer).await
        })
    }
}

struct BillingState {
    dir: Directory,
    db: Arc<dyn Database>,
    payments: Arc<dyn Payments>,
    #[allow(dead_code)]
    mailer: Option<Arc<dyn Mailer>>,
    clock: Arc<dyn Clock>,
    id_gen: Arc<dyn IdGen>,
    config: Arc<dyn Config>,
    inbox: Inbox,
    outbox: Outbox,
}

#[derive(Debug, Deserialize)]
struct CheckoutBody {
    plan: String,
    interval: Option<String>,
}

#[derive(Debug, Deserialize)]
struct EmailPayload {
    to: String,
    subject: String,
    text: String,
    html: String,
}

fn rfc3339(dt: OffsetDateTime) -> String {
    dt.format(&Rfc3339).unwrap_or_else(|_| dt.to_string())
}

/// `POST /v1/billing/checkout` (#16)
async fn checkout(
    State(state): State<Arc<BillingState>>,
    headers: HeaderMap,
    Json(body): Json<CheckoutBody>,
) -> Result<Response, Problem> {
    let caller = state.dir.authenticate(&headers).await?;

    let target_plan = Plan::parse(&body.plan)
        .ok_or_else(|| Problem::validation_failed(format!("unrecognized plan `{}`", body.plan)))?;

    if target_plan != Plan::Pro && target_plan != Plan::Team {
        return Err(Problem::validation_failed(
            "checkout is only available for `pro` and `team` plans",
        ));
    }

    // Read configured price: annual is default per Polar MoR decision (2026-10-03)
    let is_monthly = body
        .interval
        .as_deref()
        .is_some_and(|i| i.eq_ignore_ascii_case("month") || i.eq_ignore_ascii_case("monthly"));

    let price_ref =
        resolve_price(state.config.as_ref(), target_plan, is_monthly).ok_or_else(|| {
            Problem::internal().with_detail(format!(
                "price for plan `{}` is not configured",
                target_plan.as_str()
            ))
        })?;

    // Lookup existing customer_ref if known
    let customer_ref = get_customer_ref(state.db.as_ref(), &caller.account)
        .await
        .map_err(|e| Problem::internal().with_detail(format!("failed querying customer: {e}")))?;

    // Lookup account email
    let account = state.dir.find_account(&caller.account).await?;
    let customer_email = account.and_then(|a| a.email);

    let now = state.clock.now();
    let day = now.date();
    let idempotency_key = format!("{}:{}:{}", caller.account, target_plan.as_str(), day);

    let public_url = state
        .config
        .get("SEALBIN_PUBLIC_URL")
        .unwrap_or_else(|| "https://sealb.in".to_owned());
    let account_url = format!("{public_url}/account");

    let mut metadata = std::collections::BTreeMap::new();
    metadata.insert("account_id".to_owned(), caller.account.clone());
    metadata.insert("plan".to_owned(), target_plan.as_str().to_owned());

    let req = SubscriptionCheckoutRequest {
        customer_ref,
        customer_email,
        price_ref,
        trial_days: None,
        success_url: account_url.clone(),
        cancel_url: account_url,
        metadata,
        idempotency_key,
    };

    let session = state
        .payments
        .create_subscription_checkout(&req)
        .await
        .map_err(|err| match err {
            PaymentsError::NotConfigured => {
                Problem::internal().with_detail("payments not configured")
            }
            PaymentsError::Rejected(msg) => Problem::validation_failed(msg),
            PaymentsError::Transient(msg) => Problem::internal().with_detail(msg),
            _ => Problem::internal().with_detail("checkout creation failed"),
        })?;

    Ok(Json(json!({ "url": session.url })).into_response())
}

/// `POST /v1/billing/portal` (#16)
async fn portal(
    State(state): State<Arc<BillingState>>,
    headers: HeaderMap,
) -> Result<Response, Problem> {
    let caller = state.dir.authenticate(&headers).await?;
    let customer_ref = get_customer_ref(state.db.as_ref(), &caller.account)
        .await
        .map_err(|e| Problem::internal().with_detail(format!("failed querying customer: {e}")))?
        .ok_or_else(|| {
            Problem::not_found().with_detail(format!(
                "no billing customer found for account {}",
                caller.account
            ))
        })?;

    let public_url = state
        .config
        .get("SEALBIN_PUBLIC_URL")
        .unwrap_or_else(|| "https://sealb.in".to_owned());
    let return_url = format!("{public_url}/account");

    let now_str = rfc3339(state.clock.now());
    let idempotency_key = format!("portal:{}:{}", caller.account, now_str);

    let portal_session = state
        .payments
        .create_portal_session(&PortalSessionRequest {
            customer_ref,
            return_url,
            idempotency_key,
        })
        .await
        .map_err(|err| match err {
            PaymentsError::Unsupported(_) => Problem::internal()
                .with_detail("customer portal is not supported by payments adapter"),
            _ => Problem::internal().with_detail("failed to create customer portal session"),
        })?;

    Ok(Json(json!({ "url": portal_session.url })).into_response())
}

/// `POST /v1/billing/stripe-webhook` and `/v1/billing/polar-webhook` (#16)
async fn webhook(
    State(state): State<Arc<BillingState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Problem> {
    // 1. Verify webhook signature
    let event = state
        .payments
        .verify_webhook_request(&headers, &body)
        .await
        .map_err(|err| match err {
            PaymentsError::SignatureInvalid(reason) => {
                Problem::validation_failed(format!("invalid webhook signature: {reason}"))
            }
            _ => Problem::validation_failed("webhook verification failed"),
        })?;

    let now = state.clock.now();
    let now_str = rfc3339(now);

    // 2. Process event with Inbox dedup
    handle_event(state.as_ref(), &event, &now_str).await
}

#[allow(clippy::too_many_lines)]
async fn handle_event(
    state: &BillingState,
    event: &WebhookEvent,
    now_str: &str,
) -> Result<Response, Problem> {
    let kind = event.kind.as_str();

    match kind {
        "checkout.session.completed" | "order.created" | "subscription.created" => {
            let data = &event.data;
            let account_id = extract_account_id(data);
            let customer_id = extract_customer_id(data);
            let sub_id = extract_subscription_id(data);
            let plan_str = extract_plan(data).unwrap_or_else(|| "pro".to_owned());
            let plan = Plan::parse(&plan_str).unwrap_or(Plan::Pro);

            let Some(acc_id) = account_id else {
                return Ok(StatusCode::OK.into_response());
            };

            // Query authoritative subscription if available
            let (status_str, period_end_str) = if let Some(ref sid) = sub_id {
                match state.payments.get_subscription(sid).await {
                    Ok(sub) => (
                        sub.status.as_str().to_owned(),
                        sub.current_period_end.map(rfc3339),
                    ),
                    Err(_) => ("active".to_owned(), None),
                }
            } else {
                ("active".to_owned(), None)
            };

            let email = get_account_email(state.db.as_ref(), &acc_id).await;

            let mut effect = vec![
                Statement::with_values(
                    "INSERT INTO billing_customers (account_id, stripe_customer_id, subscription_id, plan, status, current_period_end, updated_at) \
                     VALUES (?, ?, ?, ?, ?, ?, ?) \
                     ON CONFLICT (account_id) DO UPDATE SET \
                         stripe_customer_id = coalesce(excluded.stripe_customer_id, billing_customers.stripe_customer_id), \
                         subscription_id = coalesce(excluded.subscription_id, billing_customers.subscription_id), \
                         plan = excluded.plan, \
                         status = excluded.status, \
                         current_period_end = coalesce(excluded.current_period_end, billing_customers.current_period_end), \
                         updated_at = excluded.updated_at",
                    vec![
                        acc_id.clone().into(),
                        customer_id.into(),
                        sub_id.into(),
                        plan.as_str().into(),
                        status_str.into(),
                        period_end_str.into(),
                        now_str.into(),
                    ],
                ),
                Statement::with_values(
                    "UPDATE accounts SET plan = ? WHERE id = ?",
                    vec![plan.as_str().into(), acc_id.clone().into()],
                ),
            ];

            if let Some(em) = email {
                let outbox_id = state.id_gen.ulid();
                let payload = json!({
                    "to": em,
                    "subject": format!("Sealbin: Plan changed to {}", plan.as_str()),
                    "text": format!("Your Sealbin plan has been updated to {}.", plan.as_str()),
                    "html": format!("<p>Your Sealbin plan has been updated to <strong>{}</strong>.</p>", plan.as_str())
                }).to_string();
                effect.push(state.outbox.enqueue_statement(
                    &outbox_id,
                    "plan_changed",
                    &payload,
                    Some(&acc_id),
                    now_str,
                ));
            }

            state
                .inbox
                .claim_with(state.db.as_ref(), &event.id, now_str, &effect)
                .await
                .map_err(|e| Problem::internal().with_detail(format!("db error: {e}")))?;

            Ok(StatusCode::OK.into_response())
        }

        "customer.subscription.updated" | "subscription.updated" => {
            let data = &event.data;
            let sub_id = extract_subscription_id(data);

            // Out-of-order protection (#16): read authoritative subscription state from provider
            let (status_str, period_end, sub_plan) = if let Some(ref sid) = sub_id {
                match state.payments.get_subscription(sid).await {
                    Ok(sub) => (
                        sub.status.as_str().to_owned(),
                        sub.current_period_end.map(rfc3339),
                        sub.metadata.get("plan").cloned(),
                    ),
                    Err(_) => (
                        extract_status(data).unwrap_or_else(|| "active".to_owned()),
                        None,
                        extract_plan(data),
                    ),
                }
            } else {
                (
                    extract_status(data).unwrap_or_else(|| "active".to_owned()),
                    None,
                    extract_plan(data),
                )
            };

            let plan_str = sub_plan.unwrap_or_else(|| "pro".to_owned());
            let plan = Plan::parse(&plan_str).unwrap_or(Plan::Pro);

            // Find matching account
            let acc_id = find_account_by_sub_or_customer(
                state.db.as_ref(),
                sub_id.as_deref(),
                extract_customer_id(data).as_deref(),
            )
            .await;
            let Some(acc_id) = acc_id else {
                return Ok(StatusCode::OK.into_response());
            };

            let effect = vec![
                Statement::with_values(
                    "UPDATE billing_customers SET plan = ?, status = ?, current_period_end = coalesce(?, current_period_end), updated_at = ? WHERE account_id = ?",
                    vec![
                        plan.as_str().into(),
                        status_str.into(),
                        period_end.into(),
                        now_str.into(),
                        acc_id.clone().into(),
                    ],
                ),
                Statement::with_values(
                    "UPDATE accounts SET plan = ? WHERE id = ?",
                    vec![plan.as_str().into(), acc_id.into()],
                ),
            ];

            state
                .inbox
                .claim_with(state.db.as_ref(), &event.id, now_str, &effect)
                .await
                .map_err(|e| Problem::internal().with_detail(format!("db error: {e}")))?;

            Ok(StatusCode::OK.into_response())
        }

        "customer.subscription.deleted" | "subscription.canceled" | "subscription.revoked" => {
            let data = &event.data;
            let sub_id = extract_subscription_id(data);
            let cust_id = extract_customer_id(data);

            let acc_id = find_account_by_sub_or_customer(
                state.db.as_ref(),
                sub_id.as_deref(),
                cust_id.as_deref(),
            )
            .await;
            let Some(acc_id) = acc_id else {
                return Ok(StatusCode::OK.into_response());
            };

            let email = get_account_email(state.db.as_ref(), &acc_id).await;

            let mut effect = vec![
                Statement::with_values(
                    "UPDATE billing_customers SET plan = 'free', status = 'canceled', updated_at = ? WHERE account_id = ?",
                    vec![now_str.into(), acc_id.clone().into()],
                ),
                Statement::with_values(
                    "UPDATE accounts SET plan = 'free' WHERE id = ?",
                    vec![acc_id.clone().into()],
                ),
            ];

            if let Some(em) = email {
                let outbox_id = state.id_gen.ulid();
                let payload = json!({
                    "to": em,
                    "subject": "Sealbin: Plan downgraded to Free",
                    "text": "Your subscription has ended and your account has returned to Free.",
                    "html": "<p>Your subscription has ended and your account has returned to <strong>Free</strong>.</p>"
                }).to_string();
                effect.push(state.outbox.enqueue_statement(
                    &outbox_id,
                    "downgraded_to_free",
                    &payload,
                    Some(&acc_id),
                    now_str,
                ));
            }

            let _ = on_plan_change(Plan::Pro, Plan::Free);

            state
                .inbox
                .claim_with(state.db.as_ref(), &event.id, now_str, &effect)
                .await
                .map_err(|e| Problem::internal().with_detail(format!("db error: {e}")))?;

            Ok(StatusCode::OK.into_response())
        }

        "invoice.payment_failed" => {
            let data = &event.data;
            let sub_id = extract_subscription_id(data);
            let cust_id = extract_customer_id(data);

            let acc_id = find_account_by_sub_or_customer(
                state.db.as_ref(),
                sub_id.as_deref(),
                cust_id.as_deref(),
            )
            .await;
            let Some(acc_id) = acc_id else {
                return Ok(StatusCode::OK.into_response());
            };

            let email = get_account_email(state.db.as_ref(), &acc_id).await;

            let mut effect = vec![Statement::with_values(
                "UPDATE billing_customers SET status = 'past_due', updated_at = ? WHERE account_id = ?",
                vec![now_str.into(), acc_id.clone().into()],
            )];

            if let Some(em) = email {
                let outbox_id = state.id_gen.ulid();
                let payload = json!({
                    "to": em,
                    "subject": "Sealbin: Payment failed",
                    "text": "Your latest payment failed. Please update your payment method to maintain access.",
                    "html": "<p>Your latest payment failed. Please update your payment method to maintain access.</p>"
                }).to_string();
                effect.push(state.outbox.enqueue_statement(
                    &outbox_id,
                    "payment_failed",
                    &payload,
                    Some(&acc_id),
                    now_str,
                ));
            }

            state
                .inbox
                .claim_with(state.db.as_ref(), &event.id, now_str, &effect)
                .await
                .map_err(|e| Problem::internal().with_detail(format!("db error: {e}")))?;

            Ok(StatusCode::OK.into_response())
        }

        "invoice.paid" => {
            let data = &event.data;
            let sub_id = extract_subscription_id(data);
            let cust_id = extract_customer_id(data);

            let acc_id = find_account_by_sub_or_customer(
                state.db.as_ref(),
                sub_id.as_deref(),
                cust_id.as_deref(),
            )
            .await;
            let Some(acc_id) = acc_id else {
                return Ok(StatusCode::OK.into_response());
            };

            let effect = vec![Statement::with_values(
                "UPDATE billing_customers SET status = 'active', updated_at = ? WHERE account_id = ?",
                vec![now_str.into(), acc_id.into()],
            )];

            state
                .inbox
                .claim_with(state.db.as_ref(), &event.id, now_str, &effect)
                .await
                .map_err(|e| Problem::internal().with_detail(format!("db error: {e}")))?;

            Ok(StatusCode::OK.into_response())
        }

        // Disputes & chargebacks (Scope additions per maintainer decision 2026-10-03)
        "customer.dispute.created" | "dispute.created" | "early_warning" => {
            let data = &event.data;
            let cust_id = extract_customer_id(data);
            let acc_id =
                find_account_by_sub_or_customer(state.db.as_ref(), None, cust_id.as_deref()).await;
            let Some(acc_id) = acc_id else {
                return Ok(StatusCode::OK.into_response());
            };

            let audit_id = state.id_gen.ulid();
            let effect = vec![
                Statement::with_values(
                    "UPDATE billing_customers SET status = 'disputed', updated_at = ? WHERE account_id = ?",
                    vec![now_str.into(), acc_id.clone().into()],
                ),
                Statement::with_values(
                    "INSERT INTO billing_audit (id, account_id, event_type, details, created_at) VALUES (?, ?, 'dispute_opened', ?, ?)",
                    vec![
                        audit_id.into(),
                        acc_id.into(),
                        data.to_string().into(),
                        now_str.into(),
                    ],
                ),
            ];

            state
                .inbox
                .claim_with(state.db.as_ref(), &event.id, now_str, &effect)
                .await
                .map_err(|e| Problem::internal().with_detail(format!("db error: {e}")))?;

            Ok(StatusCode::OK.into_response())
        }

        "customer.dispute.closed" | "dispute.closed" => {
            let data = &event.data;
            let status = data.get("status").and_then(Value::as_str).unwrap_or("lost");
            let cust_id = extract_customer_id(data);
            let acc_id =
                find_account_by_sub_or_customer(state.db.as_ref(), None, cust_id.as_deref()).await;
            let Some(acc_id) = acc_id else {
                return Ok(StatusCode::OK.into_response());
            };

            let audit_id = state.id_gen.ulid();
            if status == "won" {
                // Restore account
                let effect = vec![
                    Statement::with_values(
                        "UPDATE billing_customers SET status = 'active', updated_at = ? WHERE account_id = ?",
                        vec![now_str.into(), acc_id.clone().into()],
                    ),
                    Statement::with_values(
                        "INSERT INTO billing_audit (id, account_id, event_type, details, created_at) VALUES (?, ?, 'dispute_won', ?, ?)",
                        vec![
                            audit_id.into(),
                            acc_id.into(),
                            data.to_string().into(),
                            now_str.into(),
                        ],
                    ),
                ];
                state
                    .inbox
                    .claim_with(state.db.as_ref(), &event.id, now_str, &effect)
                    .await
                    .map_err(|e| Problem::internal().with_detail(format!("db error: {e}")))?;
            } else {
                // Lost: downgrade to Free
                let effect = vec![
                    Statement::with_values(
                        "UPDATE billing_customers SET plan = 'free', status = 'dispute_lost', updated_at = ? WHERE account_id = ?",
                        vec![now_str.into(), acc_id.clone().into()],
                    ),
                    Statement::with_values(
                        "UPDATE accounts SET plan = 'free' WHERE id = ?",
                        vec![acc_id.clone().into()],
                    ),
                    Statement::with_values(
                        "INSERT INTO billing_audit (id, account_id, event_type, details, created_at) VALUES (?, ?, 'dispute_lost', ?, ?)",
                        vec![
                            audit_id.into(),
                            acc_id.into(),
                            data.to_string().into(),
                            now_str.into(),
                        ],
                    ),
                ];
                let _ = on_plan_change(Plan::Pro, Plan::Free);
                state
                    .inbox
                    .claim_with(state.db.as_ref(), &event.id, now_str, &effect)
                    .await
                    .map_err(|e| Problem::internal().with_detail(format!("db error: {e}")))?;
            }

            Ok(StatusCode::OK.into_response())
        }

        _ => {
            // Unhandled event kind: claim and acknowledge
            let _ = state
                .inbox
                .claim(state.db.as_ref(), &event.id, now_str)
                .await;
            Ok(StatusCode::OK.into_response())
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers

fn resolve_price(cfg: &dyn Config, plan: Plan, monthly: bool) -> Option<String> {
    match plan {
        Plan::Pro => {
            if monthly {
                cfg.get("POLAR_PRICE_PRO_MONTHLY")
                    .or_else(|| cfg.get("STRIPE_PRICE_PRO_MONTHLY"))
                    .or_else(|| cfg.get("POLAR_PRICE_PRO"))
                    .or_else(|| cfg.get("STRIPE_PRICE_PRO"))
            } else {
                cfg.get("POLAR_PRICE_PRO_ANNUAL")
                    .or_else(|| cfg.get("POLAR_PRICE_PRO"))
                    .or_else(|| cfg.get("STRIPE_PRICE_PRO_ANNUAL"))
                    .or_else(|| cfg.get("STRIPE_PRICE_PRO"))
            }
        }
        Plan::Team => {
            if monthly {
                cfg.get("POLAR_PRICE_TEAM_MONTHLY")
                    .or_else(|| cfg.get("STRIPE_PRICE_TEAM_MONTHLY"))
                    .or_else(|| cfg.get("POLAR_PRICE_TEAM"))
                    .or_else(|| cfg.get("STRIPE_PRICE_TEAM"))
            } else {
                cfg.get("POLAR_PRICE_TEAM_ANNUAL")
                    .or_else(|| cfg.get("POLAR_PRICE_TEAM"))
                    .or_else(|| cfg.get("STRIPE_PRICE_TEAM_ANNUAL"))
                    .or_else(|| cfg.get("STRIPE_PRICE_TEAM"))
            }
        }
        _ => None,
    }
}

async fn get_customer_ref(db: &dyn Database, account_id: &str) -> Result<Option<String>, DbError> {
    let stmts = Statement::with_values(
        "SELECT stripe_customer_id FROM billing_customers WHERE account_id = ?",
        vec![account_id.to_owned().into()],
    );
    let rows = db.query(&stmts).await?;
    let res = rows
        .rows
        .first()
        .and_then(|r| match r.get("stripe_customer_id") {
            Some(SeaValue::String(Some(s))) => Some(*s),
            _ => None,
        });
    Ok(res)
}

async fn get_account_email(db: &dyn Database, account_id: &str) -> Option<String> {
    let rows = db
        .query(&Statement::with_values(
            "SELECT email FROM accounts WHERE id = ?",
            vec![account_id.to_owned().into()],
        ))
        .await
        .ok()?;
    rows.rows.first().and_then(|r| match r.get("email") {
        Some(SeaValue::String(Some(e))) => Some(*e),
        _ => None,
    })
}

async fn find_account_by_sub_or_customer(
    db: &dyn Database,
    subscription_id: Option<&str>,
    customer_id: Option<&str>,
) -> Option<String> {
    if let Some(sub_id) = subscription_id {
        let rows = db
            .query(&Statement::with_values(
                "SELECT account_id FROM billing_customers WHERE subscription_id = ?",
                vec![sub_id.to_owned().into()],
            ))
            .await
            .ok()?;
        if let Some(acc) = rows.rows.first().and_then(|r| match r.get("account_id") {
            Some(SeaValue::String(Some(s))) => Some(*s),
            _ => None,
        }) {
            return Some(acc);
        }
    }

    if let Some(cust_id) = customer_id {
        let rows = db
            .query(&Statement::with_values(
                "SELECT account_id FROM billing_customers WHERE stripe_customer_id = ?",
                vec![cust_id.to_owned().into()],
            ))
            .await
            .ok()?;
        if let Some(acc) = rows.rows.first().and_then(|r| match r.get("account_id") {
            Some(SeaValue::String(Some(s))) => Some(*s),
            _ => None,
        }) {
            return Some(acc);
        }
    }
    None
}

fn extract_account_id(data: &Value) -> Option<String> {
    data.get("metadata")
        .and_then(|m| m.get("account_id"))
        .and_then(Value::as_str)
        .or_else(|| data.get("client_reference_id").and_then(Value::as_str))
        .map(str::to_owned)
}

fn extract_customer_id(data: &Value) -> Option<String> {
    data.get("customer")
        .and_then(Value::as_str)
        .or_else(|| data.get("customer_id").and_then(Value::as_str))
        .map(str::to_owned)
}

fn extract_subscription_id(data: &Value) -> Option<String> {
    data.get("subscription")
        .and_then(Value::as_str)
        .or_else(|| data.get("subscription_id").and_then(Value::as_str))
        .or_else(|| {
            if data.get("object").and_then(Value::as_str) == Some("subscription") {
                data.get("id").and_then(Value::as_str)
            } else {
                None
            }
        })
        .map(str::to_owned)
}

fn extract_plan(data: &Value) -> Option<String> {
    data.get("metadata")
        .and_then(|m| m.get("plan"))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn extract_status(data: &Value) -> Option<String> {
    data.get("status")
        .and_then(Value::as_str)
        .map(str::to_owned)
}

#[cfg(test)]
mod tests;
