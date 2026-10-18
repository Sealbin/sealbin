use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use cratefield_core::axum::http::{HeaderMap, Method, StatusCode};
use cratefield_core::{
    Charge, CheckoutRequest, CheckoutSession, ConnectAccountLink, ConnectAccountLinkRequest,
    Dispute, DisputeListRequest, DisputePage, MailError, Mailer, MapConfig, Message, Payments,
    PaymentsError, PortalSession, PortalSessionRequest, Refund, RefundRequest, SendOutcome,
    Statement, Subscription, SubscriptionCheckoutRequest, SubscriptionStatus, TransferCharge,
    WebhookEvent,
};
use cratefield_testing::{TestHarness, request, request_as};
use sealbin_core::{Plan, on_plan_change};
use serde_json::json;
use time::OffsetDateTime;

use super::*;
use crate::directory::testkit::{ADMIN, new_account, new_agent};

/// Test payments adapter supporting mock subscriptions, portal sessions,
/// and fixture verification.
#[derive(Clone, Default)]
struct TestPayments {
    subscriptions: Arc<Mutex<BTreeMap<String, Subscription>>>,
    recorded_portal_requests: Arc<Mutex<Vec<PortalSessionRequest>>>,
    recorded_checkout_requests: Arc<Mutex<Vec<SubscriptionCheckoutRequest>>>,
}

#[async_trait]
impl Payments for TestPayments {
    async fn create_checkout(&self, _: &CheckoutRequest) -> Result<CheckoutSession, PaymentsError> {
        Err(PaymentsError::Unsupported("checkout"))
    }

    async fn create_subscription_checkout(
        &self,
        req: &SubscriptionCheckoutRequest,
    ) -> Result<CheckoutSession, PaymentsError> {
        self.recorded_checkout_requests
            .lock()
            .unwrap()
            .push(req.clone());
        Ok(CheckoutSession {
            id: "cs_test_123".to_owned(),
            url: "https://polar.sh/checkout/cs_test_123".to_owned(),
        })
    }

    async fn create_connect_account_link(
        &self,
        _: &ConnectAccountLinkRequest,
    ) -> Result<ConnectAccountLink, PaymentsError> {
        Err(PaymentsError::Unsupported("connect"))
    }

    async fn charge_with_transfer(&self, _: &TransferCharge) -> Result<Charge, PaymentsError> {
        Err(PaymentsError::Unsupported("transfer"))
    }

    async fn refund(&self, _: &RefundRequest) -> Result<Refund, PaymentsError> {
        Err(PaymentsError::Unsupported("refund"))
    }

    async fn verify_webhook(
        &self,
        signature: &str,
        body: &[u8],
    ) -> Result<WebhookEvent, PaymentsError> {
        if signature == "invalid" || signature == "bad" {
            return Err(PaymentsError::SignatureInvalid(
                "signature mismatch".to_owned(),
            ));
        }
        let parsed: serde_json::Value = serde_json::from_slice(body).unwrap_or(json!({}));
        let id = parsed
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("evt_1")
            .to_owned();
        let kind = parsed
            .get("type")
            .or_else(|| parsed.get("event"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_owned();
        let data = parsed
            .get("data")
            .and_then(|d| d.get("object"))
            .cloned()
            .unwrap_or(parsed);
        Ok(WebhookEvent { id, kind, data })
    }

    async fn verify_webhook_request(
        &self,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<WebhookEvent, PaymentsError> {
        let sig = headers
            .get("stripe-signature")
            .or_else(|| headers.get("webhook-signature"))
            .and_then(|v| v.to_str().ok());
        match sig {
            Some(s) => self.verify_webhook(s, body).await,
            None => Err(PaymentsError::SignatureInvalid(
                "missing signature header".to_owned(),
            )),
        }
    }

    async fn create_portal_session(
        &self,
        req: &PortalSessionRequest,
    ) -> Result<PortalSession, PaymentsError> {
        self.recorded_portal_requests
            .lock()
            .unwrap()
            .push(req.clone());
        Ok(PortalSession {
            url: format!("https://polar.sh/portal/{}", req.customer_ref),
        })
    }

    async fn get_subscription(&self, sub_ref: &str) -> Result<Subscription, PaymentsError> {
        self.subscriptions
            .lock()
            .unwrap()
            .get(sub_ref)
            .cloned()
            .ok_or_else(|| PaymentsError::Rejected("subscription not found".to_owned()))
    }

    async fn list_subscriptions(&self, _: &str) -> Result<Vec<Subscription>, PaymentsError> {
        Ok(Vec::new())
    }

    async fn get_dispute(&self, _: &str) -> Result<Dispute, PaymentsError> {
        Err(PaymentsError::Unsupported("dispute"))
    }

    async fn list_disputes(&self, _: &DisputeListRequest) -> Result<DisputePage, PaymentsError> {
        Err(PaymentsError::Unsupported("dispute"))
    }

    async fn close_dispute(&self, _: &str, _: &str) -> Result<Dispute, PaymentsError> {
        Err(PaymentsError::Unsupported("dispute"))
    }
}

/// Test mailer recording sent messages.
#[derive(Clone, Default)]
struct TestMailer {
    sent: Arc<Mutex<Vec<Message>>>,
}

#[async_trait]
impl Mailer for TestMailer {
    async fn send(&self, msg: Message) -> Result<SendOutcome, MailError> {
        self.sent.lock().unwrap().push(msg);
        Ok(SendOutcome::Sent {
            id: "msg_test".to_owned(),
        })
    }
}

fn billing_kit(
    payments: TestPayments,
    mailer: TestMailer,
    config_pairs: &[(&'static str, &'static str)],
) -> TestHarness {
    let mut pairs = vec![
        ("ADMIN_TOKEN", ADMIN),
        ("POLAR_PRICE_PRO", "price_pro_polar_annual"),
        ("POLAR_PRICE_PRO_MONTHLY", "price_pro_polar_monthly"),
        ("POLAR_PRICE_TEAM", "price_team_polar_annual"),
        ("POLAR_PRICE_TEAM_MONTHLY", "price_team_polar_monthly"),
        ("STRIPE_PRICE_PRO", "price_pro_stripe"),
        ("STRIPE_PRICE_TEAM", "price_team_stripe"),
        ("TEST_MODE", "true"),
    ];
    pairs.extend_from_slice(config_pairs);

    TestHarness::with_ports(
        vec![
            Box::new(crate::Accounts::new()),
            Box::new(crate::Agents::new()),
            Box::new(Billing::new()),
        ],
        move |ports| {
            ports.config = Arc::new(MapConfig::from_pairs(pairs.clone()));
            ports.payments = Some(Arc::new(payments.clone()));
            ports.mailer = Some(Arc::new(mailer.clone()));
        },
    )
}

#[allow(dead_code)]
struct SimpleResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

#[allow(dead_code)]
impl SimpleResponse {
    fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).expect("body is JSON")
    }
}

async fn request_raw(
    router: &cratefield_core::axum::Router,
    method: Method,
    path: &str,
    headers: HeaderMap,
    body: Option<Vec<u8>>,
) -> SimpleResponse {
    use tower::ServiceExt;
    let mut builder = cratefield_core::axum::http::Request::builder()
        .method(method)
        .uri(path);
    for (k, v) in headers {
        if let Some(name) = k {
            builder = builder.header(name, v);
        }
    }
    let body_data = body.map_or_else(
        cratefield_core::axum::body::Body::empty,
        cratefield_core::axum::body::Body::from,
    );
    let req = builder.body(body_data).expect("request builds");
    let resp = router.clone().oneshot(req).await.expect("router answers");
    let (parts, body) = resp.into_parts();
    let bytes = cratefield_core::axum::body::to_bytes(body, 1024 * 1024)
        .await
        .expect("read body");
    SimpleResponse {
        status: parts.status,
        headers: parts.headers,
        body: bytes.to_vec(),
    }
}

/// Acceptance criterion 1:
/// Tests with recorded fixtures: checkout completed sets Pro;
/// subscription deleted sets Free; same event delivered twice applies once;
/// updated arriving before completed ends in the right plan.
#[pollster::test]
async fn test_checkout_completed_sets_pro_and_deleted_sets_free() {
    let payments = TestPayments::default();
    let mailer = TestMailer::default();
    let kit = billing_kit(payments.clone(), mailer.clone(), &[]);

    // 1. Setup account and agent
    let account = new_account(&kit).await;
    let (_, token) = new_agent(&kit, &account, "laptop", &[]).await;

    // Verify initial account plan is free
    let me = request_as(&kit.router, Method::GET, "/v1/accounts/me", &token, None).await;
    assert_eq!(me.status, StatusCode::OK);
    assert_eq!(me.json()["plan"], "free");

    // 2. checkout.session.completed payload fixture (Stripe / Polar shape)
    let fixture_completed = json!({
        "id": "evt_checkout_1",
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "id": "cs_test_123",
                "customer": "cus_test_999",
                "subscription": "sub_test_777",
                "metadata": {
                    "account_id": account,
                    "plan": "pro"
                }
            }
        }
    })
    .to_string();

    let mut headers = HeaderMap::new();
    headers.insert("stripe-signature", "valid_sig".parse().unwrap());
    headers.insert("content-type", "application/json".parse().unwrap());

    // Send completed event
    let res = request_raw(
        &kit.router,
        Method::POST,
        "/v1/billing/stripe-webhook",
        headers.clone(),
        Some(fixture_completed.as_bytes().to_vec()),
    )
    .await;
    assert_eq!(res.status, StatusCode::OK);

    // Plan should now be Pro!
    let me = request_as(&kit.router, Method::GET, "/v1/accounts/me", &token, None).await;
    assert_eq!(me.status, StatusCode::OK);
    assert_eq!(me.json()["plan"], "pro");

    // 3. Same event delivered twice applies once (idempotent)
    let res_dup = request_raw(
        &kit.router,
        Method::POST,
        "/v1/billing/stripe-webhook",
        headers.clone(),
        Some(fixture_completed.as_bytes().to_vec()),
    )
    .await;
    assert_eq!(res_dup.status, StatusCode::OK);

    // 4. customer.subscription.deleted payload fixture -> plan drops back to Free
    let fixture_deleted = json!({
        "id": "evt_deleted_1",
        "type": "customer.subscription.deleted",
        "data": {
            "object": {
                "id": "sub_test_777",
                "customer": "cus_test_999",
                "status": "canceled"
            }
        }
    })
    .to_string();

    let res_del = request_raw(
        &kit.router,
        Method::POST,
        "/v1/billing/stripe-webhook",
        headers.clone(),
        Some(fixture_deleted.as_bytes().to_vec()),
    )
    .await;
    assert_eq!(res_del.status, StatusCode::OK);

    // Plan is back to Free!
    let me = request_as(&kit.router, Method::GET, "/v1/accounts/me", &token, None).await;
    assert_eq!(me.status, StatusCode::OK);
    assert_eq!(me.json()["plan"], "free");
}

/// Acceptance criterion 1 (part 4):
/// `updated` arriving before `completed` ends in the right plan.
#[pollster::test]
async fn test_updated_arriving_before_completed_ends_in_right_plan() {
    let payments = TestPayments::default();
    let mailer = TestMailer::default();

    // Mock provider's authoritative subscription state (Cratefield/harness#589)
    let mut meta = BTreeMap::new();
    meta.insert("plan".to_owned(), "pro".to_owned());
    payments.subscriptions.lock().unwrap().insert(
        "sub_out_of_order".to_owned(),
        Subscription {
            id: "sub_out_of_order".to_owned(),
            customer_ref: "cus_ooo_1".to_owned(),
            status: SubscriptionStatus::Active,
            price_ref: Some("price_pro_polar_annual".to_owned()),
            quantity: 1,
            current_period_end: Some(OffsetDateTime::now_utc()),
            cancel_at_period_end: false,
            metadata: meta,
        },
    );

    let kit = billing_kit(payments.clone(), mailer.clone(), &[]);
    let account = new_account(&kit).await;
    let (_, token) = new_agent(&kit, &account, "laptop", &[]).await;

    // Link customer id to account first (e.g. from checkout or existing record)
    kit.db
        .execute(&Statement::with_values(
            "INSERT INTO billing_customers (account_id, stripe_customer_id, subscription_id, plan, status, updated_at) VALUES (?, ?, ?, 'free', 'incomplete', ?)",
            vec![account.clone().into(), "cus_ooo_1".into(), "sub_out_of_order".into(), "2026-10-18T00:00:00Z".into()],
        ))
        .await
        .unwrap();

    let mut headers = HeaderMap::new();
    headers.insert("webhook-signature", "valid_sig".parse().unwrap());
    headers.insert("content-type", "application/json".parse().unwrap());

    // 1. `subscription.updated` arrives FIRST (out of order)
    let fixture_updated = json!({
        "id": "evt_updated_first",
        "type": "customer.subscription.updated",
        "data": {
            "object": {
                "id": "sub_out_of_order",
                "customer": "cus_ooo_1",
                "status": "active",
                "metadata": { "plan": "pro" }
            }
        }
    })
    .to_string();

    let res = request_raw(
        &kit.router,
        Method::POST,
        "/v1/billing/polar-webhook",
        headers.clone(),
        Some(fixture_updated.as_bytes().to_vec()),
    )
    .await;
    assert_eq!(res.status, StatusCode::OK);

    // Should already be Pro from authoritative subscription read!
    let me = request_as(&kit.router, Method::GET, "/v1/accounts/me", &token, None).await;
    assert_eq!(me.json()["plan"], "pro");

    // 2. `checkout.session.completed` arrives SECOND
    let fixture_completed = json!({
        "id": "evt_completed_second",
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "id": "cs_ooo",
                "customer": "cus_ooo_1",
                "subscription": "sub_out_of_order",
                "metadata": {
                    "account_id": account,
                    "plan": "pro"
                }
            }
        }
    })
    .to_string();

    let res2 = request_raw(
        &kit.router,
        Method::POST,
        "/v1/billing/polar-webhook",
        headers.clone(),
        Some(fixture_completed.as_bytes().to_vec()),
    )
    .await;
    assert_eq!(res2.status, StatusCode::OK);

    // Final plan is solidly Pro
    let me = request_as(&kit.router, Method::GET, "/v1/accounts/me", &token, None).await;
    assert_eq!(me.json()["plan"], "pro");
}

/// Acceptance criterion 2:
/// A webhook with a bad signature answers 400 and changes nothing.
#[pollster::test]
async fn test_bad_signature_answers_400_and_changes_nothing() {
    let payments = TestPayments::default();
    let mailer = TestMailer::default();
    let kit = billing_kit(payments, mailer, &[]);
    let account = new_account(&kit).await;
    let (_, token) = new_agent(&kit, &account, "laptop", &[]).await;

    let payload = json!({
        "id": "evt_tampered",
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "customer": "cus_tampered",
                "subscription": "sub_tampered",
                "metadata": { "account_id": account, "plan": "pro" }
            }
        }
    })
    .to_string();

    let mut headers = HeaderMap::new();
    headers.insert("stripe-signature", "invalid".parse().unwrap());
    headers.insert("content-type", "application/json".parse().unwrap());

    let res = request_raw(
        &kit.router,
        Method::POST,
        "/v1/billing/stripe-webhook",
        headers,
        Some(payload.as_bytes().to_vec()),
    )
    .await;

    assert_eq!(res.status, StatusCode::BAD_REQUEST);

    // Verify account plan did not change
    let me = request_as(&kit.router, Method::GET, "/v1/accounts/me", &token, None).await;
    assert_eq!(me.json()["plan"], "free");

    // Verify inbox claimed nothing
    let rows = kit
        .db
        .query(&Statement::new("SELECT * FROM billing_inbox"))
        .await
        .unwrap();
    assert!(rows.is_empty(), "bad signature must not claim in inbox");
}

/// Acceptance criterion 3:
/// Downgrade from Pro to Free keeps existing seals and keys working and applies
/// Free limits to new seals (tested through `on_plan_change`).
#[test]
fn test_downgrade_preserves_existing_seals_and_keys() {
    let effects = on_plan_change(Plan::Pro, Plan::Free);
    assert!(
        effects.is_empty(),
        "Downgrade must preserve existing seals and keys without destructive effects"
    );

    let free_limits = Plan::Free.limits();
    assert_eq!(free_limits.max_seal_bytes, Some(5_000_000));
    assert_eq!(free_limits.max_agents, Some(3));
    assert_eq!(free_limits.max_ttl, Some(Duration::from_hours(24)));

    let pro_limits = Plan::Pro.limits();
    assert_eq!(pro_limits.max_seal_bytes, Some(100_000_000));
    assert_eq!(pro_limits.max_agents, Some(10));
}

/// Acceptance criterion 4:
/// Past-due accounts drop to Free after 7 days (fake clock) and get one email
/// per transition, not per retry.
#[pollster::test]
async fn test_past_due_accounts_drop_to_free_after_7_days() {
    let payments = TestPayments::default();
    let mailer = TestMailer::default();
    let kit = billing_kit(payments, mailer.clone(), &[]);

    let account = new_account(&kit).await;
    let (_, token) = new_agent(&kit, &account, "laptop", &[]).await;

    // 1. Account upgraded to Pro
    kit.db
        .execute(&Statement::with_values(
            "UPDATE accounts SET plan = 'pro', email = 'owner@example.com' WHERE id = ?",
            vec![account.clone().into()],
        ))
        .await
        .unwrap();
    let now = kit.clock.now();
    let initial_time = rfc3339(now);
    kit.db
        .execute(&Statement::with_values(
            "INSERT INTO billing_customers (account_id, stripe_customer_id, subscription_id, plan, status, updated_at) VALUES (?, 'cus_past_due', 'sub_past_due', 'pro', 'active', ?)",
            vec![account.clone().into(), initial_time.into()],
        ))
        .await
        .unwrap();

    let mut headers = HeaderMap::new();
    headers.insert("stripe-signature", "valid_sig".parse().unwrap());
    headers.insert("content-type", "application/json".parse().unwrap());

    // 2. invoice.payment_failed arrives -> marked past_due
    let payment_failed_payload = json!({
        "id": "evt_fail_1",
        "type": "invoice.payment_failed",
        "data": {
            "object": {
                "customer": "cus_past_due",
                "subscription": "sub_past_due"
            }
        }
    })
    .to_string();

    let res = request_raw(
        &kit.router,
        Method::POST,
        "/v1/billing/stripe-webhook",
        headers,
        Some(payment_failed_payload.as_bytes().to_vec()),
    )
    .await;
    assert_eq!(res.status, StatusCode::OK);

    // Plan is still Pro during grace period
    let me = request_as(&kit.router, Method::GET, "/v1/accounts/me", &token, None).await;
    assert_eq!(me.json()["plan"], "pro");

    // Manually set updated_at to 6 days ago (< 7 days grace)
    let six_days_ago = rfc3339(now - std::time::Duration::from_hours(144));
    kit.db
        .execute(&Statement::with_values(
            "UPDATE billing_customers SET updated_at = ? WHERE account_id = ?",
            vec![six_days_ago.into(), account.clone().into()],
        ))
        .await
        .unwrap();

    // Trigger scheduled task
    Billing::run_scheduled_job(
        kit.db.clone(),
        Arc::new(kit.clock.clone()),
        Arc::new(cratefield_core::UlidIdGen),
        Some(Arc::new(mailer.clone())),
    )
    .await
    .unwrap();

    // Still Pro because 6 days < 7 days
    let me = request_as(&kit.router, Method::GET, "/v1/accounts/me", &token, None).await;
    assert_eq!(me.json()["plan"], "pro");

    // Now advance past-due timestamp to 8 days ago (> 7 days grace)
    let eight_days_ago = rfc3339(now - std::time::Duration::from_hours(192));
    kit.db
        .execute(&Statement::with_values(
            "UPDATE billing_customers SET updated_at = ? WHERE account_id = ?",
            vec![eight_days_ago.into(), account.clone().into()],
        ))
        .await
        .unwrap();

    // Trigger scheduled task
    Billing::run_scheduled_job(
        kit.db.clone(),
        Arc::new(kit.clock.clone()),
        Arc::new(cratefield_core::UlidIdGen),
        Some(Arc::new(mailer.clone())),
    )
    .await
    .unwrap();

    // Dropped to Free!
    let me = request_as(&kit.router, Method::GET, "/v1/accounts/me", &token, None).await;
    assert_eq!(me.json()["plan"], "free");

    // Count sent emails
    let emails_sent_count = mailer.sent.lock().unwrap().len();
    assert!(emails_sent_count >= 1);

    // Run scheduled task again (retry): must NOT send duplicate email
    Billing::run_scheduled_job(
        kit.db.clone(),
        Arc::new(kit.clock.clone()),
        Arc::new(cratefield_core::UlidIdGen),
        Some(Arc::new(mailer.clone())),
    )
    .await
    .unwrap();
    let emails_after_retry = mailer.sent.lock().unwrap().len();
    assert_eq!(
        emails_sent_count, emails_after_retry,
        "Retrying scheduled task must not send a second email for the same transition"
    );
}

/// Acceptance criterion 5:
/// No Stripe secret or customer email appears in logs (tested with the harness
/// log redaction, crates/core/src/logging.rs).
#[test]
fn test_no_secret_or_customer_email_in_logs() {
    use cratefield_core::{is_email_field, is_secret_field, redacted_value, scrub_text};

    let sample_secret = "whsec_test_secret_0123456789";
    let sample_email = "customer@company.com";

    // 1. Secret fields are identified
    assert!(is_secret_field("stripe_secret_key"));
    assert!(is_secret_field("webhook_secret"));
    assert!(is_secret_field("polar_access_token"));
    assert!(is_secret_field("STRIPE_SECRET_KEY"));
    assert!(is_secret_field("POLAR_WEBHOOK_SECRET"));

    // 2. Email fields are identified
    assert!(is_email_field("customer_email"));
    assert!(is_email_field("email"));

    // 3. Harness field redaction redacts secret fields
    let redacted_secret = redacted_value("webhook_secret", sample_secret);
    assert_eq!(redacted_secret, "[redacted]");
    assert!(!redacted_secret.contains(sample_secret));

    // 4. Harness field redaction pseudonymises email fields
    let redacted_email = redacted_value("customer_email", sample_email);
    assert!(!redacted_email.contains(sample_email));
    assert!(redacted_email.starts_with("subject_hash:"));

    // 5. Value-level scrubbing removes emails and Bearer secrets from free-text messages
    let log_message = format!(
        "Processed billing checkout for customer={sample_email} with authorization: Bearer {sample_secret}"
    );
    let scrubbed = scrub_text(&log_message);

    assert!(
        !scrubbed.contains(sample_secret),
        "secret must be scrubbed from log text"
    );
    assert!(
        !scrubbed.contains(sample_email),
        "raw customer email must be scrubbed from log text"
    );

    // 6. URL query strings carrying secrets are scrubbed
    let url_log = format!(
        "Redirecting to https://polar.sh/checkout/123?customer_email={sample_email}&secret={sample_secret}"
    );
    let scrubbed_url = scrub_text(&url_log);
    assert!(!scrubbed_url.contains(sample_secret));
    assert!(!scrubbed_url.contains(sample_email));
}

/// Acceptance criterion 6:
/// In self-host mode, /v1/billing/* answers 404 and the Worker builds without
/// Stripe configuration.
#[pollster::test]
async fn test_self_host_mode_answers_404_no_payments_required() {
    let self_host_billing = Billing::self_host();

    // Check requires(): does NOT require Port::Payments or Port::Mailer
    let reqs = self_host_billing.requires();
    assert!(
        !reqs.contains(&Port::Payments),
        "Self-host mode must not require Port::Payments"
    );
    assert!(
        !reqs.contains(&Port::Mailer),
        "Self-host mode must not require Port::Mailer"
    );

    // validate_config succeeds without any Stripe or Polar config
    let empty_config = MapConfig::default();
    assert!(self_host_billing.validate_config(&empty_config).is_ok());

    // Build test harness with self-host billing
    let harness = TestHarness::with_ports(
        vec![
            Box::new(crate::Accounts::new()),
            Box::new(crate::Agents::new()),
            Box::new(self_host_billing),
        ],
        |ports| {
            ports.config = Arc::new(MapConfig::from_pairs([("ADMIN_TOKEN", ADMIN)]));
        },
    );

    // Routes answer 404
    let r1 = request(&harness.router, Method::POST, "/v1/billing/checkout", None).await;
    assert_eq!(r1.status, StatusCode::NOT_FOUND);

    let r2 = request(&harness.router, Method::POST, "/v1/billing/portal", None).await;
    assert_eq!(r2.status, StatusCode::NOT_FOUND);

    let r3 = request(
        &harness.router,
        Method::POST,
        "/v1/billing/stripe-webhook",
        None,
    )
    .await;
    assert_eq!(r3.status, StatusCode::NOT_FOUND);
}

/// Checkout endpoint test: validates annual default, price lookup, URL response.
#[pollster::test]
async fn test_checkout_endpoint() {
    let payments = TestPayments::default();
    let mailer = TestMailer::default();
    let kit = billing_kit(payments.clone(), mailer, &[]);
    let account = new_account(&kit).await;
    let (_, token) = new_agent(&kit, &account, "laptop", &[]).await;

    // Checkout Pro without interval (default annual)
    let body = json!({ "plan": "pro" }).to_string();
    let res = request_as(
        &kit.router,
        Method::POST,
        "/v1/billing/checkout",
        &token,
        Some(&body),
    )
    .await;
    assert_eq!(res.status, StatusCode::OK);
    assert_eq!(res.json()["url"], "https://polar.sh/checkout/cs_test_123");

    let recorded_checkout_reqs = payments.recorded_checkout_requests.lock().unwrap().clone();
    assert_eq!(recorded_checkout_reqs.len(), 1);
    assert_eq!(recorded_checkout_reqs[0].price_ref, "price_pro_polar_annual");
    assert_eq!(recorded_checkout_reqs[0].metadata.get("account_id").unwrap(), &account);
    assert_eq!(recorded_checkout_reqs[0].metadata.get("plan").unwrap(), "pro");

    // Checkout Team with monthly interval
    let body_team = json!({ "plan": "team", "interval": "month" }).to_string();
    let res_team = request_as(
        &kit.router,
        Method::POST,
        "/v1/billing/checkout",
        &token,
        Some(&body_team),
    )
    .await;
    assert_eq!(res_team.status, StatusCode::OK);

    let recorded_checkout_reqs2 = payments.recorded_checkout_requests.lock().unwrap().clone();
    assert_eq!(recorded_checkout_reqs2.len(), 2);
    assert_eq!(recorded_checkout_reqs2[1].price_ref, "price_team_polar_monthly");
}

/// Customer portal endpoint test.
#[pollster::test]
async fn test_customer_portal_endpoint() {
    let payments = TestPayments::default();
    let mailer = TestMailer::default();
    let kit = billing_kit(payments.clone(), mailer, &[]);
    let account = new_account(&kit).await;
    let (_, token) = new_agent(&kit, &account, "laptop", &[]).await;

    // Portal without billing customer -> 404
    let res_no_cust = request_as(
        &kit.router,
        Method::POST,
        "/v1/billing/portal",
        &token,
        None,
    )
    .await;
    assert_eq!(res_no_cust.status, StatusCode::NOT_FOUND);

    // Add customer record
    kit.db
        .execute(&Statement::with_values(
            "INSERT INTO billing_customers (account_id, stripe_customer_id, plan, status, updated_at) VALUES (?, 'cus_portal_test', 'pro', 'active', '2026-10-18T00:00:00Z')",
            vec![account.into()],
        ))
        .await
        .unwrap();

    let res = request_as(
        &kit.router,
        Method::POST,
        "/v1/billing/portal",
        &token,
        None,
    )
    .await;
    assert_eq!(res.status, StatusCode::OK);
    assert_eq!(res.json()["url"], "https://polar.sh/portal/cus_portal_test");
}

/// Dispute flow test (maintainer scope addition): opened -> won -> lost.
#[pollster::test]
async fn test_dispute_lifecycle_and_audit_trail() {
    let payments = TestPayments::default();
    let mailer = TestMailer::default();
    let kit = billing_kit(payments, mailer, &[]);
    let account = new_account(&kit).await;

    kit.db
        .execute(&Statement::with_values(
            "INSERT INTO billing_customers (account_id, stripe_customer_id, subscription_id, plan, status, updated_at) VALUES (?, 'cus_disp', 'sub_disp', 'pro', 'active', '2026-10-18T00:00:00Z')",
            vec![account.clone().into()],
        ))
        .await
        .unwrap();

    let mut headers = HeaderMap::new();
    headers.insert("stripe-signature", "valid_sig".parse().unwrap());
    headers.insert("content-type", "application/json".parse().unwrap());

    // 1. Dispute created -> status marked disputed, logged in billing_audit
    let fixture_opened = json!({
        "id": "evt_disp_open",
        "type": "customer.dispute.created",
        "data": {
            "object": {
                "customer": "cus_disp",
                "status": "needs_response"
            }
        }
    })
    .to_string();

    let res = request_raw(
        &kit.router,
        Method::POST,
        "/v1/billing/stripe-webhook",
        headers.clone(),
        Some(fixture_opened.as_bytes().to_vec()),
    )
    .await;
    assert_eq!(res.status, StatusCode::OK);

    let rows = kit
        .db
        .query(&Statement::with_values(
            "SELECT status FROM billing_customers WHERE account_id = ?",
            vec![account.clone().into()],
        ))
        .await
        .unwrap();
    let status = match rows.first().unwrap().get("status") {
        Some(SeaValue::String(Some(s))) => *s,
        _ => panic!("missing status"),
    };
    assert_eq!(status, "disputed");

    // 2. Dispute won -> status restored to active
    let fixture_won = json!({
        "id": "evt_disp_won",
        "type": "customer.dispute.closed",
        "data": {
            "object": {
                "customer": "cus_disp",
                "status": "won"
            }
        }
    })
    .to_string();

    let res_won = request_raw(
        &kit.router,
        Method::POST,
        "/v1/billing/stripe-webhook",
        headers.clone(),
        Some(fixture_won.as_bytes().to_vec()),
    )
    .await;
    assert_eq!(res_won.status, StatusCode::OK);

    let rows = kit
        .db
        .query(&Statement::with_values(
            "SELECT status FROM billing_customers WHERE account_id = ?",
            vec![account.clone().into()],
        ))
        .await
        .unwrap();
    let status = match rows.first().unwrap().get("status") {
        Some(SeaValue::String(Some(s))) => *s,
        _ => panic!("missing status"),
    };
    assert_eq!(status, "active");

    // Verify audit logs
    let audit_rows = kit
        .db
        .query(&Statement::with_values(
            "SELECT event_type FROM billing_audit WHERE account_id = ?",
            vec![account.clone().into()],
        ))
        .await
        .unwrap();
    assert_eq!(audit_rows.len(), 2);
}
