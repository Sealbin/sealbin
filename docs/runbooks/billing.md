# Runbook: Billing Operations & Polar Integration

This runbook documents the configuration, operation, lifecycle, and emergency procedures for Sealbin's billing system (#16).

---

## 1. Overview & Architecture

Sealbin sells Pro and Team subscriptions through **Polar** (https://polar.sh) acting as Merchant of Record (MoR), with Stripe supported via Cratefield's provider-neutral `Payments` port.

### Key Architectural Decisions
- **Merchant of Record (MoR):** Factory Zero sells through Polar to offload global sales tax, VAT, and merchant liability.
- **Annual Billing as Default:** Polar charges 5% + 50¢ per transaction; annual billing minimizes transaction overhead.
- **Provider-Neutral Port:** Routes and handlers interact exclusively with Cratefield's `Payments` port (`adapter-polar` and `adapter-stripe`).
- **Self-Host Mode:** Disabled in self-hosted deployments (`Billing::self_host()`). Routes answer `404 Not Found` and no payments configuration or credentials are required.
- **Idempotency & Resilience:** All webhook events are signature-verified and deduplicated through the atomic `billing_inbox` table (`Inbox::claim_with`). Out-of-order webhook delivery is safeguarded by performing authoritative `get_subscription` queries to Polar/Stripe.
- **Privacy & Redaction:** No raw credit card data ever crosses the harness. Customer emails and secrets are pseudonymized/redacted in logs via `cratefield_core::logging`.

---

## 2. Environment Variables & Secret Names

The following secrets and environment variables must be configured in Cloudflare Workers / production environment:

| Secret Name | Description | Required In |
|---|---|---|
| `POLAR_ACCESS_TOKEN` | Polar Organization Access Token | Hosted (Polar) |
| `POLAR_WEBHOOK_SECRET` | Secret for verifying Standard Webhook signatures | Hosted (Polar) |
| `POLAR_PRICE_PRO` | Polar Product/Price ID for Pro Annual subscription | Hosted (Polar) |
| `POLAR_PRICE_PRO_MONTHLY` | Polar Product/Price ID for Pro Monthly subscription | Hosted (Optional) |
| `POLAR_PRICE_TEAM` | Polar Product/Price ID for Team Annual subscription | Hosted (Polar) |
| `POLAR_PRICE_TEAM_MONTHLY` | Polar Product/Price ID for Team Monthly subscription | Hosted (Optional) |
| `STRIPE_SECRET_KEY` | Stripe Secret Key (`sk_live_...`) | Hosted (Stripe) |
| `STRIPE_WEBHOOK_SECRET` | Stripe Endpoint Signing Secret (`whsec_...`) | Hosted (Stripe) |
| `STRIPE_PRICE_PRO` | Stripe Price ID for Pro tier (`price_...`) | Hosted (Stripe) |
| `STRIPE_PRICE_TEAM` | Stripe Price ID for Team tier (`price_...`) | Hosted (Stripe) |
| `SEALBIN_PUBLIC_URL` | Public application URL for checkout return redirects (default: `https://sealb.in`) | Hosted |

> **Note:** In self-hosted mode, none of the above secrets are required.

---

## 3. Polar Organization Setup (Step-by-Step)

1. **Create Polar Account & Organization:**
   - Sign up or log into [Polar](https://polar.sh).
   - Create the organization for `Sealbin`.
2. **Generate Organization Access Token:**
   - Navigate to **Settings -> Developers -> Access Tokens**.
   - Generate a new Personal/Organization Access Token with billing permissions.
   - Save the token securely into the deployment environment as `POLAR_ACCESS_TOKEN`.
3. **Configure Subscription Products:**
   - Under **Products**, create:
     - **Sealbin Pro**:
       - Annual Price (default): Set billing interval to yearly. Copy the price ID to `POLAR_PRICE_PRO`.
       - Monthly Price: Set billing interval to monthly. Copy the price ID to `POLAR_PRICE_PRO_MONTHLY`.
     - **Sealbin Team**:
       - Annual Price (default): Set billing interval to yearly. Copy the price ID to `POLAR_PRICE_TEAM`.
       - Monthly Price: Set billing interval to monthly. Copy the price ID to `POLAR_PRICE_TEAM_MONTHLY`.
4. **Register Webhook Endpoint:**
   - Navigate to **Settings -> Developers -> Webhooks**.
   - Add a new webhook endpoint:
     - **URL:** `https://sealb.in/v1/billing/polar-webhook` (or `https://<domain>/v1/billing/webhook`)
     - **Format:** Standard Webhooks
     - **Subscribed Events:**
       - `checkout.session.completed` / `order.created`
       - `subscription.created`
       - `subscription.updated`
       - `subscription.canceled` / `subscription.revoked`
   - Copy the Webhook Signing Secret into `POLAR_WEBHOOK_SECRET`.

---

## 4. Stripe Setup (Alternative / Fallback Adapter)

When running with `adapter-stripe`:
1. Log into [Stripe Dashboard](https://dashboard.stripe.com).
2. Configure Products & Prices:
   - Pro: recurring price -> set `STRIPE_PRICE_PRO`
   - Team: recurring price -> set `STRIPE_PRICE_TEAM`
3. Add Webhook Endpoint:
   - **URL:** `https://sealb.in/v1/billing/stripe-webhook`
   - **Events to Listen:**
     - `checkout.session.completed`
     - `customer.subscription.updated`
     - `customer.subscription.deleted`
     - `invoice.payment_failed`
     - `invoice.paid`
     - `customer.dispute.created`
     - `customer.dispute.closed`
4. Store signing secret as `STRIPE_WEBHOOK_SECRET` and API key as `STRIPE_SECRET_KEY`.

---

## 5. Webhook Handlers & Idempotency

### Endpoints
- `POST /v1/billing/polar-webhook`
- `POST /v1/billing/stripe-webhook`
- `POST /v1/billing/webhook`

### Deduplication (D10 / ADR 0004)
Every webhook delivery is processed through `Inbox::claim_with(&*db, event_id, now_str, &batch)`.
- If an event ID has already been recorded in `billing_inbox`, the database transaction skips the effects and returns `200 OK` immediately.
- Duplicate deliveries, network retries, and concurrent replays never produce duplicate database mutations or duplicate emails.

### Out-of-Order Resilience
When `subscription.updated` arrives before `checkout.session.completed`, the handler queries the authoritative provider state via `payments.get_subscription(sub_id)`. The database is updated with the authoritative subscription status and period end, guaranteeing eventual consistency regardless of webhook arrival order.

---

## 6. Subscription Lifecycles & Downgrade Rule

### Plan Limits & Downgrade Behavior (D13)
- **Active Plans:** `Free`, `Pro`, `Team`, `SelfHost`.
- **The Downgrade Invariant:**
  - Downgrading an account from Pro or Team to Free **never deletes, truncates, or damages existing seals or keys**.
  - All existing seals continue to be verifiable, decryptable, and serve until burn or expiration.
  - All existing API keys and agents remain valid.
  - Only new creation actions are gated by the Free plan's ceilings (e.g. max 1 active agent, 25 MiB payload cap).

### Payment Failures & 7-Day Grace Period
1. When an invoice payment fails (`invoice.payment_failed`), account status in `billing_customers` transitions to `past_due`.
2. A payment failure notification email is enqueued in `billing_outbox` and sent to the account owner from `no-reply@send.sealb.in`.
3. The account retains its paid features for a **7-day grace period** (`PAST_DUE_GRACE_SECS = 604800`).
4. A recurring scheduled job checks for accounts past due longer than 7 days:
   - Drops `plan` to `free` in both `billing_customers` and `accounts`.
   - Enqueues a single downgrade notice email in `billing_outbox`.
   - Drains `billing_outbox` via the `Mailer` port.
   - Retries of the scheduled task never send duplicate notices.

---

## 7. Disputes & Chargebacks (Maintainer Scope)

1. **Dispute Opened (`customer.dispute.created` / `dispute.created`):**
   - Account status in `billing_customers` is updated to `disputed`.
   - Audit trail record is recorded in `billing_audit` (`event_type: 'dispute_opened'`) containing the dispute payload.
2. **Dispute Won (`customer.dispute.closed` with `status: "won"`):**
   - Account status is restored to `active`.
   - Audit trail recorded (`event_type: 'dispute_won'`).
3. **Dispute Lost (`customer.dispute.closed` with `status: "lost"`):**
   - Account is immediately downgraded to `free` (`status: 'dispute_lost'`).
   - Audit trail recorded (`event_type: 'dispute_lost'`).
   - `on_plan_change(Plan::Pro, Plan::Free)` is applied.

---

## 8. Customer Portal

`POST /v1/billing/portal`
- Caller authenticates via API key bearer token.
- Looks up the customer's payment reference (`stripe_customer_id`) in `billing_customers`.
- Calls `Payments::create_portal_session` with an idempotency key and return URL (`/account`).
- Returns `{ "url": "<portal_session_url>" }` where customers can update cards, view invoices, or cancel subscriptions.

---

## 9. Operator Procedures & Incident Response

### Manual Subscription Reconciliation
If webhooks were delayed or dropped during provider downtime:
1. Identify the affected account ID and provider subscription ID.
2. Execute authoritative lookup via the Payments adapter:
   ```bash
   # Query provider subscription details and update customer row
   UPDATE billing_customers SET status = 'active', plan = 'pro', updated_at = CURRENT_TIMESTAMP WHERE subscription_id = '<SUB_ID>';
   UPDATE accounts SET plan = 'pro' WHERE id = '<ACCOUNT_ID>';
   ```
3. Insert an audit entry into `billing_audit`:
   ```sql
   INSERT INTO billing_audit (id, account_id, event_type, details, created_at)
   VALUES ('<ULID>', '<ACCOUNT_ID>', 'manual_reconciliation', '{"reason": "missed_webhook"}', CURRENT_TIMESTAMP);
   ```

### Emergency Dispute Lock
To immediately quarantine an account under fraud investigation:
```sql
UPDATE billing_customers SET status = 'disputed', updated_at = CURRENT_TIMESTAMP WHERE account_id = '<ACCOUNT_ID>';
INSERT INTO billing_audit (id, account_id, event_type, details, created_at)
VALUES ('<ULID>', '<ACCOUNT_ID>', 'manual_hold', '{"reason": "fraud_review"}', CURRENT_TIMESTAMP);
```
