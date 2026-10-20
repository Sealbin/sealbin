# Bounty Objective: Billing: Pro and Team subscriptions through Polar (MoR), webhooks, customer portal, downgrades, disputes
Target: Sealbin/sealbin Issue #16
URL: https://github.com/Sealbin/sealbin/issues/16

## Issue Description
Milestone: M1 · Size: M · Repo: sealbin/sealbin

## Context

Pro ($19/month) and Team ($49/month) need a way to pay, upgrade, cancel and get receipts. The harness has a `Payments` port with a Stripe adapter (`Cratefield/harness:crates/core/src/ports/payments.rs`, `crates/adapter-stripe/src/lib.rs`, issue #102): `create_subscription_checkout` (`SubscriptionCheckoutRequest` with `price_ref`, `customer_ref`, `customer_email`, `metadata`, `idempotency_key`) and `verify_webhook(signature_header, body) -> WebhookEvent { id, kind, data }`. Interpreting events is venture code by design (payments.rs module docs). Missing: a customer portal session (to update the card, cancel, download invoices) and a way to read a subscription's current state; Cratefield/harness#589 adds both.

Webhook delivery from Stripe is at-least-once and can repeat or reorder. The harness `Inbox` (`crates/core/src/idempotency.rs`) applies an external event's effects exactly once when the claim and the effect go in one `batch_atomic`.

Plan limits and the downgrade rule live in #15 (`sealbin-core::plans`, `on_plan_change`). This issue is the only writer of an account's `plan` on the hosted service.

## Scope

- Module `billing` in `crates/sealbin-server`, mounted at `/v1/billing`, disabled in self-host mode (routes answer 404 and the module declares no Payments requirement there).
- `POST /v1/billing/checkout {plan: "pro" | "team"}` (signed-in account, #14 session/token): creates a subscription checkout with `price_ref` from config `STRIPE_PRICE_PRO` / `STRIPE_PRICE_TEAM`, `metadata.account_id`, `idempotency_key = account_id + plan + day`, success/cancel URLs on `https://sealb.in/account`. Returns `{url}`. `sealb upgrade` (#19) opens it.
- `POST /v1/billing/portal`: returns a Stripe customer portal URL (Cratefield/harness#589) for the account's `stripe_customer_id`.
- `POST /v1/billing/stripe-webhook` with `RoutePolicy` for a machine signature (`Cratefield/harness:crates/core/src/route_policy.rs`): `verify_webhook`, then `Inbox` claim on the event id in the same batch as the effect. Events handled: `checkout.session.completed` (link customer to account, set plan), `customer.subscription.updated` (plan change, `cancel_at_period_end`), `customer.subscription.deleted` (back to Free), `invoice.payment_failed` (mark `past_due`, send a notice), `invoice.paid` (clear `past_due`). Out-of-order events: the handler reads the subscription's current state via Cratefield/harness#589 rather than trusting the event payload's order, and stores `stripe_subscription_status` and `current_period_end`.
- Schema (D1 migration): `billing_customers (account_id PK, stripe_customer_id UNIQUE, subscription_id, plan, status, current_period_end, updated_at)`. No card data, ever (payments.rs: card data never crosses the harness).
- Past due: 7 days of grace on the paid plan, then the plan drops to Free through `on_plan_change` (#15). A scheduled task (harness scheduled budget, `crates/core/src/scheduled.rs`) applies the drop.
- Notices by email through the `Mailer` port with adapter-owlpost (Cratefield/harness#591), from `no-reply@send.sealb.in`, enqueued with the `Outbox` (`crates/core/src/outbox.rs`) in the same batch as the state change: "plan changed", "payment failed", "downgraded to Free". Stripe sends receipts and invoices itself (portal setting, **needs-human**).
- Runbook `docs/runbooks/billing.md` (**needs-human** steps): create products and prices in Stripe (Pro $19, Team $49, monthly, USD), enable the customer portal with cancel and invoice history, register the webhook endpoint `https://api.sealb.in/v1/billing/stripe-webhook` for the five events, set `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `STRIPE_PRICE_PRO`, `STRIPE_PRICE_TEAM` as Worker secrets, and test mode first.

## Acceptance criteria

- [ ] Tests with the harness testing kit and recorded Stripe payload fixtures (no live keys in CI): checkout completed sets Pro; subscription deleted sets Free; the same event delivered twice applies once; `updated` arriving before `completed` ends in the right plan.
- [ ] A webhook with a bad signature answers 400 and changes nothing.
- [ ] Downgrade from Pro to Free keeps existing seals and keys working and applies Free limits to new seals (test through `on_plan_change`).
- [ ] Past-due accounts drop to Free after 7 days (fake clock) and get one email per transition, not per retry.
- [ ] No Stripe secret or customer email appears in logs (test with the harness log redaction, `crates/core/src/logging.rs`).
- [ ] In self-host mode, `/v1/billing/*` answers 404 and the Worker builds without Stripe configuration.
- [ ] The runbook lists every needs-human step with the exact names of secrets and events.

## Out of scope

- Enterprise invoicing, taxes beyond what Stripe Tax does when enabled in the dashboard, coupons.
- Usage-based billing for inbox deliveries (#45).
- Team seat changes inside a plan: Team is a flat price for up to 50 agents.

## Depends on

- #15 (plans, `on_plan_change`).
- Cratefield/harness#589 (portal session and subscription lookup), Cratefield/harness#591 (Owlpost mailer).

## References

- `Sealbin/website:index.html` pricing section.
- `Cratefield/harness:crates/core/src/ports/payments.rs` (`SubscriptionCheckoutRequest`, `WebhookEvent`, `verify_webhook`), `crates/adapter-stripe/src/lib.rs`, `crates/core/src/idempotency.rs`, `crates/core/src/outbox.rs`, `crates/core/src/route_policy.rs`, `crates/core/src/scheduled.rs`, `docs/PAYMENTS.md`.
- Stripe docs: Checkout subscriptions, customer portal, webhook best practices (event ordering, retries).


## Instructions for Kuro (Autonomous Solver):
1. Use skills: `systematic-debugging` and `code-review-and-quality`.
2. Inspect the repository structure, locate relevant files, and understand the bug/feature.
3. Apply the minimal, robust fix or implementation.
4. Run any existing test suites or linters in the workspace.
5. Ensure the fix adheres to the project's existing code style.
6. When done, output a summary of files modified and verification results.
