-- The `billing_customers` table: one row per account holding its billing status.
-- `account_id` is the PK. `stripe_customer_id` is the provider's customer reference
-- (Polar or Stripe), UNIQUE across accounts.
CREATE TABLE IF NOT EXISTS billing_customers (
    account_id TEXT PRIMARY KEY,
    stripe_customer_id TEXT UNIQUE,
    subscription_id TEXT,
    plan TEXT NOT NULL DEFAULT 'free',
    status TEXT,
    current_period_end TEXT,
    updated_at TEXT NOT NULL
);

-- The `billing_inbox` table: deduplicates incoming webhook events exactly once.
CREATE TABLE IF NOT EXISTS billing_inbox (
    event_key TEXT PRIMARY KEY,
    seen_at TEXT NOT NULL
);

-- The `billing_outbox` table: durable delivery of email notifications.
CREATE TABLE IF NOT EXISTS billing_outbox (
    id TEXT PRIMARY KEY,
    topic TEXT NOT NULL,
    payload TEXT NOT NULL,
    subject TEXT,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TEXT NOT NULL,
    locked_until TEXT,
    created_at TEXT NOT NULL
);

-- The `billing_audit` table: dispute, chargeback and plan transition audit records.
CREATE TABLE IF NOT EXISTS billing_audit (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    details TEXT,
    created_at TEXT NOT NULL
);
