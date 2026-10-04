-- The `accounts` table (D11): one row per account, keyed by an opaque ULID.
-- `auth_subject` links a hosted-auth identity when one is configured; it is
-- UNIQUE so one identity cannot claim two accounts.
CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    plan TEXT NOT NULL DEFAULT 'free',
    auth_subject TEXT UNIQUE,
    email TEXT,
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','disabled'))
);
