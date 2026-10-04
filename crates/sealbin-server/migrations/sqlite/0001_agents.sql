-- The `agents` table (D12): one row per named key an account holds. The row is
-- the agent's identity; the credential is its `api_keys` row (0002). `kind` is
-- advisory (machine/agent/ci), never a permission.
--
-- A revoked agent keeps its row, so the public prefix stays attributable; the
-- partial index frees the name for a new agent the moment the old one is
-- revoked, which the full uniqueness of `(account, name)` would not.
CREATE TABLE IF NOT EXISTS agents (
    prefix TEXT PRIMARY KEY,
    account TEXT NOT NULL,
    name TEXT NOT NULL,
    kind TEXT,
    created_at TEXT NOT NULL,
    revoked_at TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS agents_account_name_active
    ON agents (account, name)
    WHERE revoked_at IS NULL;
