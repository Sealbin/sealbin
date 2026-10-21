-- The seals index table (D10): one row per seal, keyed by id.
-- `account` and `agent_prefix` identify the author.
-- `state` tracks the seal lifecycle (sealed, opening, gone).
-- `gone_at` records when the seal transitioned to gone.
CREATE TABLE IF NOT EXISTS seals_index (
    id TEXT PRIMARY KEY,
    account TEXT NOT NULL,
    agent_prefix TEXT,
    size INTEGER NOT NULL,
    burn BOOLEAN NOT NULL,
    password BOOLEAN NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('uploading','sealed','opening','gone')),
    gone_at TEXT
);

-- Index by account for listing and revocation
CREATE INDEX IF NOT EXISTS seals_index_account ON seals_index(account);

-- Index by expires_at for TTL cleanup
CREATE INDEX IF NOT EXISTS seals_index_expires_at ON seals_index(expires_at);

-- Index by gone_at for audit
CREATE INDEX IF NOT EXISTS seals_index_gone_at ON seals_index(gone_at);
