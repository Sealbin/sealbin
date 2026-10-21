-- The seals idempotency table (D9): dedup POST /v1/seals requests with the same
-- Idempotency-Key header within a 24h window. `key_hash` is SHA-256(Idempotency-Key).
-- `response_id` is the returned seal id.
-- Rows older than 24h are cleaned up by the expiry window.
CREATE TABLE IF NOT EXISTS seals_idempotency (
    key_hash TEXT NOT NULL,
    response_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (key_hash)
);

-- Index by created_at for TTL cleanup (rows after 24h)
CREATE INDEX IF NOT EXISTS seals_idempotency_created_at ON seals_idempotency(created_at);
