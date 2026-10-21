-- The anonymous seal rate-limit tracker (D14): one row per (ip_hash, sender_id)
-- per rolling 24h. `ip_hash` is never the raw IP, but a salted hash thereof.
-- `sender_id` is optional sender attribution if Bearer token is provided.
-- `created_at` and `expires_at` are unix milliseconds.
-- Rows older than 24h are cleaned up by expiry.
CREATE TABLE IF NOT EXISTS anon_seal_limits (
    ip_hash TEXT NOT NULL,
    sender_id TEXT,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (ip_hash, sender_id)
);

-- Index by expires_at for rolling 24h cleanup
CREATE INDEX IF NOT EXISTS anon_seal_limits_expires_at ON anon_seal_limits(expires_at);
