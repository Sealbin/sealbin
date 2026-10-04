-- The harness API-key store (D12): one row per agent. `subject` is the account
-- id the key speaks for, and `secret_hash` is the only place the key's secret
-- exists — never in plaintext.
--
-- Verbatim `ApiKeys::create_table_sql()` from cratefield-core 0.7.0 with the
-- table `api_keys`; `the_api_keys_migration_matches_the_harness_ddl` fails if
-- the two ever drift.
CREATE TABLE IF NOT EXISTS api_keys (
    prefix TEXT PRIMARY KEY,
    secret_hash TEXT NOT NULL,
    namespace TEXT NOT NULL,
    subject TEXT NOT NULL,
    scopes TEXT NOT NULL,
    mode TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_used_at TEXT,
    revoked_at TEXT
);
