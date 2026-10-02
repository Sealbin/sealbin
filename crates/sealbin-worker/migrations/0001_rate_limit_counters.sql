-- The D1-backed per-key rate limiter's counters table.
--
-- Verbatim `RATE_LIMIT_COUNTERS_SQL` from cratefield-runtime-cloudflare
-- 0.2.0 src/ports/d1_rate_limit.rs: the SQL the limiter's atomic upsert
-- counts in. It is not a module migration (`fz migrations collect` writes
-- only `Module::migrations()`), so it is hand-written and numbered like the
-- files collect produces.
CREATE TABLE IF NOT EXISTS rate_limit_counters (key TEXT PRIMARY KEY, window_start INTEGER NOT NULL, count INTEGER NOT NULL);
