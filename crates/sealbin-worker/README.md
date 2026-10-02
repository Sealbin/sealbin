# sealbin-worker

The sealbin Cloudflare Worker: the harness composition, the `SealObject`
Durable Object (a stub until #8), `wrangler.toml`, `migrations/` and the
static pages from `web/dist/` (D1, D3, D9).

Every manual step below is marked **needs-human**: nothing here is done by CI
and none of it can be replayed without the account.

## Local run

```sh
cd ../.. && web/build.sh && cd crates/sealbin-worker   # builds web/dist/
printf 'HARNESS_SECRET=%s\n' "$(openssl rand -hex 32)" > .dev.vars  # gitignored
wrangler d1 migrations apply DB --local
wrangler dev --local
```

`.dev.vars` is gitignored and needs `HARNESS_SECRET` (≥ 32 bytes — the harness
`Signer`; without it the Worker boots but logs `Signer port not provided`).
`ADMIN_TOKEN` is optional, only for the harness admin routes.

The Worker serves `/s/*` and `/activate*` from `web/dist/` and everything else
from the harness, so `curl localhost:8787/__health`,
`localhost:8787/.well-known/sealbin` and `localhost:8787/v1/x` (404) exercise
the harness.

## Smoke test

```sh
bash crates/sealbin-worker/tests/smoke.sh
```

Builds `web/dist/` and the bundle, applies the local migrations into a temp
`--persist-to`, starts `wrangler dev --local` on a random port with a random
`HARNESS_SECRET`, and checks `/__health`, `/.well-known/sealbin` (`api`,
`formats: [1]`, `max-age=3600`), `/s/*` and `/activate` (HTML, and **no
`x-request-id`**, which proves the harness router was not the one serving the
page) and a `/v1/x` 404. It never touches an account and removes its state on
exit.

## Resources

**needs-human** — create each one, then put its id where the table says.

| Resource | Env | Create | Where the id goes |
| :--- | :--- | :--- | :--- |
| D1 `sealbin` | production | `wrangler d1 create sealbin` | `[[env.production.d1_databases]] database_id` |
| D1 `sealbin-staging` | staging + local | `wrangler d1 create sealbin-staging` | `[[env.staging.d1_databases]]` and the top-level `database_id` |
| R2 `sealbin-seals` | production | `wrangler r2 bucket create sealbin-seals` | `[[env.production.r2_buckets]] bucket_name` (already set) |
| R2 `sealbin-seals-staging` | staging + local | `wrangler r2 bucket create sealbin-seals-staging` | `[[env.staging.r2_buckets]]` (already set) |
| DO class `SealObject` | all | none — `[[migrations]] tag = "v1"` is top-level and applies to every env | `[[durable_objects.bindings]] SEAL_OBJECTS` |
| Rate-limit namespace `1017` | all | none — ids are account-wide and manual | `[[unsafe.bindings]] RATE_LIMITER namespace_id` |
| Assets `web/dist` | all | `web/build.sh` | `[assets] directory` |

The `database_id` placeholders are the all-zero UUID; wrangler accepts it so
`--dry-run` passes, but a real deploy needs the ids above. **needs-human:**
confirm namespace **1017** is unused on the Factory0 account (the waitlist uses
1016) — a collision would silently share its counters.

## Secrets

**needs-human**, once per environment:

```sh
wrangler secret put HARNESS_SECRET --env staging    # ≥ 32 bytes, fresh per env
wrangler secret put HARNESS_SECRET --env production
# ADMIN_TOKEN only if the admin routes are wanted; ≥ 32 bytes when set.
```

## Migrations

`migrations/0001_rate_limit_counters.sql` is `RATE_LIMIT_COUNTERS_SQL` from
`cratefield-runtime-cloudflare`, hand-written because that constant is not a
harness module migration, so `fz migrations collect` would not write it. There
is no `.harness-lock.json` until a module adds SQL of its own.

## Routes and deploys

**needs-human** precondition (out of scope here): the `sealb.in` zone must move
to Cloudflare and the Pages project's domain be attached, with Pages keeping
every path except `/s/*`, `/activate*` and `/.well-known/sealbin` (D3).
Production then gets `api.sealb.in` as a custom domain plus the three zone
routes in `[env.production].routes`; staging stays on `workers.dev`.

```sh
(cd ../.. && web/build.sh)                 # from crates/sealbin-worker
wrangler d1 migrations apply DB --env production --remote
wrangler deploy --env production           # runs worker-build via [build]
```

Staging deploys from `.github/workflows/deploy-staging.yml` on every push to
main. **needs-human:** set the `CLOUDFLARE_API_TOKEN` repository secret (Workers
Scripts:Edit, D1:Edit, Workers R2 Storage:Edit); `CLOUDFLARE_ACCOUNT_ID` too if
the token can see more than one account. Without the token the workflow skips
itself with a notice.
