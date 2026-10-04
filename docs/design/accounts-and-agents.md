# Accounts and agents

How identity works before billing and audit land (#13). Decisions D10–D13 in
`decisions.md` are the authority; this file says how the code reads them.

## An account

One `accounts` row, keyed by an opaque ULID the server mints: plan, optional
email, and a status of `active` or `disabled`. `auth_subject` is reserved for
the hosted-auth identity (D11) and is UNIQUE, so one identity cannot claim two
accounts; self-hosted deployments leave it NULL and hand out access with
`ADMIN_TOKEN` instead. A disabled account keeps its rows, but no key of it
authenticates: every request is 403 `account/disabled`.

## An agent is a key

An agent is one named API key (D12). The `agents` row is the identity — prefix,
name, kind, created and revoked — and the harness `api_keys` row is the
credential; they share the prefix. A revoked agent keeps its row, so the prefix
stays attributable and the name it retired is visible, and the partial unique
index frees that name the moment it is revoked. `kind` (`machine`, `agent`,
`ci`) is advisory: it records what the caller meant, never a permission.

## Keys

Minted by `ApiKeys` under namespace `sb`, so a token reads
`sb_live_<16 hex>_<64 hex>` (`sb_test_…` in test mode). Only the prefix and a
hash are stored: the token exists in the one `201` that returns it, and in no
log line, list body or export. `mode` is decided at mint — the admin route
takes it from the body, `POST /v1/agents` takes the caller's — so a key can
never mint into an environment the caller cannot reach.

## Scopes

Four exact-match strings: `seals:write`, `seals:read-attributed`,
`agents:manage`, `audit:read`. Naming none grants the first two — what sealing
needs — so a key that seals by default cannot grow the account's authority.
`agents:manage` is what lets a key create, rename and revoke the account's
others; a key may always rename and revoke itself.

## Bootstrap

No self-service sign-up. An operator with `ADMIN_TOKEN` creates the account
(`POST /v1/accounts/admin/accounts`) and mints its first key
(`POST /v1/accounts/admin/accounts/{id}/agents`). `ADMIN_TOKEN` unset is a legal
deployment: the admin routes answer 401, as they do for a missing key, so a
probe learns nothing either way.

## Limits and erasure

Plan ceilings live behind `PlanGate`, defaulting to unlimited (self-host
unlimited, D13); the hosted ceilings are #15's. Erasing an account revokes every
key, revokes its seals through `SealRevoker` (#9), and deletes its `api_keys`,
`agents` and `accounts` rows — the declarations in `personal_data` say so.

## Open question

D12 left open whether the agent limit counts per machine or per agent:
`sealb init` writes one key per machine unless `--key-per-agent`. Counting
active keys, as the code does, makes "3 agents on Free" three machines by
default.
