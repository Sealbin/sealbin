# AGENTS.md

House rules for coding agents and humans. Read `docs/design/decisions.md`
before changing behavior; it records why.

## Layout

| Path | What it is |
| :--- | :--- |
| `crates/` | the Rust workspace: `sealbin-format`, `sealbin-core`, `sealbin-server`, `sealbin-worker`, `sealb`, `sealbin-wasm` |
| `npm/` | npm wrappers: `sealb`, `@sealbin/mcp`, `@sealbin/cli-<platform>`, `@sealbin/crypto` |
| `skill/` | the agent skill |
| `web/` | the browser open and activate pages |
| `spec/` | the handoff format spec |
| `docs/` | design decisions, agents, threat model, runbooks |
| `deploy/` | self-host tooling |

## Before handing work back

Run the checks in `CONTRIBUTING.md` — the same ones CI runs. Work that fails
them is not done.

## Dependencies

All `cratefield-*` crates share one source: the crates.io 0.6 line, or all of
them pinned to the same Cratefield/harness git rev in the root
`[workspace.dependencies]`. Never mix. Two copies of `cratefield-core` fail to
compile with `expected cratefield_core::Module, found cratefield_core::Module`.
`cargo tree -d --depth 0 | grep cratefield` must print nothing.

## Secrets

Never print, log or commit a secret: `HARNESS_SECRET`, `ADMIN_TOKEN`, Stripe and
Owlpost keys, any `sb_live_` key, or any link containing `#key=`. The part after
`#` is the decryption key and never reaches a server.

## Deploys

Run `wrangler deploy` and remote D1 migrations only when a human asks for it.

## Crypto

The crypto in `sealbin-format` changes only with a spec change in `spec/` and
new test vectors, in the same pull request.

## New crates

Put a new crate under `crates/`. The `crates/*` workspace glob picks it up; do
not edit a member list.

## `unsafe_code`

`unsafe_code` is forbidden workspace-wide.
