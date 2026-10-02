# Security

Report vulnerabilities privately to security@sealb.in. Do not open a public
issue for a vulnerability; that tells everyone before there is a fix.

The machine-readable policy is at https://sealb.in/.well-known/security.txt.

Tell us how to reproduce the problem and give us time to fix it before you
disclose it.

## In scope

- the crates: `sealbin-format`, `sealbin-core`, `sealbin-server`,
  `sealbin-worker`, `sealb`, `sealbin-wasm`
- the CLI and `sealb mcp`
- the Cloudflare Worker
- the browser open page at https://sealb.in/s/{id}
- the handoff format (`spec/`)

## Never include

Never put live keys or a `#key=` link in a report. The part after `#` is the
decryption key: once it is in an email or an issue, that seal is compromised.
Reproduce with a seal you created for testing, and say so.
