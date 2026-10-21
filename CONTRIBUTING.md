# Contributing

## Bounties and outside pull requests

There are no bounties on this project. Issues here are the team's planning notes, not paid tasks.
Pull requests from people outside the team are only reviewed when the change was discussed in the
issue first and a maintainer agreed to it. Other pull requests are closed without review.

Run the same checks CI runs before you hand work back:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo check -p sealbin-format -p sealbin-core -p sealbin-server -p sealbin-worker -p sealbin-wasm --target wasm32-unknown-unknown
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
cargo deny check
(cd crates/sealbin-worker && worker-build --release)   # gzip'd bundle must stay under 3 MiB
```

The toolchain comes from `rust-toolchain.toml`. You also need `worker-build`
and `cargo-deny` on PATH.

## Licensing

No CLA. Contributions are under Apache-2.0, inbound = outbound (Apache-2.0
section 5). No DCO sign-off is required.

## Crypto changes

A change to the crypto in `sealbin-format` needs a spec change in `spec/` and
new test vectors, in the same pull request.

House rules for coding agents and humans are in `AGENTS.md`.
