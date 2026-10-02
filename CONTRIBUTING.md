# Contributing

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
