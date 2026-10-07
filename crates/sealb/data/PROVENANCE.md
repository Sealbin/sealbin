# Provenance of `stack.json`

- `data/stack.json` is a verbatim copy of Sealbin's entry (`ventures[]` where
  `id == "FZ-016"`) in the Factory Zero registry, published at
  <https://factory0.ventures/stack.json>.
- Retrieved: 2026-10-07.
- The registry is the source of truth. Changes land there first; this file only
  follows it.
- To re-vendor: update the registry entry, fetch `stack.json`, replace
  `ventures[]` for `FZ-016` with the published object, and keep the retrieval
  date above current. Nothing here may be edited to disagree with the registry.
- The registry also publishes the status words, `live` ("In use today.") and
  `planned` ("Decided and tracked, not in use yet."). Only those two statuses
  exist; nothing planned may be shown as live.
- `crates/sealb/build.rs` reads this file at build time and generates
  `ENTRIES`; `web/open.html` mirrors it by hand. Neither fetches at runtime.
- `crates/sealb/tests/built_with.rs` has a network-gated drift test
  (`vendored_entry_matches_published_registry`) that fails CI when the copy here
  no longer matches the registry.
