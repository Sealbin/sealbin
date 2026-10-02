# web

The browser open page at `/s/{id}` and the activate page, vanilla JS like the
site. The Worker (`crates/sealbin-worker`) serves them, and they decrypt in the
browser with `@sealbin/crypto`
(see [`docs/design/decisions.md`](../docs/design/decisions.md), D3 and D11).
