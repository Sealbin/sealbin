#!/usr/bin/env bash
# End-to-end smoke test for the sealbin Worker (#7): starts `wrangler dev
# --local` against a throwaway persistence directory with a random
# HARNESS_SECRET and checks the routes issue #7 owns.
#
# Nothing here touches a Cloudflare account: `--local` and `--persist-to` keep
# every byte on this machine, and the temp directory is removed on exit.
#
# Needs: bash, curl, node, openssl, wrangler (or npx) and a built bundle
# (`worker-build --release`, run here if `build/worker/shim.mjs` is missing).
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
worker_dir=$(cd "$script_dir/.." && pwd)
repo_root=$(cd "$worker_dir/../.." && pwd)

WRANGLER=${WRANGLER:-wrangler}
command -v "$WRANGLER" >/dev/null 2>&1 || WRANGLER="npx --yes wrangler@4"
command -v node >/dev/null || { echo "smoke: node is required" >&2; exit 1; }
command -v openssl >/dev/null || { echo "smoke: openssl is required" >&2; exit 1; }

fail() {
  echo "smoke: FAIL: $*" >&2
  exit 1
}

# --- scratch state ---------------------------------------------------------

tmp=$(mktemp -d)
persist=$(mktemp -d)
port=$(( 20000 + RANDOM % 20000 ))
dev_pid=""

# The secret is random per run and never printed. `wrangler` may echo a var it
# was given, so any log tail shown on failure is redacted first.
secret=$(openssl rand -hex 32)

cleanup() {
  status=$?
  if [ -n "$dev_pid" ]; then
    kill -TERM "-$dev_pid" 2>/dev/null || kill -TERM "$dev_pid" 2>/dev/null || true
    wait "$dev_pid" 2>/dev/null || true
  fi
  rm -rf "$tmp" "$persist"
  exit "$status"
}
trap cleanup EXIT

# --- bundle and assets -----------------------------------------------------

"$repo_root/web/build.sh" >/dev/null

if [ ! -f "$worker_dir/build/worker/shim.mjs" ]; then
  echo "smoke: building the Worker bundle (worker-build --release)"
  ( cd "$worker_dir" && worker-build --release )
fi

# --- local D1 --------------------------------------------------------------

( cd "$worker_dir" && $WRANGLER d1 migrations apply DB --local --persist-to "$persist" ) \
  >"$tmp/migrations.log" 2>&1 \
  || { cat "$tmp/migrations.log" >&2; fail "d1 migrations apply failed"; }

# --- the dev server --------------------------------------------------------

api_url="http://127.0.0.1:$port"
( cd "$worker_dir" && exec setsid $WRANGLER dev --local --ip 127.0.0.1 --port "$port" \
    --persist-to "$persist" \
    --var "HARNESS_SECRET:$secret" \
    --var "SEALBIN_API_URL:$api_url" \
    --var "ENV:development" ) >"$tmp/wrangler.log" 2>&1 &
dev_pid=$!

code=""
for _ in $(seq 1 120); do
  code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/__health" || true)
  [ "$code" = "200" ] && break
  sleep 1
done
if [ "$code" != "200" ]; then
  sed "s/$secret/REDACTED/g" "$tmp/wrangler.log" | tail -30 >&2
  fail "the dev server never answered 200 on /__health (last: ${code:-none})"
fi

# --- checks ----------------------------------------------------------------

check_status() { # url expected label
  got=$(curl -s -o /dev/null -w '%{http_code}' "$1" || true)
  [ "$got" = "$2" ] || fail "$3: GET $1 expected $2, got ${got:-none}"
}

# The harness, not the Worker's page branch.
check_status "http://127.0.0.1:$port/__health" 200 "/__health"

# The discovery document the CLI resolves the API from (D3).
well_known=$(curl -s -D "$tmp/well-known.headers" -o "$tmp/well-known.json" \
  -w '%{http_code}' "http://127.0.0.1:$port/.well-known/sealbin" || true)
[ "$well_known" = "200" ] || fail "/.well-known/sealbin expected 200, got ${well_known:-none}"

grep -qi '^cache-control:.*max-age=3600' "$tmp/well-known.headers" \
  || fail "/.well-known/sealbin cache-control missing max-age=3600"

node -e '
const fs = require("fs");
const [file, want] = process.argv.slice(1);
const doc = JSON.parse(fs.readFileSync(file, "utf8"));
if (doc.api !== want) throw new Error(`api ${JSON.stringify(doc.api)} !== ${JSON.stringify(want)}`);
if (JSON.stringify(doc.formats) !== "[1]") throw new Error(`formats ${JSON.stringify(doc.formats)} !== [1]`);
' "$tmp/well-known.json" "$api_url" \
  || fail "/.well-known/sealbin body is not the expected document"

# The two asset routes: HTML from the ASSETS binding, and — the point of the
# test — no `x-request-id`, which the harness scope layer adds to everything
# it serves. Its absence proves the harness router was never reached.
check_page() { # path label
  code=$(curl -s -D "$tmp/page.headers" -o "$tmp/page.html" \
    -w '%{http_code}' "http://127.0.0.1:$port$1" || true)
  [ "$code" = "200" ] || fail "$2: GET $1 expected 200, got ${code:-none}"
  grep -qi '^content-type: *text/html' "$tmp/page.headers" \
    || fail "$2: GET $1 content-type is not text/html"
  if grep -qi '^x-request-id:' "$tmp/page.headers"; then
    fail "$2: GET $1 carries x-request-id — the harness served it, not the assets binding"
  fi
  grep -qi '<html' "$tmp/page.html" || fail "$2: GET $1 body is not HTML"
}
check_page "/s/abc" "/s/*"
check_page "/activate" "/activate"

# Anything else reaches the harness.
v1=$(curl -s -D "$tmp/v1.headers" -o "$tmp/v1.body" \
  -w '%{http_code}' "http://127.0.0.1:$port/v1/x" || true)
[ "$v1" = "404" ] || fail "/v1/x expected 404, got ${v1:-none}"
v1_type=$(grep -i '^content-type:' "$tmp/v1.headers" | tr -d '\r' || true)
echo "smoke: /v1/x 404 content-type: ${v1_type:-<none>}"

echo "smoke: OK (port $port)"
