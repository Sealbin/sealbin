#!/usr/bin/env bash
# Builds web/dist/, the directory the Worker's `ASSETS` binding serves
# (crates/sealbin-worker/wrangler.toml). No bundler yet: the pages are vanilla
# HTML and will stay that way (D1), so this only copies.
set -euo pipefail

cd "$(dirname "$0")"
out=dist

rm -rf "$out"
mkdir -p "$out"

# Everything but the build output itself, this script and the README.
while IFS= read -r -d '' file; do
  rel="${file#./}"
  case "$rel" in
    dist/* | build.sh | README.md) continue ;;
  esac
  mkdir -p "$out/$(dirname "$rel")"
  cp "$rel" "$out/$rel"
done < <(find . -type f -print0)

echo "web/dist built:"
find "$out" -type f | sort
