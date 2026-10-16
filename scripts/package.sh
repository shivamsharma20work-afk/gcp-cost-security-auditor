#!/usr/bin/env bash
# Build the Cloud Functions source folder: build/function/
#   main.py           <- entry point the Functions runtime looks for
#   auditor/          <- our package
#   requirements.txt  <- pinned from uv.lock (runtime deps only)
set -euo pipefail
cd "$(dirname "$0")/.."

OUT=build/function
rm -rf "$OUT" && mkdir -p "$OUT"
cp -r src/auditor "$OUT/"
find "$OUT" -name '__pycache__' -prune -exec rm -rf {} +
printf 'from auditor.main import run_audit  # noqa: F401\n' > "$OUT/main.py"
uv export --frozen --no-dev --no-emit-project --no-hashes -q -o "$OUT/requirements.txt"
echo "Packaged -> $OUT"
