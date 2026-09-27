#!/usr/bin/env bash
# build.sh — build gonidbg (pure-Go variant: the unicorn engine loads the stock
# libunicorn at runtime via purego; no cgo, no C compiler).
#
# Runtime dependency: libunicorn on the target machine (brew install unicorn /
# apt install libunicorn2), locatable via $GOLEM_UNICORN or the loader path.
#
# Usage:
#   ./build.sh                 # -> ./bin/{gonidbg,elfscan,loadplan}
#   OUT=dist ./build.sh
set -euo pipefail
cd "$(dirname "$0")"
OUT="${OUT:-bin}"
mkdir -p "$OUT"

command -v go >/dev/null || { echo "need 'go' in PATH"; exit 1; }

echo "[build] gonidbg  (CLI, unicorn engine via purego, -tags unicorn)"
CGO_ENABLED=0 go build -tags unicorn -o "$OUT/gonidbg" ./cmd/gonidbg

echo "[build] elfscan / loadplan  (pure-Go analysis tools)"
CGO_ENABLED=0 go build -o "$OUT/elfscan"  ./cmd/elfscan
CGO_ENABLED=0 go build -o "$OUT/loadplan" ./cmd/loadplan

echo "[build] done -> $OUT/"
echo "        run with: GOLEM_UNICORN=/path/to/libunicorn.dylib $OUT/gonidbg ..."
