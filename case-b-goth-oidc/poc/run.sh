#!/bin/sh
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="${SRC_DIR:-$HERE/../repo}"
OUT="${OUT:-$HERE/../out}"
OFFLINE="${OFFLINE-}"
MODE="${1:-baseline}"
mkdir -p "$OUT"

# Build the consumer once; the control arm reuses the artifact under $OUT.
if [ ! -x "$OUT/poc" ]; then
  export GOFLAGS=-mod=mod GOCACHE="${GOCACHE:-$OUT/gocache}"
  # Consumer module in poc/ with a replace pointing at the checkout; the build
  # uses a copy of go.mod under $OUT so go.sum lands there and poc/ is unchanged.
  sed "s#=> ../repo#=> $(cd "$SRC_DIR" && pwd)#" "$HERE/go.mod" > "$OUT/go.mod"
  (cd "$HERE" && go build -modfile="$OUT/go.mod" -o "$OUT/poc" .)
fi

echo "built $OUT/poc sha256 $(sha256sum "$OUT/poc" | cut -d' ' -f1)"

"$OUT/poc" "$MODE"
