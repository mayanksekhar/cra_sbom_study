#!/usr/bin/env bash
# usage: replicate_cdxgen.sh <cdxgen version> <workdir>
# Runs an older cdxgen on fresh copies of the npm and Rust sets, as gen_set.sh does.
set -u
V="$1"; W="$2"
root="$(cd "$(dirname "$0")/.." && pwd)"
P="$W/cdxgen_$V"; BIN="$P/node_modules/.bin/cdxgen"
export TMPDIR="$W/tmp"
mkdir -p "$TMPDIR" "$W/work"

run_set() {
  eco="$1"; t="$2"; csv="$3"; src="$4"; out="$W/out_$V/$eco"; mkdir -p "$out"
  tail -n +2 "$csv" | while IFS=, read -r name rest; do
    echo "== $name ($eco)"
    rm -rf "$W/work/$name"; cp -a "$src/$name" "$W/work/$name"
    git -C "$W/work/$name" clean -xfdq; git -C "$W/work/$name" checkout -q -- .
    ( cd "$P" && timeout 900 systemd-run --user --scope -q -p MemoryMax=6G -p MemorySwapMax=0 "$BIN" --spec-version 1.6 -t "$t" -o "$out/${name}_cdxgen.cdx.json" "$W/work/$name" < /dev/null > "$out/${name}_cdxgen.log" 2>&1 ) || echo "cdxgen failed: $name"
  done
}

if cd "$root"; then
  if [ ! -x "$BIN" ]; then npm install --prefix "$P" --no-audit --no-fund "@cyclonedx/cdxgen@$V" > "$W/install_$V.log" 2>&1; fi
  if [ ! -x "$BIN" ]; then
    echo "install failed, see $W/install_$V.log"
  else
    echo "cdxgen version reported: $("$BIN" --version 2>&1 | head -1)"
    run_set npm js dataset/npm_set.csv dataset/src_npm
    run_set rust rust dataset/rust_set.csv dataset/src_rust
  fi
fi
