#!/usr/bin/env bash
set -eu
root="$(cd "$(dirname "$0")/.." && pwd)"
gt="$root/groundtruth/rust"; mkdir -p "$gt"
cargo --version > "$gt/_tooling.txt" 2>&1; rustc --version >> "$gt/_tooling.txt" 2>&1
tree() { cargo tree --workspace --locked --target all --prefix none -f '{p}' "$@" 2>&1; }
for name in ripgrep fd; do
  cd "$root/dataset/src/$name"
  tree -e normal,build,dev > /tmp/${name}_rs_all.txt
  tree -e normal > /tmp/${name}_rs_shipped.txt
  grep -F '(/' /tmp/${name}_rs_all.txt | awk '{print tolower($1)}' | sort -u > "$gt/${name}_mainmodule.txt"
  for kind in all shipped; do
    grep -vF '(/' /tmp/${name}_rs_${kind}.txt | awk 'NF>=2 && $1 !~ /^\[/ && $2 ~ /^v[0-9]/ {print "pkg:cargo/"$1"@"substr($2,2)}' | sort -u > "$gt/${name}_${kind}.txt"
  done
  date -u +%Y%m%dT%H%M%SZ > "$gt/${name}_resolved_at.txt"
done
wc -l "$gt"/*_all.txt "$gt"/*_shipped.txt; cat "$gt"/*_mainmodule.txt
