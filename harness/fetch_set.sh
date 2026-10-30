#!/usr/bin/env bash
# usage: fetch_set.sh <csv> <src dir> <pinned csv>
set -u
cd "$(dirname "$0")/.."
CSV="$1"; SRC="$2"; OUT="$3"
mkdir -p "$SRC"
echo "name,ecosystem,repo_url,kind,tag,commit_sha" > "$OUT"
tail -n +2 "$CSV" | while IFS=, read -r name eco url kind tag; do
  d="$SRC/$name"
  [ -d "$d" ] || git clone -q --depth 1 --branch "$tag" "$url" "$d" 2>&1 | tail -n 1
  sha=$(git -C "$d" rev-parse HEAD 2>/dev/null || echo MISSING)
  echo "$name,$eco,$url,$kind,$tag,$sha" >> "$OUT"
  printf '%-18s %-10s %-12s %s\n' "$name" "$tag" "${sha:0:10}" "$(grep -m1 '^go ' "$d/go.mod" 2>/dev/null)"
done
