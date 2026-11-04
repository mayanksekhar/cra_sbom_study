#!/usr/bin/env bash
# usage: fetch_set.sh <csv> <src dir> <pinned csv>   (tag column may hold a 40 char commit hash)
set -u
cd "$(dirname "$0")/.."
CSV="$1"; SRC="$2"; OUT="$3"
mkdir -p "$SRC"
echo "name,ecosystem,repo_url,kind,tag,commit_sha" > "$OUT"
tail -n +2 "$CSV" | while IFS=, read -r name eco url kind tag; do
  d="$SRC/$name"
  if [ ! -d "$d" ]; then
    if [[ "$tag" =~ ^[0-9a-f]{40}$ ]]; then
      git init -q "$d" && git -C "$d" remote add origin "$url" && git -C "$d" fetch -q --depth 1 origin "$tag" && git -C "$d" checkout -q FETCH_HEAD || echo "fetch by hash failed: $name"
    else
      git clone -q --depth 1 --branch "$tag" "$url" "$d" 2>&1 | tail -n 1
    fi
  fi
  sha=$(git -C "$d" rev-parse HEAD 2>/dev/null || echo MISSING)
  echo "$name,$eco,$url,$kind,$tag,$sha" >> "$OUT"
  printf '%-24s %-28s %s  %s\n' "$name" "${tag:0:28}" "${sha:0:10}" "$(ls "$d" | grep -E '^(pom.xml|go.mod|package-lock.json|Cargo.lock)$' | tr '\n' ' ')"
done
