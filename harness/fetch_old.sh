#!/usr/bin/env bash
set -u
cd "$(dirname "$0")/.."
mkdir -p dataset/src_old
echo "name,ecosystem,repo_url,kind,tag,commit_sha" > dataset/pilot_old_pinned.csv
tail -n +2 dataset/pilot_old.csv | while IFS=, read -r name eco url kind tag; do
  d="dataset/src_old/$name"
  [ -d "$d" ] || git clone -q --depth 1 --branch "$tag" "$url" "$d" 2>&1 | tail -n 1
  sha=$(git -C "$d" rev-parse HEAD 2>/dev/null || echo MISSING)
  echo "$name,$eco,$url,$kind,$tag,$sha" >> dataset/pilot_old_pinned.csv
  printf '%-14s %-24s %s\n' "$name" "$tag" "${sha:0:10}"
  find "$d" \( -name go.sum -o -name package-lock.json -o -name Cargo.lock -o -name pom.xml -o -name uv.lock \) -not -path '*/node_modules/*' | sed "s|^$d/|     |" | head -n 8
done
