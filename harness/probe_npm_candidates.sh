#!/usr/bin/env bash
# usage: probe_npm_candidates.sh <candidates csv> <workdir>
# Finds the highest stable tag of each candidate and whether package-lock.json is committed there.
set -u
CSV="$1"; W="$2"
export TMPDIR="$W/tmp"; mkdir -p "$TMPDIR" "$W/probe"
echo "name,kind,repo_url,tag,commit_sha,lock,lockfile_version,lock_packages"
tail -n +2 "$CSV" | while IFS=, read -r name eco url kind; do
  tag=$(git ls-remote --tags --refs "$url" 2>/dev/null | awk '{print $2}' | sed 's#refs/tags/##' | grep -E '^v?[0-9]+\.[0-9]+\.[0-9]+$' | awk '{v=$0; sub(/^v/,"",v); print v" "$0}' | sort -V -k1,1 | tail -1 | awk '{print $2}')
  if [ -z "$tag" ]; then echo "$name,$kind,$url,NONE,NONE,no stable tag,0,0"; continue; fi
  d="$W/probe/$name"; rm -rf "$d"
  if git clone -q --depth 1 --branch "$tag" "$url" "$d" > /dev/null 2>&1; then
    sha=$(git -C "$d" rev-parse HEAD)
    if [ -f "$d/package-lock.json" ]; then n=$(jq '(.packages // {}) | length' "$d/package-lock.json" 2>/dev/null || echo 0); lv=$(jq '.lockfileVersion' "$d/package-lock.json" 2>/dev/null || echo 0); echo "$name,$kind,$url,$tag,$sha,yes,$lv,$n"
    else echo "$name,$kind,$url,$tag,$sha,no,0,0"; fi
  else
    echo "$name,$kind,$url,$tag,NONE,clone failed,0,0"
  fi
  rm -rf "$d"
done
