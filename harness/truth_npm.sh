#!/usr/bin/env bash
set -eu
root="$(cd "$(dirname "$0")/.." && pwd)"
gt="$root/groundtruth/npm"; mkdir -p "$gt"
{ node --version; npm --version; } > "$gt/_tooling.txt"
for name in express axios; do
  cd "$root/dataset/src/$name"
  if [ -f package-lock.json ]; then
    echo committed > "$gt/${name}_lockfile.txt"
  else
    npm install --package-lock-only --ignore-scripts --no-audit --no-fund > /dev/null
    echo generated > "$gt/${name}_lockfile.txt"
  fi
  jq -r '.name | ascii_downcase' package.json > "$gt/${name}_mainmodule.txt"
  jq -r '.packages | to_entries[] | select(.key != "" and .value.version != null) | "pkg:npm/" + (.key | sub("^.*node_modules/"; "")) + "@" + .value.version' package-lock.json | sort -u > "$gt/${name}_all.txt"
  jq -r '.packages | to_entries[] | select(.key != "" and .value.version != null and .value.dev != true) | "pkg:npm/" + (.key | sub("^.*node_modules/"; "")) + "@" + .value.version' package-lock.json | sort -u > "$gt/${name}_shipped.txt"
  date -u +%Y%m%dT%H%M%SZ > "$gt/${name}_resolved_at.txt"
done
wc -l "$gt"/*_all.txt "$gt"/*_shipped.txt; cat "$gt"/*_mainmodule.txt "$gt"/*_lockfile.txt
