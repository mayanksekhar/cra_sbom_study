#!/usr/bin/env bash
set -eu
export PATH="$PATH:$HOME/go/bin"
root="$(cd "$(dirname "$0")/.." && pwd)"
stamp="$(date -u +%Y%m%d)"
snap="$root/vulndb/$stamp"
meta="$root/tools/dbsnap_$stamp.txt"
cache="${XDG_CACHE_HOME:-$HOME/.cache}"
df -h "$root" | tail -n 1
mkdir -p "$snap/grype" "$snap/trivy"
grype db update
trivy image --download-db-only -q
trivy image --download-java-db-only -q
cp -a "$cache/grype/db/." "$snap/grype/"
cp -a "$cache/trivy/db" "$snap/trivy/db"
cp -a "$cache/trivy/java-db" "$snap/trivy/java-db"
{
  echo "frozen_at_utc: $(date -u +%Y%m%dT%H%M%SZ)"
  echo "== grype db status"; grype db status 2>&1
  echo "== trivy db metadata"; cat "$snap/trivy/db/metadata.json"
  echo "== trivy java db metadata"; cat "$snap/trivy/java-db/metadata.json"
  echo "== sha256"; find "$snap" -type f -name '*.db' -exec sha256sum {} \;
} | tee "$meta"
du -sh "$snap"
