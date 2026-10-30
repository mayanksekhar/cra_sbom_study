#!/usr/bin/env bash
set -eu
unset GRYPE_DB_CACHE_DIR GRYPE_DB_AUTO_UPDATE GRYPE_DB_VALIDATE_AGE GRYPE_CHECK_FOR_APP_UPDATE
export PATH="$PATH:$HOME/go/bin"
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
stamp="$(date -u +%Y%m%d)"
snap="$root/vulndb/$stamp"
meta="$root/tools/dbsnap_$stamp.txt"
cache="${XDG_CACHE_HOME:-$HOME/.cache}"
mkdir -p "$snap/grype" "$snap/trivy" "$snap/osv"
grype db update
trivy image --download-db-only -q
trivy image --download-java-db-only -q
cp -a "$cache/grype/db/." "$snap/grype/"
cp -a "$cache/trivy/db" "$snap/trivy/db"
cp -a "$cache/trivy/java-db" "$snap/trivy/java-db"
for f in results/reference/*/*.cdx.json results/raw/go/cobra_syft.cdx.json; do
  XDG_CACHE_HOME="$snap/osv" osv-scanner scan source --download-offline-databases --offline-vulnerabilities --sbom "$f" > /dev/null 2>&1 || true
done
{
  echo "frozen_at_utc: $(date -u +%Y%m%dT%H%M%SZ)"
  echo "== grype db status"; GRYPE_DB_CACHE_DIR="$snap/grype" grype db status 2>&1
  echo "== trivy db metadata"; cat "$snap/trivy/db/metadata.json"; echo
  echo "== trivy java db metadata"; cat "$snap/trivy/java-db/metadata.json"; echo
  echo "== osv databases"; find "$snap/osv" -name all.zip | sort
  echo "== sha256"; find "$snap" -type f \( -name '*.db' -o -name all.zip \) -exec sha256sum {} \;
} | tee "$meta"
du -sh "$snap"
