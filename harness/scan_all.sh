#!/usr/bin/env bash
set -u
export PATH="$PATH:$HOME/go/bin"
root="$(cd "$(dirname "$0")/.." && pwd)"
source "$root/harness/env_frozen.sh"
cd "$root"
for f in results/raw/*/*.cdx.json; do
  eco="$(basename "$(dirname "$f")")"; stem="$(basename "$f" .cdx.json)"
  out="results/vulns/$eco"; mkdir -p "$out"
  grype "sbom:$f" -o json -q > "$out/${stem}_grype.json" 2> "$out/${stem}_grype.err" || echo "grype failed: $stem"
  trivy sbom --cache-dir "$SNAP/trivy" --skip-db-update --skip-java-db-update --scanners vuln --format json --output "$out/${stem}_trivy.json" -q "$f" 2> "$out/${stem}_trivy.err" || echo "trivy failed: $stem"
done
echo "== snapshot integrity"
grep -E '^[0-9a-f]{64}' tools/dbsnap_20261026.txt | sha256sum -c -
grype db status | head -n 4
