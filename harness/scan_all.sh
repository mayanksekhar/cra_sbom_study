#!/usr/bin/env bash
set -u
export PATH="$PATH:$HOME/go/bin"
root="$(cd "$(dirname "$0")/.." && pwd)"
source "$root/harness/env_frozen.sh"
cd "$root"
scan() {
  local f="$1" out="$2" stem="$3"; mkdir -p "$out"
  grype "sbom:$f" -o json -q > "$out/${stem}_grype.json" 2> "$out/${stem}_grype.err" || echo "grype failed: $stem"
  trivy sbom --cache-dir "$SNAP/trivy" --skip-db-update --skip-java-db-update --scanners vuln --format json --output "$out/${stem}_trivy.json" -q "$f" 2> "$out/${stem}_trivy.err" || echo "trivy failed: $stem"
  XDG_CACHE_HOME="$OSV_CACHE" osv-scanner scan source --offline-vulnerabilities --sbom "$f" --format json > "$out/${stem}_osv.json" 2> "$out/${stem}_osv.err" || true
  [ -s "$out/${stem}_osv.json" ] || echo "osv produced no output: $stem"
}
for f in results/raw/*/*.cdx.json; do
  scan "$f" "results/vulns/$(basename "$(dirname "$f")")" "$(basename "$f" .cdx.json)"
done
for f in results/reference/*/*.cdx.json; do
  scan "$f" "results/vulns_ref/$(basename "$(dirname "$f")")" "$(basename "$f" .cdx.json)"
done
echo "== snapshot integrity (all snapshots)"
for m in tools/dbsnap_*.txt; do grep -E '^[0-9a-f]{64}' "$m" | sha256sum -c - | grep -v ': OK$' || echo "$m: all checksums OK"; done
