#!/usr/bin/env bash
# usage: scan_set.sh <suffix>   (for example _old)
set -u
export PATH="$PATH:$HOME/go/bin"
root="$(cd "$(dirname "$0")/.." && pwd)"
source "$root/harness/env_frozen.sh"
cd "$root"
R="results$1"
strip() { python3 - "$1" "$2" << 'PY'
import json, sys
def clean(cs):
    out = []
    for c in cs or []:
        if (c.get("purl") or "").startswith("pkg:github/"):
            continue
        if c.get("components"):
            c["components"] = clean(c["components"])
        out.append(c)
    return out
d = json.load(open(sys.argv[1]))
d["components"] = clean(d.get("components"))
mc = (d.get("metadata") or {}).get("component")
if mc and mc.get("components"):
    mc["components"] = clean(mc["components"])
json.dump(d, open(sys.argv[2], "w"))
PY
}
scan() {
  local f="$1" out="$2" stem="$3"; mkdir -p "$out" /tmp/cra_osv
  grype "sbom:$f" -o json -q > "$out/${stem}_grype.json" 2> "$out/${stem}_grype.err" || echo "grype failed: $stem"
  trivy sbom --cache-dir "$SNAP/trivy" --skip-db-update --skip-java-db-update --scanners vuln --format json --output "$out/${stem}_trivy.json" -q "$f" 2> "$out/${stem}_trivy.err" || echo "trivy failed: $stem"
  strip "$f" "/tmp/cra_osv/$stem.cdx.json"
  XDG_CACHE_HOME="$OSV_CACHE" osv-scanner scan source --offline-vulnerabilities --sbom "/tmp/cra_osv/$stem.cdx.json" --format json > "$out/${stem}_osv.json" 2> "$out/${stem}_osv.err" || true
  [ -s "$out/${stem}_osv.json" ] || echo "osv produced no output: $stem"
}
for f in "$R"/raw/*/*.cdx.json; do scan "$f" "$R/vulns/$(basename "$(dirname "$f")")" "$(basename "$f" .cdx.json)"; done
for f in "$R"/reference/*/*.cdx.json; do scan "$f" "$R/vulns_ref/$(basename "$(dirname "$f")")" "$(basename "$f" .cdx.json)"; done
echo "== snapshot integrity"
for m in tools/dbsnap_*.txt; do grep -E '^[0-9a-f]{64}' "$m" | sha256sum -c - | grep -v ': OK$' || echo "$m: all checksums OK"; done
