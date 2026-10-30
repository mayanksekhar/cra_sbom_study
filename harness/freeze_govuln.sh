#!/usr/bin/env bash
set -eu
root="$(cd "$(dirname "$0")/.." && pwd)"
g="$root/vulndb/${STAMP:-20261030}/govuln"
rm -f "$g/modules.json_check"
mkdir -p "$g/index" "$g/ID"
for f in db.json modules.json vulns.json; do
  curl -fsSL -o "$g/index/$f" "https://vuln.go.dev/index/$f" || echo "not available: $f"
done
n=$(jq 'length' "$g/index/vulns.json")
echo "entries: $n"
[ "$n" -lt 30000 ] || { echo "too many entries, stopping"; exit 1; }
jq -r '.[].id' "$g/index/vulns.json" | xargs -P 8 -I{} curl -fsSL -o "$g/ID/{}.json" "https://vuln.go.dev/ID/{}.json" || echo "some downloads failed"
echo "files: $(ls "$g/ID" | wc -l)"
du -sh "$g"
( cd "$g" && find . -type f | sort | xargs sha256sum ) > "$root/tools/govuln_${STAMP:-20261030}.sha256"
cat "$g/index/db.json"; echo
