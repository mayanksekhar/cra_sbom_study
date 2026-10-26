#!/usr/bin/env bash
set -u
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
mkdir -p results/raw_cdx17
run() {
  local name="$1" eco="$2" t="$3" src="$4" out="$root/results/raw/$2"
  [ -f "$out/${name}_cdxgen.cdx.json" ] && mv "$out/${name}_cdxgen.cdx.json" "$root/results/raw_cdx17/${eco}_${name}_cdxgen.cdx.json"
  (cd "$root/tools" && timeout 900 npx cdxgen --spec-version 1.6 -t "$t" -o "$out/${name}_cdxgen.cdx.json" "$src" < /dev/null > "$out/${name}_cdxgen.log" 2>&1) || echo "cdxgen failed: $name"
}
tail -n +2 dataset/pilot_pinned.csv | while IFS=, read -r name eco url kind sha; do
  case "$eco" in go) t=golang;; maven) t=java;; npm) t=js;; pypi) t=py;; rust) t=rust;; esac
  run "$name" "$eco" "$t" "$root/dataset/src/$name"
done
run express_nolock npm js "$root/dataset/src_nolock/express"
printf '%-28s %6s %6s %5s\n' sbom old new spec
for f in results/raw_cdx17/*.cdx.json; do
  b="$(basename "$f")"; eco="${b%%_*}"; n="${b#*_}"; new="results/raw/$eco/$n"
  printf '%-28s %6s %6s %5s\n' "${n%_cdxgen.cdx.json}" "$(jq '[.components[]?.purl // empty] | length' "$f")" "$(jq '[.components[]?.purl // empty] | length' "$new")" "$(jq -r .specVersion "$new")"
done
