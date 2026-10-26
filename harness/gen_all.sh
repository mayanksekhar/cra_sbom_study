#!/usr/bin/env bash
set -u
export PATH="$PATH:$HOME/go/bin"
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
tail -n +2 dataset/pilot_pinned.csv | while IFS=, read -r name eco url kind sha; do
  [ "$eco" = "go" ] && continue
  src="$root/dataset/src/$name"
  out="$root/results/raw/$eco"; mkdir -p "$out"
  case "$eco" in maven) t=java;; npm) t=js;; pypi) t=py;; rust) t=rust;; esac
  echo "== $name ($eco)"
  syft scan "dir:$src" -o "cyclonedx-json=$out/${name}_syft.cdx.json" -q < /dev/null
  trivy fs --skip-db-update --skip-java-db-update --format cyclonedx --output "$out/${name}_trivy.cdx.json" -q "$src" < /dev/null
  (cd "$root/tools" && timeout 900 npx cdxgen -t "$t" -o "$out/${name}_cdxgen.cdx.json" "$src" < /dev/null > "$out/${name}_cdxgen.log" 2>&1) || echo "cdxgen failed or timed out for $name"
done
echo; echo "== purl type census"
for f in results/raw/*/*.cdx.json; do
  printf '%s: ' "${f#results/raw/}"
  jq -r '[.components[]?.purl // empty | split(":")[1] | split("/")[0]] | group_by(.) | map("\(.[0])=\(length)") | join(" ")' "$f"
done
