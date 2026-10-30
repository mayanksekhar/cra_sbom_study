#!/usr/bin/env bash
# usage: gen_set.sh <src dir> <csv> <results dir>
set -u
export PATH="$PATH:$HOME/go/bin"
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
SRC="$1"; CSV="$2"; R="$3"
work=/tmp/cra_work; rm -rf "$work"; mkdir -p "$work"
fresh() { rm -rf "$work/$1"; cp -a "$SRC/$1" "$work/$1"; git -C "$work/$1" clean -xfdq; git -C "$work/$1" checkout -q -- .; }
tail -n +2 "$CSV" | while IFS=, read -r name eco url kind tag sha; do
  case "$eco" in go) t=golang;; maven) t=java;; npm) t=js;; pypi) t=py;; rust) t=rust;; esac
  out="$R/raw/$eco"; mkdir -p "$out"; echo "== $name ($eco)"
  fresh "$name"; syft scan "dir:$work/$name" -o "cyclonedx-json=$out/${name}_syft.cdx.json" -q < /dev/null
  fresh "$name"; trivy fs --skip-db-update --skip-java-db-update --format cyclonedx --output "$out/${name}_trivy.cdx.json" -q "$work/$name" < /dev/null
  fresh "$name"; (cd "$root/tools" && timeout 900 npx cdxgen --spec-version 1.6 -t "$t" -o "$root/$out/${name}_cdxgen.cdx.json" "$work/$name" < /dev/null > "$root/$out/${name}_cdxgen.log" 2>&1) || echo "cdxgen failed: $name"
done
printf '\n%-28s %6s\n' sbom components
for f in "$R"/raw/*/*.cdx.json; do printf '%-28s %6s\n' "$(basename "$f" .cdx.json)" "$(jq '[.components[]?.purl // empty] | length' "$f")"; done
