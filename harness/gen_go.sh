#!/usr/bin/env bash
set -eu
export PATH="$PATH:$HOME/go/bin"
root="$(cd "$(dirname "$0")/.." && pwd)"
out="$root/results/raw/go"
mkdir -p "$out"
for name in cobra node_exporter; do
  src="$root/dataset/src/$name"
  syft scan "dir:$src" -o "cyclonedx-json=$out/${name}_syft.cdx.json" -q
  trivy fs --skip-db-update --skip-java-db-update --format cyclonedx --output "$out/${name}_trivy.cdx.json" -q "$src"
  (cd "$root/tools" && npx cdxgen -t golang -o "$out/${name}_cdxgen.cdx.json" "$src")
done
ls -l "$out"
