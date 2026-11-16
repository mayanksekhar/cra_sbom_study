#!/usr/bin/env bash
# usage: replicate_syft_go_grype.sh OUT WORKDIR
# OUT is the folder written by replicate_syft_trivy.sh. Scans the old and the pinned Syft SBOMs of the Go set with the pinned Grype.
set -u
root="$(cd "$(dirname "$0")/.." && pwd)"; cd "$root"
source harness/env_frozen.sh
OUT="$1"; W="$2/grype_syft_go"; mkdir -p "$W/old" "$W/new"
echo "grype: $(grype version 2>/dev/null | head -1)"
for ver in old new; do
  for f in "$OUT/$ver/syft/go"/*.cdx.json; do
    n="$(basename "$f" .cdx.json)"
    grype "sbom:$f" -o json -q > "$W/$ver/${n}_grype.json" 2> "$W/$ver/${n}_grype.err" || echo "grype failed: $ver $n"
  done
done
echo "scanned: old $(ls "$W/old"/*_grype.json | wc -l), new $(ls "$W/new"/*_grype.json | wc -l)"
