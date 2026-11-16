#!/usr/bin/env bash
# usage: replicate_grype.sh <grype version without v> <workdir>
# Rescans the npm and Rust SBOMs (generator and reference) with an older Grype and the frozen database.
set -u
V="$1"; W="$2"
root="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$W/oldgrype/$V/grype"
if cd "$root"; then
  source harness/env_frozen.sh
  if [ ! -x "$BIN" ]; then bash harness/fetch_old_grype.sh "$V" "$W/oldgrype"; fi
  for pair in npm:results_npm rust:results_rust; do
    eco="${pair%%:*}"; res="${pair##*:}"; out="$W/out_grype_$V/$eco"; mkdir -p "$out"
    for f in "$res"/raw/$eco/*.cdx.json "$res"/reference/$eco/*.cdx.json; do
      stem="$(basename "$f" .cdx.json)"
      "$BIN" "sbom:$f" -o json -q > "$out/${stem}_grype.json" 2> "$out/${stem}_grype.err" || echo "grype failed: $stem"
    done
  done
  echo "scans written: $(ls "$W/out_grype_$V"/*/*_grype.json | wc -l)"
fi
