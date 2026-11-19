#!/usr/bin/env bash
# usage: replicate_grype.sh <grype version without v> <workdir> [npm_rust|go_mvn_py|pilot|pilot_old]   (default npm_rust)
# Rescans the npm and Rust SBOMs (generator and reference) with an older Grype and the frozen database.
set -u
V="$1"; W="$2"
root="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$W/oldgrype/$V/grype"
if cd "$root"; then
  source harness/env_frozen.sh
  if [ ! -x "$BIN" ]; then bash harness/fetch_old_grype.sh "$V" "$W/oldgrype"; fi
  case "${3:-npm_rust}" in
    go_mvn_py) pairs="go:results_go maven:results_mvn pypi:results_py";;
    pilot) OUTTAG=_pilot; pairs="npm:results go:results maven:results pypi:results rust:results";;
    pilot_old) OUTTAG=_pilot_old; pairs="npm:results_old go:results_old maven:results_old rust:results_old";;
    *) pairs="npm:results_npm rust:results_rust";;
  esac
  for pair in $pairs; do
    eco="${pair%%:*}"; res="${pair##*:}"; out="$W/out_grype_$V${OUTTAG:-}/$eco"; mkdir -p "$out"
    for f in "$res"/raw/$eco/*.cdx.json "$res"/reference/$eco/*.cdx.json; do
      stem="$(basename "$f" .cdx.json)"
      "$BIN" "sbom:$f" -o json -q > "$out/${stem}_grype.json" 2> "$out/${stem}_grype.err" || echo "grype failed: $stem"
    done
  done
  echo "scans written: $(ls "$W/out_grype_$V${OUTTAG:-}"/*/*_grype.json | wc -l)"
fi
