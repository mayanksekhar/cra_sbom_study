#!/usr/bin/env bash
# usage: replicate_syft_trivy.sh OLDTOOLS OUT [npm_rust|go|maven|pypi|pilot|pilot_old]   (default npm_rust)
# Runs Syft 1.33.0 and Trivy 0.66.0 (from fetch_old_syft_trivy.sh) and the pinned Syft and Trivy on the
# same fresh copies of the npm and Rust projects, with the arguments of gen_set.sh.
set -u
export PATH="$PATH:$HOME/go/bin"
root="$(cd "$(dirname "$0")/.." && pwd)"; cd "$root"
OLD="$1"; OUT="$2"
work="${CRA_WORK:-/tmp/cra_work_old}"
OSYFT="$OLD/syft_1.33.0/syft"; OTRIVY="$OLD/trivy_0.66.0"
export SYFT_CHECK_FOR_APP_UPDATE=false
echo "== versions"
"$OSYFT" --version | head -1; syft --version | head -1
"$OTRIVY" --version | head -1; trivy --version | head -1
mkdir -p "$OUT"
fresh() { rm -rf "$work/$1"; cp -a "$2/$1" "$work/$1"; git -C "$work/$1" clean -xfdq; git -C "$work/$1" checkout -q -- .; }
run_one() {
  local name="$1" eco="$2" src="$3" gen="$4" tool="$5" bin="$6" f="$OUT/$4/$5/$2/$1.cdx.json"
  mkdir -p "$(dirname "$f")"; fresh "$name" "$src"
  if [ "$tool" = syft ]; then "$bin" scan "dir:$work/$name" -o "cyclonedx-json=$f" -q < /dev/null
  else "$bin" fs --skip-db-update --skip-java-db-update --format cyclonedx --output "$f" -q "$work/$name" < /dev/null; fi
  [ -s "$f" ] || echo "EMPTY OR MISSING: $gen $tool $name"
}
run_set() {
  local src="$1" csv="$2"
  echo "== set $csv ($(($(wc -l < "$csv") - 1)) projects, sources $src)"
  mkdir -p "$work"
  tail -n +2 "$csv" | while IFS=, read -r name eco url kind tag sha; do
    echo "   $name ($eco)"
    run_one "$name" "$eco" "$src" old syft "$OSYFT"
    run_one "$name" "$eco" "$src" new syft "$(command -v syft)"
    run_one "$name" "$eco" "$src" old trivy "$OTRIVY"
    run_one "$name" "$eco" "$src" new trivy "$(command -v trivy)"
  done
}
case "${3:-npm_rust}" in
  npm_rust) run_set dataset/src_npm dataset/npm_pinned.csv; run_set dataset/src_npm2 dataset/npm_pinned2.csv; run_set dataset/src_rust dataset/rust_pinned.csv;;
  go) run_set dataset/src_go dataset/go_pinned10.csv;;
  maven) run_set dataset/src_mvn dataset/mvn_pinned.csv;;
  pypi) run_set dataset/src_py dataset/py_pinned.csv;;
  pilot) run_set dataset/src dataset/pilot_pinned.csv;;
  pilot_old) run_set dataset/src_old dataset/pilot_old_pinned.csv;;
  *) echo "unknown set $3"; exit 1;;
esac
echo "== done"
