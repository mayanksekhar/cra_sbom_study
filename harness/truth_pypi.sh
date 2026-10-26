#!/usr/bin/env bash
set -eu
root="$(cd "$(dirname "$0")/.." && pwd)"
gt="$root/groundtruth/pypi"; mkdir -p "$gt"
python3 --version > "$gt/_tooling.txt"
nrm() { awk -F'==' 'NF==2 {n=tolower($1); gsub(/[-_.]+/,"-",n); print "pkg:pypi/"n"@"$2}' | sort -u; }
for name in requests flask; do
  cd "$root/dataset/src/$name"
  python3 -c "import tomllib;print(tomllib.load(open('pyproject.toml','rb'))['project']['name'])" | sed -E 's/[-_.]+/-/g' | tr 'A-Z' 'a-z' > "$gt/${name}_mainmodule.txt"
  python3 -m venv "/tmp/venv_$name"
  "/tmp/venv_$name/bin/pip" install -q .
  "/tmp/venv_$name/bin/pip" freeze | nrm > "/tmp/${name}_py.txt"
  grep -v "pkg:pypi/$(cat "$gt/${name}_mainmodule.txt")@" "/tmp/${name}_py.txt" > "$gt/${name}_shipped.txt" || true
  date -u +%Y%m%dT%H%M%SZ > "$gt/${name}_resolved_at.txt"
done
wc -l "$gt"/*_shipped.txt; cat "$gt"/*_mainmodule.txt
