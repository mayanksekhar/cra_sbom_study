#!/usr/bin/env bash
# Does Trivy read a pip-compile lock file under its original name and folder, and when renamed to requirements.txt at the root?
# usage: control_trivy_layout.sh <project dir> <relative path of the lock file>
set -u
export PATH="$PATH:$HOME/go/bin"
src="${1:-dataset/src_py/ansible-lint}"; rel="${2:-.config/requirements-lock.txt}"
base="$(mktemp -d /tmp/cra_layout.XXXXXX)"
mkdir -p "$base/orig" "$base/renamed"
cp -a "$src/." "$base/orig/"; cp -a "$src/." "$base/renamed/"
cp "$base/renamed/$rel" "$base/renamed/requirements.txt"
for v in orig renamed; do
  trivy fs --skip-db-update --skip-java-db-update --format cyclonedx --output "$base/$v.json" -q "$base/$v" < /dev/null
  printf '%-8s components with a purl: %-4s pypi: %s\n' "$v" "$(jq '[.components[]? | select(.purl != null)] | length' "$base/$v.json")" "$(jq '[.components[]? | select(.purl != null) | select(.purl | startswith("pkg:pypi"))] | length' "$base/$v.json")"
done
echo "(work dir: $base)"
