#!/usr/bin/env bash
# usage: replicate_trivy_maven_control.sh OLDTOOLS WORKDIR
# Runs Trivy 0.66.0 and the pinned Trivy on spring-petclinic-rest in the order old, new, new, old
# and counts the swagger-annotations-jakarta and swagger-models-jakarta purls with and without a version.
set -u
root="$(cd "$(dirname "$0")/.." && pwd)"; cd "$root"
OLD="$1/trivy_0.66.0"; NEW="$(command -v trivy)"; W="$2/mvn_ctl"
src=dataset/src_mvn/spring-petclinic-rest
mkdir -p "$W"
"$OLD" --version | head -1; "$NEW" --version | head -1
i=0
for label in old new new old; do
  i=$((i + 1)); bin="$OLD"; [ "$label" = new ] && bin="$NEW"
  rm -rf "$W/work"; cp -a "$src" "$W/work"; git -C "$W/work" clean -xfdq; git -C "$W/work" checkout -q -- .
  f="$W/run${i}_$label.cdx.json"
  "$bin" fs --skip-db-update --skip-java-db-update --format cyclonedx --output "$f" -q "$W/work" < /dev/null
  printf 'run %s %-4s purls %s | swagger jakarta: %s\n' "$i" "$label" "$(jq '[.components[]?.purl // empty] | length' "$f")" \
    "$(jq -r '[.components[]?.purl // empty | select(test("swagger-(annotations|models)-jakarta"))] | "versioned \(map(select(test("@"))) | length) unversioned \(map(select(test("@") | not)) | length)"' "$f")"
done
