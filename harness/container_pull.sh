#!/usr/bin/env bash
# Pull the eight images by tag, save them as archives, read the package truth, build the reference SBOMs.
# usage: bash harness/container_pull.sh WORKDIR   (run from the repository root, podman installed)
W=${1:?workdir}
mkdir -p "$W/tar" "$W/truth" "$W/ref"
echo "name,ref,digest,bytes" > "$W/images.csv"
for spec in "debian12:docker.io/library/debian:bookworm-20240926-slim" "debian11:docker.io/library/debian:bullseye-20240926-slim" "alpine320:docker.io/library/alpine:3.20.3" "alpine318:docker.io/library/alpine:3.18.9" "nginx:docker.io/library/nginx:1.27.2" "redis:docker.io/library/redis:7.4.1-bookworm" "python:docker.io/library/python:3.12.7-slim-bookworm" "postgres:docker.io/library/postgres:16.4-alpine3.20"; do
  n=${spec%%:*}; r=${spec#*:}
  if podman pull -q "$r" > /dev/null 2>&1; then
    podman save -o "$W/tar/$n.tar" "$r" > /dev/null 2>&1
    echo "$n,$r,$(podman image inspect "$r" --format '{{.Digest}}'),$(stat -c %s "$W/tar/$n.tar")" >> "$W/images.csv"
    python3 harness/container_truth.py "$n" "$r" "$W"
    python3 harness/container_dual.py "$n" "$W"
  else
    echo "PULL FAILED: $r"
  fi
done
