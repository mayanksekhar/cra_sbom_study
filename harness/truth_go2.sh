#!/usr/bin/env bash
set -eu
root="$(cd "$(dirname "$0")/.." && pwd)"
gt="$root/groundtruth/go"
for name in cobra node_exporter; do
  cd "$root/dataset/src/$name"
  go mod edit -json | jq -r '.Module.Path' > "$gt/${name}_mainmodule.txt"
  go mod edit -json | jq -r '.Require[] | "pkg:golang/"+.Path+"@"+.Version' | sort -u > "$gt/${name}_declared.txt"
  : > "$gt/${name}_rt.tmp"
  for plat in linux/amd64 darwin/arm64 windows/amd64; do
    GOOS="${plat%/*}" GOARCH="${plat#*/}" go list -e -deps -f '{{if and .Module (not .Module.Main)}}pkg:golang/{{.Module.Path}}@{{.Module.Version}}{{end}}' ./... 2>/dev/null | grep . >> "$gt/${name}_rt.tmp" || true
  done
  sort -u "$gt/${name}_rt.tmp" > "$gt/${name}_runtime_multi.txt"
  rm "$gt/${name}_rt.tmp"
done
wc -l "$gt"/*_declared.txt "$gt"/*_runtime_multi.txt
