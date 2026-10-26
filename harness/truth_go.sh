#!/usr/bin/env bash
set -eu
root="$(cd "$(dirname "$0")/.." && pwd)"
for name in cobra node_exporter; do
  cd "$root/dataset/src/$name"
  go list -m all | tail -n +2 | awk '{print "pkg:golang/"$1"@"$2}' | sort -u > "$root/groundtruth/go/${name}_modgraph.txt"
  go list -deps -f '{{if and .Module (not .Module.Main)}}pkg:golang/{{.Module.Path}}@{{.Module.Version}}{{end}}' ./... | sort -u | grep . > "$root/groundtruth/go/${name}_runtime.txt"
  date -u +%Y%m%dT%H%M%SZ > "$root/groundtruth/go/${name}_resolved_at.txt"
done
wc -l "$root"/groundtruth/go/*_modgraph.txt "$root"/groundtruth/go/*_runtime.txt
