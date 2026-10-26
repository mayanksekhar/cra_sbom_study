#!/usr/bin/env bash
set -eu
cd "$(dirname "$0")/.."
mkdir -p dataset/src
echo "name,ecosystem,repo_url,kind,commit_sha" > dataset/pilot_pinned.csv
tail -n +2 dataset/pilot.csv | while IFS=, read -r name eco url kind; do
  if [ ! -d "dataset/src/$name" ]; then
    git clone --depth 1 "$url" "dataset/src/$name" 2>&1 | tail -n 1
  fi
  sha=$(git -C "dataset/src/$name" rev-parse HEAD)
  echo "$name,$eco,$url,$kind,$sha" >> dataset/pilot_pinned.csv
done
cat dataset/pilot_pinned.csv
