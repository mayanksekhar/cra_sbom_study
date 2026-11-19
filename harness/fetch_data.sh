#!/usr/bin/env bash
# Fetch the data archive from the GitHub release, check its pinned SHA-256 and unpack it at the repository root
# without overwriting tracked files. Usage: bash harness/fetch_data.sh [LOCAL_ARCHIVE]
set -eu
NAME=cra_data_20261119.tar.gz
SHA=979297259dcfdfe17b625e0c0b73e40d8078de230dc2a4fca78ffff238869a48
URL=https://github.com/mayanksekhar/cra_sbom_study/releases/download/data-20261119/$NAME
cd "$(dirname "$0")/.."
if [ "${1:-}" != "" ]; then cp "$1" "$NAME"; else curl -fsSL -o "$NAME" "$URL"; fi
if command -v sha256sum >/dev/null 2>&1; then echo "$SHA  $NAME" | sha256sum -c -; else echo "$SHA  $NAME" | shasum -a 256 -c -; fi
tar -xzf "$NAME" --skip-old-files
rm -f "$NAME"
echo "data archive unpacked"
