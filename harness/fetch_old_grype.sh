#!/usr/bin/env bash
# usage: fetch_old_grype.sh <version without v> <dest dir>
# Downloads a Grype release tarball, verifies its sha256 against the release checksums, extracts the binary.
set -u
V="$1"; D="$2"; mkdir -p "$D/$V"
base="https://github.com/anchore/grype/releases/download/v$V"
f="grype_${V}_linux_amd64.tar.gz"
if [ ! -x "$D/$V/grype" ]; then
  curl -fsSL -o "$D/$V/$f" "$base/$f" && curl -fsSL -o "$D/$V/checksums.txt" "$base/grype_${V}_checksums.txt" || echo "download failed $V"
  if [ -f "$D/$V/$f" ] && [ -f "$D/$V/checksums.txt" ]; then
    if (cd "$D/$V" && grep " $f\$" checksums.txt | sha256sum -c - > /dev/null 2>&1); then
      tar -xzf "$D/$V/$f" -C "$D/$V" grype && echo "ok $V (checksum verified)"
    else
      echo "checksum failed $V"
    fi
  fi
fi
