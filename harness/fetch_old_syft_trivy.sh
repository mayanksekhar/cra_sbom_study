#!/usr/bin/env bash
# usage: fetch_old_syft_trivy.sh WORKDIR
# Syft 1.33.0 from the release tarball (checksum verified); Trivy 0.66.0 built from the tagged source.
set -eu
W="$1"; mkdir -p "$W"; cd "$W"
SV=1.33.0; TV=0.66.0
base="https://github.com/anchore/syft/releases/download/v$SV"
curl -sSLO "$base/syft_${SV}_linux_amd64.tar.gz"
curl -sSLO "$base/syft_${SV}_checksums.txt"
grep " syft_${SV}_linux_amd64.tar.gz\$" "syft_${SV}_checksums.txt" | sha256sum -c -
mkdir -p "syft_$SV"; tar -xzf "syft_${SV}_linux_amd64.tar.gz" -C "syft_$SV" syft
"./syft_$SV/syft" --version
[ -d trivy_src ] || git clone -q --depth 1 --branch "v$TV" https://github.com/aquasecurity/trivy trivy_src
echo "trivy source commit: $(git -C trivy_src rev-parse HEAD)"
(cd trivy_src && CGO_ENABLED=0 go build -ldflags "-s -w -X github.com/aquasecurity/trivy/pkg/version/app.ver=$TV" -o "../trivy_$TV" ./cmd/trivy)
"./trivy_$TV" --version
