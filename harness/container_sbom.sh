#!/usr/bin/env bash
# Generate the Syft and Trivy SBOMs of the saved image archives.
# usage: bash harness/container_sbom.sh WORKDIR [OUTNAME]   (run from the repository root, source harness/env_frozen.sh first)
W=${1:?workdir}; O=${2:-out}
mkdir -p "$W/$O"
for n in $(tail -n +2 "$W/images.csv" | cut -d, -f1); do
  syft scan "docker-archive:$W/tar/$n.tar" -o "cyclonedx-json=$W/$O/${n}_syft.cdx.json" -q < /dev/null 2>/dev/null
  trivy image --input "$W/tar/$n.tar" --skip-db-update --skip-java-db-update --format cyclonedx --output "$W/$O/${n}_trivy.cdx.json" -q < /dev/null 2>/dev/null
  (cd tools && timeout 900 systemd-run --user --scope -q -p MemoryMax=6G -p MemorySwapMax=0 npx cdxgen -t docker --spec-version 1.6 -o "$W/$O/${n}_cdxgen.cdx.json" "$W/tar/$n.tar" < /dev/null > /dev/null 2>&1)
done
echo "SBOM files written: $(ls "$W/$O" | wc -l)"
