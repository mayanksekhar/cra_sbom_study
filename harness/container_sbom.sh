#!/usr/bin/env bash
# Generate the Syft and Trivy SBOMs of the saved image archives.
# usage: bash harness/container_sbom.sh WORKDIR [OUTNAME]   (source harness/env_frozen.sh first)
W=${1:?workdir}; O=${2:-out}
mkdir -p "$W/$O"
for n in $(tail -n +2 "$W/images.csv" | cut -d, -f1); do
  syft scan "docker-archive:$W/tar/$n.tar" -o "cyclonedx-json=$W/$O/${n}_syft.cdx.json" -q < /dev/null 2>/dev/null
  trivy image --input "$W/tar/$n.tar" --skip-db-update --skip-java-db-update --format cyclonedx --output "$W/$O/${n}_trivy.cdx.json" -q < /dev/null 2>/dev/null
done
echo "SBOM files written: $(ls "$W/$O" | wc -l)"
