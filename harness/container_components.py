#!/usr/bin/env python3
"""Component level check of container SBOMs against the package database truth.
usage: container_components.py WORKDIR OUTDIR
Writes OUTDIR/container_components.csv (image, generator, truth, true_positive, extra, missed, other_types)."""
import csv, json, sys
from pathlib import Path

W, OUT = Path(sys.argv[1]), Path(sys.argv[2])
imgs = [l.split(",")[0] for l in (W / "images.csv").read_text().splitlines()[1:]]
OS = ("pkg:deb/", "pkg:apk/")
rows = []
for n in imgs:
    truth = {p["name"] for p in json.loads((W / "truth" / f"{n}.json").read_text())["packages"]}
    for gen in ("syft", "trivy"):
        cs = json.loads((W / "out" / f"{n}_{gen}.cdx.json").read_text()).get("components") or []
        names = {c["name"] for c in cs if (c.get("purl") or "").startswith(OS)}
        other = sum(1 for c in cs if (c.get("purl") or "").startswith("pkg:") and not (c.get("purl") or "").startswith(OS))
        rows.append([n, gen, len(truth), len(names & truth), len(names - truth), len(truth - names), other])
with open(OUT / "container_components.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["image", "generator", "truth", "true_positive", "extra", "missed", "other_types"])
    w.writerows(rows)
