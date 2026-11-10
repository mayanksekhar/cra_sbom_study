#!/usr/bin/env python3
"""Container set scoring, OS packages only.
usage: container_score.py WORKDIR OUTDIR
Reference = the scanner's own scan of the dual reference SBOM (built from the image package database).
Writes OUTDIR/container_calibration.csv and OUTDIR/container_scoring.csv."""
import csv, json, subprocess, sys
from pathlib import Path

W, OUT = Path(sys.argv[1]), Path(sys.argv[2])
OUT.mkdir(exist_ok=True)
imgs = [l.split(",")[0] for l in (W / "images.csv").read_text().splitlines()[1:]]

def grype(src):
    r = subprocess.run(["grype", src, "-o", "json", "-q"], capture_output=True, text=True, stdin=subprocess.DEVNULL)
    d = json.loads(r.stdout)
    return {(m["artifact"]["name"], m["artifact"]["version"], m["vulnerability"]["id"]): m["matchDetails"][0]["type"]
            for m in d["matches"] if m["artifact"]["type"] in ("deb", "apk")}

def trivy(args):
    r = subprocess.run(["trivy", *args, "--skip-db-update", "--skip-java-db-update", "--format", "json", "-q"], capture_output=True, text=True, stdin=subprocess.DEVNULL)
    d = json.loads(r.stdout)
    return {(v["PkgName"], v["InstalledVersion"], v["VulnerabilityID"]): "os"
            for res in d.get("Results") or [] if res.get("Class") == "os-pkgs" for v in res.get("Vulnerabilities") or []}

def scan(scanner, kind, path):
    if scanner == "grype":
        return grype(f"docker-archive:{path}" if kind == "image" else f"sbom:{path}")
    return trivy(["image", "--input", str(path)] if kind == "image" else ["sbom", str(path)])

cal, sco = [], []
for n in imgs:
    for scanner in ("grype", "trivy"):
        ref = scan(scanner, "sbom", W / "ref" / f"{n}_truth_dual.cdx.json")
        im = scan(scanner, "image", W / "tar" / f"{n}.tar")
        only_im = set(im) - set(ref)
        cpe = sum(1 for k in only_im if im[k] == "cpe-match")
        cal.append([n, scanner, len(im), len(ref), len(set(im) & set(ref)), len(only_im), len(set(ref) - set(im)), cpe])
        for gen in ("syft", "trivy"):
            g = scan(scanner, "sbom", W / "out" / f"{n}_{gen}.cdx.json")
            sco.append([n, scanner, gen, len(ref), len(set(g) & set(ref)), len(set(ref) - set(g)), len(set(g) - set(ref))])
with open(OUT / "container_calibration.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["image", "scanner", "image_scan", "reference", "in_both", "only_image", "only_reference", "only_image_cpe_match"])
    w.writerows(cal)
with open(OUT / "container_scoring.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["image", "scanner", "generator", "reference", "found", "missed", "extra"])
    w.writerows(sco)
