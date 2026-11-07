#!/usr/bin/env python3
import csv, json, os, subprocess
from pathlib import Path
root = Path(__file__).resolve().parent.parent
snap, osvc = os.environ["SNAP"], os.environ["OSV_CACHE"]
out = root / "results_go" / "control_version"
out.mkdir(parents=True, exist_ok=True)
tags = {r["name"]: r["tag"] for r in csv.DictReader(open(root / "dataset/go_pinned10.csv"))}

def comp(variant, main, tag):
    base = "pkg:golang/" + main
    if variant == "no version":
        return {"type": "library", "name": main, "purl": base, "bom-ref": base}
    if variant == "UNKNOWN":
        return {"type": "library", "name": main, "version": "UNKNOWN", "purl": base, "bom-ref": base}
    return {"type": "library", "name": main, "version": tag, "purl": base + "@" + tag, "bom-ref": base + "@" + tag}

def js(cmd, env=None):
    r = subprocess.run(cmd, capture_output=True, text=True, env=env)
    try:
        return json.loads(r.stdout)
    except ValueError:
        return None

def n_grype(f):
    d = js(["grype", "sbom:" + str(f), "-o", "json", "-q"])
    return "ERR" if d is None else len(d["matches"])

def n_trivy(f):
    d = js(["trivy", "sbom", "--cache-dir", snap + "/trivy", "--skip-db-update", "--skip-java-db-update", "--scanners", "vuln", "--format", "json", "-q", str(f)])
    return "ERR" if d is None else sum(len(r.get("Vulnerabilities") or []) for r in d.get("Results") or [])

def n_osv(f):
    d = js(["osv-scanner", "scan", "source", "--offline-vulnerabilities", "--sbom", str(f), "--format", "json"], dict(os.environ, XDG_CACHE_HOME=osvc))
    return "ERR" if d is None else sum(len(p.get("groups") or []) for r in d.get("results") or [] for p in r.get("packages") or [])

expected = {"nats-server": (44, 14), "caddy": (19, 15), "helm": (23, 6), "hugo": (11, 8)}
print(f"{'project':<13}{'variant':<11}{'grype':>7}{'trivy':>7}{'osv':>6}   earlier count (no version, tag)")
for p in expected:
    main = (root / "groundtruth_go/go" / f"{p}_mainmodule.txt").read_text().strip()
    for v in ("no version", "UNKNOWN", "tag"):
        f = out / f"{p}_{v.replace(' ', '_')}.cdx.json"
        f.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": [comp(v, main, tags[p])]}))
        e = expected[p][0] if v == "no version" else expected[p][1] if v == "tag" else ""
        print(f"{p:<13}{v:<11}{n_grype(f):>7}{n_trivy(f):>7}{n_osv(f):>6}   {e}")
