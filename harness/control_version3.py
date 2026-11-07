#!/usr/bin/env python3
import csv, json, os, subprocess
from pathlib import Path
root = Path(__file__).resolve().parent.parent
snap, osvc = os.environ["SNAP"], os.environ["OSV_CACHE"]
out = root / "results_go" / "control_version3"
out.mkdir(parents=True, exist_ok=True)
tags = {r["name"]: r["tag"] for r in csv.DictReader(open(root / "dataset/go_pinned10.csv"))}

def js(cmd, env=None):
    r = subprocess.run(cmd, capture_output=True, text=True, env=env)
    try:
        return json.loads(r.stdout)
    except ValueError:
        return None

def grype(f):
    d = js(["grype", "sbom:" + str(f), "-o", "json", "-q"])
    return "ERR" if d is None else len(d["matches"])

def trivy(f):
    d = js(["trivy", "sbom", "--cache-dir", snap + "/trivy", "--skip-db-update", "--skip-java-db-update", "--scanners", "vuln", "--format", "json", "-q", str(f)])
    return "ERR" if d is None else sum(len(r.get("Vulnerabilities") or []) for r in d.get("Results") or [])

def osv(f):
    d = js(["osv-scanner", "scan", "source", "--offline-vulnerabilities", "--sbom", str(f), "--format", "json"], dict(os.environ, XDG_CACHE_HOME=osvc))
    if d is None:
        return "ERR", "ERR"
    pk = [p for r in d.get("results") or [] for p in r.get("packages") or []]
    return len({v["id"] for p in pk for v in p.get("vulnerabilities") or []}), sum(len(p.get("groups") or []) for p in pk)

print(f"{'project':<13}{'purl version':<14}{'version field':<14}{'grype':>7}{'trivy':>7}{'osv ids':>9}{'osv groups':>11}")
for p in ("nats-server", "caddy"):
    main = (root / "groundtruth_go/go" / f"{p}_mainmodule.txt").read_text().strip()
    base, tag = "pkg:golang/" + main, tags[p]
    for pv, fv in ((tag, None), (tag, "UNKNOWN"), (None, tag), ("v0.0.0", tag), (tag, "v0.0.0")):
        purl = base + ("@" + pv if pv else "")
        c = {"type": "library", "name": main, "purl": purl, "bom-ref": purl}
        if fv:
            c["version"] = fv
        f = out / f"{p}_{pv or 'none'}_{fv or 'none'}.cdx.json"
        f.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": [c]}))
        oi, og = osv(f)
        lab = lambda x: "tag" if x == tag else (x or "none")
        print(f"{p:<13}{lab(pv):<14}{lab(fv):<14}{grype(f):>7}{trivy(f):>7}{oi:>9}{og:>11}")
