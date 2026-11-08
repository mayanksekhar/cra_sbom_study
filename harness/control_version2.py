#!/usr/bin/env python3
import csv, json, os, subprocess
from pathlib import Path
root = Path(__file__).resolve().parent.parent
snap, osvc = os.environ["SNAP"], os.environ["OSV_CACHE"]
out = root / "results_go" / "control_version2"
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

def osv_ids(f):
    d = js(["osv-scanner", "scan", "source", "--offline-vulnerabilities", "--sbom", str(f), "--format", "json"], dict(os.environ, XDG_CACHE_HOME=osvc))
    if d is None:
        return None
    return {v["id"] for r in d.get("results") or [] for p in r.get("packages") or [] for v in p.get("vulnerabilities") or []}

ids = {}
print(f"{'project':<13}{'version field':<14}{'grype':>7}{'trivy':>7}{'osv ids':>9}")
for p in ("nats-server", "caddy"):
    main = (root / "groundtruth_go/go" / f"{p}_mainmodule.txt").read_text().strip()
    base = "pkg:golang/" + main
    for label, ver in (("none", None), ("UNKNOWN", "UNKNOWN"), ("latest", "latest"), ("v0.0.0", "v0.0.0"), ("v999.0.0", "v999.0.0"), ("tag " + tags[p], tags[p])):
        c = {"type": "library", "name": main, "purl": base, "bom-ref": base}
        if ver:
            c["version"] = ver
        f = out / f"{p}_{label.split()[0]}.cdx.json"
        f.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": [c]}))
        o = osv_ids(f)
        ids[(p, label.split()[0])] = o
        print(f"{p:<13}{label[:13]:<14}{grype(f):>7}{trivy(f):>7}{'ERR' if o is None else len(o):>9}")
a, b = ids[("nats-server", "UNKNOWN")], ids[("nats-server", "tag")]
if a is not None and b is not None:
    print(f"\nnats-server OSV Scanner: UNKNOWN {len(a)} ids, tag {len(b)} ids, only with UNKNOWN {len(a - b)}, only with the tag {len(b - a)}")
    print("   only with UNKNOWN (first 6):", sorted(a - b)[:6])
