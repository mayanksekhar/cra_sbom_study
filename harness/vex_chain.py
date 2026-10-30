#!/usr/bin/env python3
import collections, json, os, subprocess
from pathlib import Path
from urllib.parse import unquote
root = Path(__file__).resolve().parent.parent
snap = os.environ["SNAP"]
R = root / "results_old"
vexA = json.loads((R / "vex/scale_vex_A.json").read_text())
norm = lambda p: unquote(p.split("?")[0]).lower()
notcalled = collections.defaultdict(set)
for st in vexA["statements"]:
    notcalled[norm(st["products"][0]["subcomponents"][0]["identifiers"]["purl"])].add(st["vulnerability"]["name"])
tag = subprocess.run(["git", "-C", str(root / "dataset/src_old/node_exporter"), "describe", "--tags", "--always"],
                     capture_output=True, text=True).stdout.strip()
ROOT = "pkg:golang/github.com/prometheus/node_exporter@" + tag
ref = json.loads((R / "reference/go/node_exporter_truth.cdx.json").read_text())

def trivy_scan(sb, v):
    cmd = ["trivy", "sbom", "--cache-dir", snap + "/trivy", "--skip-db-update", "--skip-java-db-update", "--scanners", "vuln", "--format", "json", "-q"] + (["--vex", str(v)] if v else []) + [str(sb)]
    try:
        d = json.loads(subprocess.run(cmd, capture_output=True, text=True).stdout)
    except ValueError:
        return None
    out = []
    for res in d.get("Results") or []:
        for x in res.get("Vulnerabilities") or []:
            pu = norm((x.get("PkgIdentifier") or {}).get("PURL") or "")
            ids = {x["VulnerabilityID"]} | set(x.get("VendorIDs") or [])
            out.append("not called" if ids & notcalled.get(pu, set()) else "called")
    return out

def build(mid):
    comps = [dict(c, **{"bom-ref": c["purl"]}) for c in ref["components"]]
    m = {"type": mid["type"], "name": mid["name"], "bom-ref": "mid0"}
    if mid.get("purl"):
        m["purl"] = mid["purl"]; m["version"] = "1.0.0"
    deps = [{"ref": "root", "dependsOn": ["mid0"]}, {"ref": "mid0", "dependsOn": [c["bom-ref"] for c in comps]}] + [{"ref": c["bom-ref"], "dependsOn": []} for c in comps]
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
           "metadata": {"component": {"type": "application", "name": "node_exporter", "version": tag, "purl": ROOT, "bom-ref": "root"}},
           "components": [m] + comps, "dependencies": deps}
    p = R / "vex" / "chain.cdx.json"
    p.write_text(json.dumps(doc))
    return p

variants = [("library with purl", {"type": "library", "name": "mid", "purl": "pkg:golang/example.com/mid@1.0.0"}),
            ("library, no purl", {"type": "library", "name": "go.mod"}),
            ("application, no purl", {"type": "application", "name": "go.mod"}),
            ("file, no purl", {"type": "file", "name": "go.mod"})]
print(f"\n{'intermediate component':<26}{'left':>5}{'called kept':>13}{'removed':>10}")
for label, mid in variants:
    sb = build(mid)
    b, a = trivy_scan(sb, None), trivy_scan(sb, R / "vex/scale_vex_A.json")
    if b is None or a is None:
        print(f"{label:<26}scan failed")
        continue
    cb, ca = collections.Counter(b), collections.Counter(a)
    print(f"{label:<26}{len(a):>5}{ca['called']:>8} of {cb['called']:<3}{cb['not called'] - ca['not called']:>5} of {cb['not called']}")
