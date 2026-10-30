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

per = collections.defaultdict(collections.Counter)
gref = json.loads((R / "vulns_ref/go/node_exporter_truth_grype.json").read_text())["matches"]
for m in gref:
    ids = {m["vulnerability"]["id"]} | {r["id"] for r in m.get("relatedVulnerabilities", [])}
    pu = norm(m["artifact"]["purl"])
    per[pu]["not called" if ids & notcalled.get(pu, set()) else "called"] += 1
print("findings per vulnerable module (Grype on the reference):")
for pu, c in sorted(per.items(), key=lambda x: -sum(x[1].values())):
    if pu in notcalled:
        print(f"   {pu:<55} not called {c['not called']:>3}  called {c['called']:>3}")

def kind(purl, ids):
    return "not called" if ids & notcalled.get(norm(purl), set()) else "called"

def run(cmd):
    try:
        return json.loads(subprocess.run(cmd, capture_output=True, text=True).stdout)
    except ValueError:
        return None

def trivy_scan(sb, v):
    d = run(["trivy", "sbom", "--cache-dir", snap + "/trivy", "--skip-db-update", "--skip-java-db-update", "--scanners", "vuln", "--format", "json", "-q"]
            + (["--vex", str(v)] if v else []) + [str(sb)])
    if d is None:
        return None
    out = []
    for res in d.get("Results") or []:
        for x in res.get("Vulnerabilities") or []:
            pu = (x.get("PkgIdentifier") or {}).get("PURL") or ""
            out.append(kind(pu, {x["VulnerabilityID"]} | set(x.get("VendorIDs") or [])))
    return out

def build(depth):
    comps = [dict(c, **{"bom-ref": c["purl"]}) for c in ref["components"]]
    mids = [{"type": "library", "name": "mid%d" % i, "version": "1.0.0", "purl": "pkg:golang/example.com/mid%d@1.0.0" % i,
             "bom-ref": "pkg:golang/example.com/mid%d@1.0.0" % i} for i in range(depth - 1)]
    chain = ["root"] + [m["bom-ref"] for m in mids]
    deps = [{"ref": chain[i], "dependsOn": [chain[i + 1]]} for i in range(len(chain) - 1)]
    deps.append({"ref": chain[-1], "dependsOn": [c["bom-ref"] for c in comps]})
    deps += [{"ref": c["bom-ref"], "dependsOn": []} for c in comps + mids]
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
           "metadata": {"component": {"type": "application", "name": "node_exporter", "version": tag, "purl": ROOT, "bom-ref": "root"}},
           "components": mids + comps, "dependencies": deps}
    p = R / "vex" / ("depth_%d.cdx.json" % depth)
    p.write_text(json.dumps(doc))
    return p

print(f"\n{'depth':<7}{'trivy left':>11}{'called kept':>13}{'removed':>10}")
for depth in (1, 2, 3, 4):
    sb = build(depth)
    b, a = trivy_scan(sb, None), trivy_scan(sb, R / "vex/scale_vex_A.json")
    if b is None or a is None:
        print(f"{depth:<7}scan failed")
        continue
    cb, ca = collections.Counter(b), collections.Counter(a)
    print(f"{depth:<7}{len(a):>11}{ca['called']:>8} of {cb['called']:<3}{cb['not called'] - ca['not called']:>5} of {cb['not called']}")
