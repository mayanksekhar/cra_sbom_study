#!/usr/bin/env python3
import collections, datetime, json, os, subprocess
from pathlib import Path
root = Path(__file__).resolve().parent.parent
snap = os.environ["SNAP"]
R = root / "results_old"
vexA = json.loads((R / "vex/scale_vex_A.json").read_text())
notcalled = collections.defaultdict(set)
for st in vexA["statements"]:
    notcalled[st["products"][0]["subcomponents"][0]["identifiers"]["purl"]].add(st["vulnerability"]["name"])
tag = subprocess.run(["git", "-C", str(root / "dataset/src_old/node_exporter"), "describe", "--tags", "--always"],
                     capture_output=True, text=True).stdout.strip()
ROOT = "pkg:golang/github.com/prometheus/node_exporter@" + tag

def kind(purl, ids):
    return "not called" if ids & notcalled.get(purl.split("?")[0], set()) else "called"

def run(cmd):
    try:
        return json.loads(subprocess.run(cmd, capture_output=True, text=True).stdout)
    except ValueError:
        return None

def grype_scan(sb, v):
    d = run(["grype", "sbom:" + str(sb), "-o", "json", "-q"] + (["--vex", str(v)] if v else []))
    if d is None:
        return None
    return [kind(m["artifact"]["purl"], {m["vulnerability"]["id"]} | {r["id"] for r in m.get("relatedVulnerabilities", [])}) for m in d["matches"]]

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

def variant(tool, fix_id, flat):
    d = json.loads((R / "raw/go" / f"node_exporter_{tool}.cdx.json").read_text())
    mc = d["metadata"]["component"]
    if fix_id:
        mc.update({"type": "application", "name": "github.com/prometheus/node_exporter", "version": tag, "purl": ROOT})
    rref = mc.get("bom-ref") or "root"
    mc["bom-ref"] = rref
    if flat:
        seen, refs = set(), []
        for c in d.get("components") or []:
            c.setdefault("bom-ref", c.get("purl") or c["name"])
            if c["bom-ref"] not in seen:
                seen.add(c["bom-ref"]); refs.append(c["bom-ref"])
        d["dependencies"] = [{"ref": rref, "dependsOn": refs}] + [{"ref": r, "dependsOn": []} for r in refs]
    name = "fact_%s_%s_%s" % (tool, "fixed" if fix_id else "orig", "flat" if flat else "orig")
    sb = R / "vex" / (name + ".cdx.json")
    sb.write_text(json.dumps(d))
    pid = mc.get("purl") or mc.get("bom-ref")
    prod = {"@id": pid}
    if mc.get("purl"):
        prod["identifiers"] = {"purl": mc["purl"]}
    sts = [{"vulnerability": st["vulnerability"], "products": [dict(prod, subcomponents=st["products"][0]["subcomponents"])],
            "status": st["status"], "justification": st["justification"]} for st in vexA["statements"]]
    vp = R / "vex" / (name + "_vex.json")
    vp.write_text(json.dumps({"@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://example.org/vex/" + name, "author": "cra_sbom_study",
                              "timestamp": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"), "version": 1, "statements": sts}))
    return sb, vp

print(f"{'sbom':<8}{'root id':<8}{'graph':<7}{'scanner':<8}{'left':>5}{'called kept':>13}{'removed':>10}")
for tool in ("syft", "trivy", "cdxgen"):
    for fix_id, flat in ((False, False), (True, False), (False, True), (True, True)):
        sb, vp = variant(tool, fix_id, flat)
        scanners = [("trivy", trivy_scan)] + ([("grype", grype_scan)] if fix_id and flat else [])
        for sname, fn in scanners:
            b, a = fn(sb, None), fn(sb, vp)
            if b is None or a is None:
                print(f"{tool:<8}{'fixed' if fix_id else 'orig':<8}{'flat' if flat else 'orig':<7}{sname:<8}scan failed")
                continue
            cb, ca = collections.Counter(b), collections.Counter(a)
            print(f"{tool:<8}{'fixed' if fix_id else 'orig':<8}{'flat' if flat else 'orig':<7}{sname:<8}{len(a):>5}{ca['called']:>8} of {cb['called']:<3}{cb['not called'] - ca['not called']:>5} of {cb['not called']}")
