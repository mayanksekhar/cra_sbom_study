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

print(f"{'sbom':<9}{'scanner':<8}{'product id used':<62}{'none':>5}{'A left':>7}{'called kept':>12}{'removed':>9}")
for tool in ("syft", "trivy", "cdxgen"):
    sb = R / "raw/go" / f"node_exporter_{tool}.cdx.json"
    mc = (json.loads(sb.read_text()).get("metadata") or {}).get("component") or {}
    pid = mc.get("purl") or mc.get("bom-ref")
    if not pid:
        print(f"{tool:<9}root component has no purl or bom-ref, skipped")
        continue
    prod = {"@id": pid}
    if mc.get("purl"):
        prod["identifiers"] = {"purl": mc["purl"]}
    sts = [{"vulnerability": st["vulnerability"], "products": [dict(prod, subcomponents=st["products"][0]["subcomponents"])],
            "status": st["status"], "justification": st["justification"]} for st in vexA["statements"]]
    vp = R / "vex" / f"real_{tool}_A.json"
    vp.write_text(json.dumps({"@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://example.org/vex/real_" + tool, "author": "cra_sbom_study",
                              "timestamp": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"), "version": 1, "statements": sts}, indent=1))
    for scanner, fn in (("grype", grype_scan), ("trivy", trivy_scan)):
        b, a = fn(sb, None), fn(sb, vp)
        if b is None or a is None:
            print(f"{tool:<9}{scanner:<8}scan failed")
            continue
        cb, ca = collections.Counter(b), collections.Counter(a)
        print(f"{tool:<9}{scanner:<8}{pid[:60]:<62}{len(b):>5}{len(a):>7}{ca['called']:>6} of {cb['called']:<4}{cb['not called'] - ca['not called']:>5} of {cb['not called']}")
