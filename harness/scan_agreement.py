#!/usr/bin/env python3
import csv, json
from pathlib import Path
root = Path(__file__).resolve().parent.parent

def key(purl, name, ver):
    p = (purl or "").split("?")[0].split("#")[0].lower()
    return p if p else f"{name.lower()}@{ver}"

def grype(p):
    out = []
    for m in json.loads(p.read_text()).get("matches", []):
        a = m["artifact"]
        ids = {m["vulnerability"]["id"]} | {r["id"] for r in m.get("relatedVulnerabilities", [])}
        out.append((key(a.get("purl"), a["name"], a["version"]), ids))
    return out

def trivy(p):
    out = []
    for r in json.loads(p.read_text()).get("Results") or []:
        for v in r.get("Vulnerabilities") or []:
            ids = {v["VulnerabilityID"]} | set(v.get("VendorIDs") or [])
            out.append((key((v.get("PkgIdentifier") or {}).get("PURL"), v["PkgName"], v["InstalledVersion"]), ids))
    return out

def matched(a, b):
    by = {}
    for k, ids in b:
        by.setdefault(k, []).append(ids)
    return sum(1 for k, ids in a if any(ids & x for x in by.get(k, [])))

rows = []
for g in sorted((root / "results/vulns").glob("*/*_grype.json")):
    t = g.with_name(g.name.replace("_grype.json", "_trivy.json"))
    if g.stat().st_size == 0 or not t.exists() or t.stat().st_size == 0:
        continue
    ga, ta = grype(g), trivy(t)
    mg, mt = matched(ga, ta), matched(ta, ga)
    rows.append({"sbom": g.name.replace("_grype.json", ""), "grype_n": len(ga), "trivy_n": len(ta),
                 "grype_matched": mg, "grype_only": len(ga) - mg, "trivy_matched": mt, "trivy_only": len(ta) - mt})
with open(root / "results/vuln_agreement.csv", "w", newline="") as fh:
    w = csv.DictWriter(fh, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
print(f"{'sbom':<26}{'g_n':>5}{'t_n':>5}{'g_match':>9}{'g_only':>8}{'t_match':>9}{'t_only':>8}")
for r in rows:
    if r["grype_n"] or r["trivy_n"]:
        print(f"{r['sbom']:<26}{r['grype_n']:>5}{r['trivy_n']:>5}{r['grype_matched']:>9}{r['grype_only']:>8}{r['trivy_matched']:>9}{r['trivy_only']:>8}")
