#!/usr/bin/env python3
import csv, json
from pathlib import Path
root = Path(__file__).resolve().parent.parent

def pnorm(p):
    return p.split("?")[0].split("#")[0].lower()

def grype(p):
    s = set()
    for m in json.loads(p.read_text()).get("matches", []):
        a = m["artifact"]
        s.add((m["vulnerability"]["id"], pnorm(a.get("purl") or f'{a["name"]}@{a["version"]}')))
    return s

def trivy(p):
    s = set()
    for r in json.loads(p.read_text()).get("Results") or []:
        for v in r.get("Vulnerabilities") or []:
            pu = (v.get("PkgIdentifier") or {}).get("PURL") or f'{v["PkgName"]}@{v["InstalledVersion"]}'
            s.add((v["VulnerabilityID"], pnorm(pu)))
    return s

rows = []
for g in sorted((root / "results/vulns").glob("*/*_grype.json")):
    t = g.with_name(g.name.replace("_grype.json", "_trivy.json"))
    if g.stat().st_size == 0 or not t.exists() or t.stat().st_size == 0:
        print("scan failed, skipped:", g.name.replace("_grype.json", ""))
        continue
    gs, ts = grype(g), trivy(t)
    gp, tp = {x[1] for x in gs}, {x[1] for x in ts}
    j = len(gp & tp) / len(gp | tp) if gp | tp else 1.0
    rows.append({"sbom": g.name.replace("_grype.json", ""), "grype_findings": len(gs), "trivy_findings": len(ts),
                 "grype_pkgs": len(gp), "trivy_pkgs": len(tp), "pkg_jaccard": round(j, 2)})
with open(root / "results/vuln_summary.csv", "w", newline="") as fh:
    w = csv.DictWriter(fh, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
print(f"{'sbom':<30}{'grype':>7}{'trivy':>7}{'g_pkgs':>8}{'t_pkgs':>8}{'jaccard':>9}")
for r in rows:
    print(f"{r['sbom']:<30}{r['grype_findings']:>7}{r['trivy_findings']:>7}{r['grype_pkgs']:>8}{r['trivy_pkgs']:>8}{r['pkg_jaccard']:>9}")
