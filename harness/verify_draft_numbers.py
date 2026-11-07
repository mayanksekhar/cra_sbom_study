#!/usr/bin/env python3
import collections, csv, json
from pathlib import Path
root = Path(__file__).resolve().parent.parent
draft = " ".join((root / "docs" / "draft.md").read_text().split())
def tot(f, tool, key):
    return sum(int(r[key]) for r in csv.DictReader(open(root / f)) if r["scanner"] == "grype" and r["tool"] == tool and not r["project"].endswith("_nolock"))
S = {"pilot": "results/findings_vs_reference.csv", "older": "results_old/findings_vs_reference.csv", "go": "results_go/findings_vs_reference.csv",
     "maven": "results_mvn/findings_vs_reference.csv", "pypi": "results_py/findings_vs_reference.csv"}
ref = {k: tot(f, "cdxgen", "ref_n") for k, f in S.items()}
phrases = {
 "grand total": f"{sum(ref.values())} reference findings over five sets",
 "pilot syft": f"Syft {tot(S['pilot'], 'syft', 'tp')} of {ref['pilot']}",
 "older all three": f"older pins 48 of 48" if ref["older"] == 48 and all(tot(S["older"], t, "tp") == 48 for t in ("cdxgen", "syft", "trivy")) else "older pins MISMATCH",
 "go cdxgen": f"cdxgen {tot(S['go'], 'cdxgen', 'tp')} of {ref['go']}",
 "maven syft": f"Syft {tot(S['maven'], 'syft', 'tp')} of {ref['maven']}",
 "maven others": f"cdxgen and Trivy {ref['maven']} of {ref['maven']}" if tot(S["maven"], "cdxgen", "tp") == ref["maven"] == tot(S["maven"], "trivy", "tp") else "maven others MISMATCH",
 "pypi cdxgen": f"cdxgen {tot(S['pypi'], 'cdxgen', 'tp')} of {ref['pypi']} ({tot(S['pypi'], 'cdxgen', 'fn_wrong_version')} wrong version",
 "pypi syft": f"Syft {tot(S['pypi'], 'syft', 'tp')} of {ref['pypi']}",
 "pypi trivy": f"Trivy {tot(S['pypi'], 'trivy', 'tp')} of {ref['pypi']}",
}
reach = json.loads((root / "results_go/reach.json").read_text())
c = collections.Counter(e["class"] for es in reach.values() for e in es)
phrases["reachability"] = f"{sum(c.values())} findings on the reference SBOMs of 10 applications: {c['called']} called, {c['not called']} not called, {c['unknown']} without a verdict"
pf = list(csv.DictReader(open(root / "results_go/product_findings.csv")))
phrases["product"] = f"{sum(int(r['grype_raw']) for r in pf)} findings on the 10 Go applications' own module"
phrases["product 3"] = f"{sum(int(r['all_three']) for r in pf)} are confirmed by Grype, Trivy and OSV"
vx = list(csv.DictReader(open(root / "results_go/vex_set.csv")))
def vs(sc, fm, key, tk="notcalled_removed"):
    return sum(int(r[tk]) for r in vx if r["scanner"] == sc and r["form"] == fm)
tn = sum(int(r["notcalled_total"]) for r in vx if r["scanner"] == "trivy" and r["form"] == "A")
gn = sum(int(r["notcalled_total"]) for r in vx if r["scanner"] == "grype" and r["form"] == "A")
phrases["vex trivy A"] = f"Trivy with form A: {vs('trivy', 'A', 'x')} of {tn} not called findings removed"
phrases["vex grype A"] = f"Grype with form A: {vs('grype', 'A', 'x')} of {gn} removed"
phrases["vex grype B"] = f"Grype with form B: {vs('grype', 'B', 'x')} of {gn} removed"
phrases["no called removed"] = "No called finding removed" if sum(int(r["called_removed"]) for r in vx) == 0 else "CALLED FINDINGS WERE REMOVED, rewrite 6.2"
bad = 0
for k, p in phrases.items():
    ok = p in draft
    bad += not ok
    print(f"{'OK     ' if ok else 'MISSING'} {k:<18} {p}")
print("not checked: Trivy 0 of 216 called removed (no CSV stores the called total), all numbers in sections 3, 4 and 5.2 to 5.5")
print("phrases not found in the draft:", bad)
