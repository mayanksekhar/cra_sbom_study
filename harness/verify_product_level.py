#!/usr/bin/env python3
"""Recompute the product level reachability, VEX and cross project figures from tracked files and require the same phrases in the draft and the abstract."""
import ast, collections, csv, json, re, sys
from pathlib import Path
root = Path(__file__).resolve().parent.parent
R = root / "results_go"
docs = {n: " ".join((root / "docs" / n).read_text().split()) for n in ("draft.md", "draft_section7.md", "draft_front_back.md")}
D, S7, FB = docs["draft.md"], docs["draft_section7.md"], docs["draft_front_back.md"]
abstract = FB.split("## Abstract")[1].split("## 1 Introduction")[0]
reach = json.loads((R / "reach_product.json").read_text())
cls = collections.Counter(e["class"] for es in reach.values() for e in es)
tot = sum(cls.values()); nc = cls["not called"]; pct = round(100 * nc / tot)
vx = list(csv.DictReader(open(R / "vex_set_product.csv")))
def vs(sc, fm, k): return sum(int(r[k]) for r in vx if r["scanner"] == sc and r["form"] == fm)
log = (R / "vex_set_product.log").read_text()
def logrow(sc, fm): return re.search(rf"^{sc}\s+{fm}\s+(\d+) of (\d+)\s+(\d+) of (\d+)", log, re.M).groups()
tA, gA, gB = logrow("trivy", "A"), logrow("grype", "A"), logrow("grype", "B")
cross = (R / "vex_cross_product.txt").read_text()
po, pt = re.search(r"ordered project pairs: (\d+); pairs where .*?: (\d+)", cross).group(1, 2)[::-1]
n_exp, m_called = re.search(r"suppress: (\d+) of (\d+)", cross).groups()
risk = ast.literal_eval(re.search(r"at risk per project: (\{.*\})", cross).group(1))
riskstr = ", ".join(f"{k} {v}" for k, v in sorted(risk.items()))
rows = [tuple(map(int, m)) for m in re.findall(r"^\s*\S+ -> \S+\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$", cross, re.M)]
pairs_ok = all(p == t == g and a == 0 for p, t, g, a in rows)
pred = [str(r[0]) for r in rows]
predstr = ", ".join(pred[:-1]) + " and " + pred[-1] if len(pred) > 1 else "".join(pred)
mech = list(csv.DictReader(open(R / "mech_result_product.csv")))
ABS, PRES = ("all listed functions absent", "package absent"), ("function present", "package symbols present")
def cnt(c, vals): return sum(1 for r in mech if r["govulncheck"] == c and r["mechanical"] in vals)
nca, nas, ca, cas = cnt("not called", ABS), cnt("not called", ABS + PRES), cnt("called", ABS), cnt("called", ABS + PRES)
checks = [
 (D, f"{tot} findings, {cls['called']} called, {nc} not called, {cls['unknown']} without a verdict, so {nc} of {tot} ({pct} percent) are not called"),
 (D, f"Trivy with form A: {vs('trivy','A','notcalled_removed')} of {vs('trivy','A','notcalled_total')} not called findings removed (its scan reports {vs('trivy','A','notcalled_total')} of the {nc}), {tA[0]} of {tA[1]} called removed"),
 (D, f"Grype with form A: {vs('grype','A','notcalled_removed')} of {vs('grype','A','notcalled_total')} removed"),
 (D, f"Grype with form B: {vs('grype','B','notcalled_removed')} of {vs('grype','B','notcalled_total')} removed, {gB[0]} of {gB[1]} called removed"),
 (D, f"{po} of {pt} ordered pairs overlap; {n_exp} of {m_called} called findings are exposed ({riskstr})"),
 (D, f"matched the scans of all {len(rows)} pairs in both scanners ({predstr} called findings removed)"),
 (D, f"Of the {nas} not called findings that can be checked this way, {nca} have no vulnerable function in the built binary; of the {cas} called findings that can be checked, {ca} " + ("has" if ca == 1 else "have") + " none"),
 (S7, f"Trivy removed {vs('trivy','A','notcalled_removed')} of {vs('trivy','A','notcalled_total')} not called findings"),
 (S7, f"Grype removed {vs('grype','A','notcalled_removed')} of {vs('grype','A','notcalled_total')}"),
 (S7, f"({vs('grype','B','notcalled_removed')} of {vs('grype','B','notcalled_total')})"),
 (S7, f"{n_exp} of {m_called} called findings were exposed at product level"),
 (S7, f"all {len(rows)} overlapping pairs"),
 (S7, f"{nc} of {tot} Go findings ({pct} percent)"),
 (abstract, f"removed {vs('trivy','A','notcalled_removed')} of {vs('trivy','A','notcalled_total')} not called findings in Trivy and {vs('grype','A','notcalled_removed')} of {vs('grype','A','notcalled_total')} in Grype"),
 (abstract, f"({n_exp} of {m_called} called findings)"),
 (abstract, f"classifies {nc} of {tot} findings ({pct} percent) as not called"),
 (FB, f"{nca + ca} of {nas + cas} checkable findings have no vulnerable function in the built binary ({round(100 * (nca + ca) / (nas + cas))} percent)"),
]
bad = 0
if not pairs_ok or po != str(len(rows)):
    bad += 1; print("MISSING pair rows: predicted, trivy B, grype B must agree and trivy A must be 0 in every overlapping pair; rows:", rows, "pairs line:", po)
if tA[0] != "0" or gA[0] != "0" or gB[0] != "0":
    bad += 1; print("MISSING called findings were removed, the draft statement 'no called finding removed' is wrong")
for text, p in checks:
    ok = p in text
    bad += not ok
    print(f"{'OK     ' if ok else 'MISSING'} {p[:110]}")
print("not checked: 166 -> 151 movement, 6 of 8 explained, module level 42 of 230 and 5 of 90 (source output not stored), section 5.2 figures, threats list")
print("phrases not confirmed:", bad)
sys.exit(1 if bad else 0)
