#!/usr/bin/env python3
"""Recompute the headline numbers of docs/draft_section7.md from repo files and check each appears in the text in the same phrase."""
import collections, csv, json
from pathlib import Path
root = Path(__file__).resolve().parent.parent
text = " ".join((root / "docs" / "draft_section7.md").read_text().split())
DIRS = ["results", "results_old", "results_go", "results_mvn", "results_py"]
def walk(cs):
    for c in cs or []:
        yield c
        yield from walk(c.get("components"))
st = collections.defaultdict(collections.Counter)
for d in DIRS:
    for f in sorted((root / d / "raw").glob("*/*.cdx.json")):
        tool = f.name[: -len(".cdx.json")].rsplit("_", 1)[1]
        doc = json.loads(f.read_text())
        s = st[tool]; s["n"] += 1
        mc = (doc.get("metadata") or {}).get("component") or {}
        s["rv"] += bool(mc.get("version"))
        ref = mc.get("bom-ref")
        edges = {x["ref"]: x.get("dependsOn") or [] for x in doc.get("dependencies") or []}
        s["re"] += bool(ref and edges.get(ref))
        s["comp"] += bool(doc.get("compositions"))
        for c in walk(doc.get("components")):
            purl = (c.get("purl") or "").split("?")[0]
            if purl and "@" not in purl.rsplit("/", 1)[-1] and c.get("version") == "UNKNOWN":
                s["unk"] += 1
def rows(f):
    return list(csv.DictReader(open(root / f)))
mv = [r for r in rows("results_mvn/findings_vs_reference.csv") if r["scanner"] == "grype" and r["tool"] == "syft"]
py = [r for r in rows("results_py/findings_vs_reference.csv") if r["scanner"] == "grype" and r["tool"] == "cdxgen"]
vx = rows("results_go/vex_set.csv")
pf = rows("results_go/product_findings.csv")
reach = json.loads((root / "results_go/reach.json").read_text())
cls = collections.Counter(e["class"] for es in reach.values() for e in es)
total_sboms = sum(s["n"] for s in st.values())
ph = {
 "root version": f"Syft {st['syft']['rv']} of {st['syft']['n']} SBOMs and Trivy {st['trivy']['rv']} of {st['trivy']['n']} carry one, cdxgen {st['cdxgen']['rv']} of {st['cdxgen']['n']}",
 "root edges": f"Syft's primary component had no outgoing edge in {st['syft']['n'] - st['syft']['re']} of {st['syft']['n']} SBOMs, Trivy's had edges in {st['trivy']['re']}, cdxgen's in {st['cdxgen']['re']}",
 "compositions": (f"none of the {total_sboms} SBOMs states completeness" if sum(s["comp"] for s in st.values()) == 0 else "COMPOSITIONS FOUND, REWRITE 7.4"),
 "unknown": f"Syft wrote UNKNOWN in {st['syft']['unk']} version fields",
 "maven syft": f"Syft's Maven SBOMs recovered {sum(int(r['tp']) for r in mv)} of {sum(int(r['ref_n']) for r in mv)} real findings, {sum(int(r['fn_no_version']) for r in mv)} of the misses",
 "pypi cdxgen": f"lost {sum(int(r['fn']) for r in py)} of {sum(int(r['ref_n']) for r in py)} PyPI reference findings",
 "vex trivy": "Trivy removed {} of {} not called findings".format(sum(int(r["notcalled_removed"]) for r in vx if r["scanner"] == "trivy" and r["form"] == "A"), sum(int(r["notcalled_total"]) for r in vx if r["scanner"] == "trivy" and r["form"] == "A")),
 "vex grype A": "Grype removed {} of {}".format(sum(int(r["notcalled_removed"]) for r in vx if r["scanner"] == "grype" and r["form"] == "A"), sum(int(r["notcalled_total"]) for r in vx if r["scanner"] == "grype" and r["form"] == "A")),
 "vex grype B": "(356 of 356)" if sum(int(r["notcalled_removed"]) for r in vx if r["scanner"] == "grype" and r["form"] == "B") == 356 else "GRYPE FORM B CHANGED",
 "product": "{} findings sit on the 10 Go applications' own modules at their tags ({} confirmed by Grype, Trivy and OSV Scanner, {} high or critical)".format(sum(int(r["grype_raw"]) for r in pf), sum(int(r["all_three"]) for r in pf), sum(int(r["grype_high_crit"]) for r in pf)),
 "reachability": f"{cls['not called']} of {sum(cls.values())} Go findings ({round(100 * cls['not called'] / sum(cls.values()))} percent)",
}
bad = 0
for k, p in ph.items():
    ok = p in text
    bad += not ok
    print(f"{'OK     ' if ok else 'MISSING'} {k:<14} {p}")
print("not checked: scope table in 7.1, 42 of 230 in 7.6 (printed by vex_cross.py, not stored), 19 to 22 drift, Trivy path rule (34 of 34), all legal and BSI statements")
print("phrases not found in section 7:", bad)
