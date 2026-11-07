#!/usr/bin/env python3
import collections, csv, json
from pathlib import Path
root = Path(__file__).resolve().parent.parent
draft = (root / "docs" / "draft.md").read_text()
def tot(f, tool, key):
    return sum(int(r[key]) for r in csv.DictReader(open(root / f)) if r["scanner"] == "grype" and r["tool"] == tool and not r["project"].endswith("_nolock"))
checks = {
 "pilot reference": tot("results/findings_vs_reference.csv", "cdxgen", "ref_n"),
 "older pins reference": tot("results_old/findings_vs_reference.csv", "cdxgen", "ref_n"),
 "go reference": tot("results_go/findings_vs_reference.csv", "cdxgen", "ref_n"),
 "maven reference": tot("results_mvn/findings_vs_reference.csv", "cdxgen", "ref_n"),
 "pypi reference": tot("results_py/findings_vs_reference.csv", "cdxgen", "ref_n"),
 "maven syft found": tot("results_mvn/findings_vs_reference.csv", "syft", "tp"),
 "pypi cdxgen found": tot("results_py/findings_vs_reference.csv", "cdxgen", "tp"),
 "pypi cdxgen wrong version": tot("results_py/findings_vs_reference.csv", "cdxgen", "fn_wrong_version"),
 "pypi syft found": tot("results_py/findings_vs_reference.csv", "syft", "tp"),
 "pypi trivy found": tot("results_py/findings_vs_reference.csv", "trivy", "tp"),
 "go cdxgen found": tot("results_go/findings_vs_reference.csv", "cdxgen", "tp"),
}
reach = json.loads((root / "results_go/reach.json").read_text())
cls = collections.Counter(e["class"] for es in reach.values() for e in es)
checks.update({"reach called": cls["called"], "reach not called": cls["not called"], "reach unknown": cls["unknown"], "reach total": sum(cls.values())})
pf = list(csv.DictReader(open(root / "results_go/product_findings.csv")))
checks["product findings grype raw"] = sum(int(r["grype_raw"]) for r in pf)
checks["product findings all three"] = sum(int(r["all_three"]) for r in pf)
vx = list(csv.DictReader(open(root / "results_go/vex_set.csv")))
checks["vex trivy A not called removed"] = sum(int(r["notcalled_removed"]) for r in vx if r["scanner"] == "trivy" and r["form"] == "A")
checks["vex grype B not called removed"] = sum(int(r["notcalled_removed"]) for r in vx if r["scanner"] == "grype" and r["form"] == "B")
checks["vex grype A not called removed"] = sum(int(r["notcalled_removed"]) for r in vx if r["scanner"] == "grype" and r["form"] == "A")
checks["vex called removed (any)"] = sum(int(r["called_removed"]) for r in vx)
bad = 0
for k, v in checks.items():
    ok = str(v) in draft
    bad += not ok
    print(f"{'OK     ' if ok else 'MISSING'} {k:<34}{v}")
print("numbers not found in the draft:", bad)
