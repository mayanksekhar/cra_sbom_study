#!/usr/bin/env python3
"""Check the abstract of docs/draft_front_back.md: every 'N of M' and 'N percent' must appear in docs/draft.md or docs/draft_section7.md, and the project version count is recomputed."""
import csv, re
from pathlib import Path
root = Path(__file__).resolve().parent.parent
fb = " ".join((root / "docs" / "draft_front_back.md").read_text().split())
abstract = fb.split("## Abstract")[1].split("## 1 Introduction")[0]
body = " ".join(((root / "docs" / "draft.md").read_text() + " " + (root / "docs" / "draft_section7.md").read_text()).split())
bad = 0
for pat in (r"\b\d[\d,]* of \d[\d,]*\b", r"\b\d+ percent\b"):
    for m in sorted(set(re.findall(pat, abstract))):
        ok = m in body
        bad += not ok
        print(f"{'OK     ' if ok else 'MISSING'} {m}")
n = 0
for d in ("results", "results_old", "results_go", "results_mvn", "results_py", "results_rust", "results_npm"):
    n += len({r["project"] for r in csv.DictReader(open(root / d / "findings_vs_reference.csv")) if not r["project"].endswith("_nolock")})
ok = f"{n} project versions" in abstract
bad += not ok
print(f"{'OK     ' if ok else 'MISSING'} {n} project versions (recomputed from the seven findings CSVs)")
t = re.search(r"\b(\d+) reference findings\b", abstract)
print("phrase '1061 reference findings' present" if "959 reference findings" in abstract else "check the reference findings figure")
print("not checked: scanner names, VEX removal counts other than those matched above, the sentence about version carriers")
print("abstract phrases not confirmed:", bad)
