#!/usr/bin/env python3
"""usage: replicate_syft_go_grype_compare.py WORKDIR CSV  (WORKDIR is the folder holding grype_syft_go)"""
import csv, json, sys
from pathlib import Path
W, dest = Path(sys.argv[1]) / "grype_syft_go", sys.argv[2]
def pairs(p):
    d = json.loads(Path(p).read_text())
    return {(m["artifact"]["name"].lower(), m["artifact"]["version"], m["vulnerability"]["id"]) for m in d.get("matches", [])}
rows = []
for old in sorted((W / "old").glob("*_grype.json")):
    n = old.name[: -len("_grype.json")]
    new = W / "new" / old.name
    comm = Path("results_go/vulns/go") / f"{n}_syft_grype.json"
    a, b = pairs(old), pairs(new)
    c = pairs(comm) if comm.exists() else None
    rows.append({"project": n, "old": len(a), "new": len(b), "only_old": len(a - b), "only_new": len(b - a),
                 "new_equals_committed": "" if c is None else int(b == c)})
    if a != b:
        print(f"DIFF {n}: only_old {sorted(a - b)[:4]} only_new {sorted(b - a)[:4]}")
with open(dest, "w", newline="") as fh:
    w = csv.DictWriter(fh, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
print(f"{'project':<20}{'old':>5}{'new':>5}{'only_old':>9}{'only_new':>9}  new equals committed scan")
for r in rows:
    print(f"{r['project']:<20}{r['old']:>5}{r['new']:>5}{r['only_old']:>9}{r['only_new']:>9}  {r['new_equals_committed']}")
print("rows", len(rows), "| old equals new in", sum(r["only_old"] == 0 and r["only_new"] == 0 for r in rows), "| new equals committed in", sum(r["new_equals_committed"] == 1 for r in rows))
