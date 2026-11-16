#!/usr/bin/env python3
"""usage: replicate_syft_trivy_compare.py OUT CSV  (compares old and new purl sets per project and tool)"""
import csv, json, sys
from pathlib import Path
out, dest = Path(sys.argv[1]), sys.argv[2]
def purls(p):
    s = set()
    def walk(cs):
        for c in cs or []:
            if c.get("purl"):
                s.add(c["purl"].lower())
            walk(c.get("components"))
    walk(json.loads(p.read_text()).get("components"))
    return s
rows = []
for old in sorted((out / "old").glob("*/*/*.cdx.json")):
    tool, eco, name = old.parts[-3], old.parts[-2], old.name[: -len(".cdx.json")]
    new = out / "new" / tool / eco / old.name
    if not new.exists():
        print("MISSING new", tool, eco, name); continue
    a, b = purls(old), purls(new)
    rows.append({"project": name, "ecosystem": eco, "tool": tool, "n_old": len(a), "n_new": len(b),
                 "only_old": len(a - b), "only_new": len(b - a), "identical": int(a == b)})
    if a != b:
        print(f"DIFF {name} {tool}: only_old {sorted(a - b)[:12]} only_new {sorted(b - a)[:12]}")
with open(dest, "w", newline="") as fh:
    w = csv.DictWriter(fh, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
print(f"{'project':<16}{'eco':<6}{'tool':<7}{'old':>6}{'new':>6}{'only_old':>9}{'only_new':>9}  identical")
for r in rows:
    print(f"{r['project']:<16}{r['ecosystem']:<6}{r['tool']:<7}{r['n_old']:>6}{r['n_new']:>6}{r['only_old']:>9}{r['only_new']:>9}  {r['identical']}")
print("rows", len(rows), "identical", sum(r["identical"] for r in rows))
