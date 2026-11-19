#!/usr/bin/env python3
"""usage: replicate_cdxgen_env_control.py WORKDIR OLDVERSION
Go, Maven and PyPI sets. For each project: S the stored pinned SBOM (cdxgen 12.9.0, made earlier), R a fresh run of the pinned cdxgen in
the present environment (WORKDIR/out_12.9.0), O the older version (WORKDIR/out_OLDVERSION). Compares the purl sets of the three."""
import csv, json, sys
from pathlib import Path
W, V = Path(sys.argv[1]), sys.argv[2]
sets = [("go", "dataset/go_pinned10.csv", "results_go/raw/go"), ("maven", "dataset/mvn_pinned.csv", "results_mvn/raw/maven"), ("pypi", "dataset/py_pinned.csv", "results_py/raw/pypi")]
def load(p):
    p = Path(p)
    if not p.exists(): return None
    return {c["purl"] for c in json.loads(p.read_text()).get("components", []) if c.get("purl")}
rows = []
print(f"{'eco':<6}{'project':<28}{'S':>5}{'R':>5}{'O':>5} | {'S-R':>4}{'R-S':>4} | {'R-O':>4}{'O-R':>4}  S=R R=O")
for eco, c, rd in sets:
    for r in list(csv.reader(open(c)))[1:]:
        n = r[0]
        S = load(f"{rd}/{n}_cdxgen.cdx.json"); R = load(W / "out_12.9.0" / eco / f"{n}_cdxgen.cdx.json"); O = load(W / f"out_{V}" / eco / f"{n}_cdxgen.cdx.json")
        if S is None or R is None or O is None:
            print(f"{eco:<6}{n:<28}  missing: S {S is not None} R {R is not None} O {O is not None}"); rows.append((eco, n, None)); continue
        rows.append((eco, n, (S == R, R == O)))
        print(f"{eco:<6}{n:<28}{len(S):>5}{len(R):>5}{len(O):>5} | {len(S - R):>4}{len(R - S):>4} | {len(R - O):>4}{len(O - R):>4}  {int(S == R)}   {int(R == O)}")
ok = [x for x in rows if x[2] is not None]
print(f"projects with all three: {len(ok)} of {len(rows)} | stored pinned equals fresh pinned: {sum(x[2][0] for x in ok)} | fresh pinned equals old {V}: {sum(x[2][1] for x in ok)}")
