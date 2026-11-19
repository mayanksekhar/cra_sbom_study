#!/usr/bin/env python3
"""usage: replicate_cdxgen_pypi_names.py WORKDIR OLDVERSION
PyPI set. Compares the fresh run of the pinned cdxgen (out_12.9.0) with an older version at the level of package names (version and qualifiers removed,
names normalised as in PEP 503), to separate a difference in the version form from a difference in the components."""
import csv, json, re, sys
from pathlib import Path
W, V = Path(sys.argv[1]), sys.argv[2]
def names(p):
    p = Path(p)
    if not p.exists(): return None
    out = set()
    for c in json.loads(p.read_text()).get("components", []):
        u = c.get("purl") or ""
        if u.startswith("pkg:pypi/"):
            n = u[len("pkg:pypi/"):].split("?")[0].split("@")[0]
            out.add(re.sub(r"[-_.]+", "-", n.lower()))
    return out
print(f"{'project':<14}{'R names':>8}{'O names':>8} | only R names / only O names")
same = tot = 0
for r in list(csv.reader(open("dataset/py_pinned.csv")))[1:]:
    n = r[0]
    R, O = names(W / "out_12.9.0" / "pypi" / f"{n}_cdxgen.cdx.json"), names(W / f"out_{V}" / "pypi" / f"{n}_cdxgen.cdx.json")
    if R is None or O is None:
        print(f"{n:<14}  missing: R {R is not None} O {O is not None}"); continue
    tot += 1; same += R == O
    print(f"{n:<14}{len(R):>8}{len(O):>8} | {sorted(R - O)[:8]} / {sorted(O - R)[:8]}")
print(f"projects with both: {tot}; equal at the name level: {same}")
