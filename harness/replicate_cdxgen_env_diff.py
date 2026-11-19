#!/usr/bin/env python3
"""usage: replicate_cdxgen_env_diff.py WORKDIR ECO PROJECT A B
A and B are S (the stored pinned SBOM of the study), R (a fresh run of the pinned cdxgen 12.9.0 in WORKDIR/out_12.9.0) or an older version number.
Prints the purls only in A and only in B (up to 10 each)."""
import json, sys
from pathlib import Path
W, eco, name, a, b = Path(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
RES = {"go": "results_go/raw/go", "maven": "results_mvn/raw/maven", "pypi": "results_py/raw/pypi"}
def path(x):
    if x == "S": return Path(f"{RES[eco]}/{name}_cdxgen.cdx.json")
    return W / f"out_{'12.9.0' if x == 'R' else x}" / eco / f"{name}_cdxgen.cdx.json"
def load(x):
    p = path(x)
    return None if not p.exists() else {c["purl"] for c in json.loads(p.read_text()).get("components", []) if c.get("purl")}
A, B = load(a), load(b)
if A is None or B is None:
    print(f"== {eco} {name}: {a} {len(A) if A is not None else 'missing'} | {b} {len(B) if B is not None else 'missing'}"); sys.exit(0)
print(f"== {eco} {name}: {a} {len(A)} | {b} {len(B)} | only {a} {len(A - B)} | only {b} {len(B - A)}")
for lab, s in ((a, sorted(A - B)), (b, sorted(B - A))):
    if s: print(f"   only {lab}:", [p[:110] for p in s[:10]])
