#!/usr/bin/env python3
"""usage: replicate_syft_go_forms.py OUT
For the Go set: old Syft writes a path below the module root as a purl subpath (name@version#sub), the pinned Syft puts it in the name
(name/sub@version). Converts each old purl that is not in the pinned output and counts how many land on a purl that only the pinned output has."""
import json, sys
from pathlib import Path
out = Path(sys.argv[1])
def purls(p):
    s = set()
    def walk(cs):
        for c in cs or []:
            if c.get("purl"):
                s.add(c["purl"].lower())
            walk(c.get("components"))
    walk(json.loads(p.read_text()).get("components")); return s
def convert(p):
    left, _, sub = p.partition("#")
    if not sub:
        return None
    if "@" in left.rsplit("/", 1)[-1] or "@" in left:
        base, ver = left.rsplit("@", 1)
        return f"{base}/{sub}@{ver}"
    return f"{left}/{sub}"
tot = hit = tot_old = 0
print(f"{'project':<20}{'only_old':>9}{'with subpath':>13}{'mapped one to one':>19}{'unmapped':>10}")
for old in sorted((out / "old" / "syft" / "go").glob("*.cdx.json")):
    a, b = purls(old), purls(out / "new" / "syft" / "go" / old.name)
    oo, on = a - b, b - a
    conv = [(p, convert(p)) for p in sorted(oo)]
    sub = [(p, q) for p, q in conv if q]
    ok = sum(q in on for p, q in sub)
    print(f"{old.name[:-9]:<20}{len(oo):>9}{len(sub):>13}{ok:>19}{len(oo) - ok:>10}")
    tot_old += len(oo); tot += len(sub); hit += ok
    for p, q in sub:
        if q not in on:
            print("   unmapped:", p, "->", q)
print(f"total only_old {tot_old}, with subpath {tot}, mapped one to one {hit}, unmapped {tot_old - hit}")
