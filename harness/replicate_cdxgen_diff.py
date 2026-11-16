#!/usr/bin/env python3
"""usage: replicate_cdxgen_diff.py PROJECT WORKDIR VERSION
Lists the purls that differ between the pinned cdxgen SBOM of an npm project and the SBOM of an older cdxgen,
and the source file each came from (paths relative to the scanned copy)."""
import json, re, sys
from collections import Counter
from pathlib import Path
name, W, V = sys.argv[1], Path(sys.argv[2]), sys.argv[3]
def load(p):
    d = json.loads(Path(p).read_text()); r = {}
    def walk(cs):
        for c in cs or []:
            if c.get("purl"):
                src = ""
                for pr in c.get("properties", []):
                    if pr.get("name", "").lower() == "srcfile":
                        src = pr.get("value", ""); break
                if not src:
                    occ = (c.get("evidence") or {}).get("occurrences") or []
                    src = occ[0].get("location", "") if occ else "NO SOURCE PROPERTY"
                r[c["purl"]] = re.sub(r"^.*?/(?:work|cra_work|work_gen)/[^/]+/", "", src)
            walk(c.get("components"))
    walk(d.get("components")); return r
pin = load(f"results_npm/raw/npm/{name}_cdxgen.cdx.json")
old = load(W / f"out_{V}" / "npm" / f"{name}_cdxgen.cdx.json")
op, oo = sorted(set(pin) - set(old)), sorted(set(old) - set(pin))
print(f"== {name}, cdxgen {V} against the pinned 12.9.0: only pinned {len(op)}, only old {len(oo)}")
print("only old (up to 5):", [(p, old[p]) for p in oo[:5]])
print("only pinned from the root lock file (up to 5):", [(p, pin[p]) for p in op if pin[p] == "package-lock.json"][:5])
cnt = Counter(pin[p] for p in op)
print("only pinned, by source file (top 8 of %d files):" % len(cnt))
for k, v in cnt.most_common(8): print("  ", v, k)
print("source files in the old output:", len(set(old.values())), "| in the pinned output:", len(set(pin.values())))
