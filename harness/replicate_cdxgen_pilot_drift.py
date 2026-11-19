#!/usr/bin/env python3
"""usage: replicate_cdxgen_pilot_drift.py WORKDIR   (run from the repository root)
Stored pinned SBOM against a fresh cdxgen 12.9.0 run for the pilot projects without a lock file, at name level."""
import json, sys
W = sys.argv[1]
def comps(p):
    d = {}
    for c in json.load(open(p)).get("components", []):
        u = c.get("purl")
        if not u: continue
        n = u.split("?")[0].split("#")[0]
        name, ver = (n.rsplit("@", 1) + [""])[:2] if "@" in n else (n, "")
        d.setdefault(name, set()).add(ver)
    return d
for eco, proj, res in (("npm", "express", "results"), ("pypi", "requests", "results")):
    S = comps(f"{res}/raw/{eco}/{proj}_cdxgen.cdx.json")
    R = comps(f"{W}/out_12.9.0_pilot/{eco}/{proj}_cdxgen.cdx.json")
    only_s, only_r = sorted(set(S) - set(R)), sorted(set(R) - set(S))
    changed = sorted(n for n in set(S) & set(R) if S[n] != R[n])
    print(f"{eco} {proj}: names stored {len(S)} fresh {len(R)}, only stored {len(only_s)}, only fresh {len(only_r)}, same name other version {len(changed)}")
    for n in changed[:3]: print("   changed", n, sorted(S[n]), "->", sorted(R[n]))
    for n in only_s[:3]: print("   only stored", n, sorted(S[n]))
