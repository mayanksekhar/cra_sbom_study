#!/usr/bin/env python3
"""usage: replicate_grype_pilot_trace.py WORKDIR   (run from the repository root)
Lists the purls behind the differing pairs of Grype 0.88.0 and 0.95.0 on the pilot sets, with the kinds of advisory ids."""
import glob, json, os, sys
W = sys.argv[1]
SETS = {"pilot": ("results", ("npm", "go", "maven", "pypi", "rust")), "pilot_old": ("results_old", ("npm", "go", "maven", "rust"))}
def pairs(p):
    s = set()
    for m in json.load(open(p)).get("matches", []):
        a = m.get("artifact", {}); key = (a.get("purl") or (str(a.get("name")) + "@" + str(a.get("version")))).lower()
        s.add((key, m["vulnerability"]["id"]))
    return s
for V in ("0.88.0", "0.95.0"):
    for sname, (res, ecos) in SETS.items():
        for eco in ecos:
            for f in sorted(glob.glob(f"{res}/raw/{eco}/*.cdx.json") + glob.glob(f"{res}/reference/{eco}/*.cdx.json")):
                stem = os.path.basename(f)[: -len(".cdx.json")]
                pin = f"{res}/{'vulns_ref' if stem.endswith('_truth') else 'vulns'}/{eco}/{stem}_grype.json"
                old = f"{W}/out_grype_{V}_{sname}/{eco}/{stem}_grype.json"
                try: a, b = pairs(pin), pairs(old)
                except Exception: continue
                if a == b: continue
                print(f"{V} {sname} {eco} {stem}: only_pinned {len(a - b)}, only_old {len(b - a)}")
                for label, d in (("only_pinned", a - b), ("only_old", b - a)):
                    ps = sorted({k for k, _ in d}); kinds = sorted({i[:4] for _, i in d})
                    print(f"   {label}: {len(ps)} purls {ps[:4]}; advisory kinds {kinds}")
