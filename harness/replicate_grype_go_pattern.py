#!/usr/bin/env python3
"""usage: replicate_grype_go_pattern.py WORKDIR > record   (run from the repository root)
Grype 0.88.0 (WORKDIR/out_grype_0.88.0) against the pinned 0.114.0 on the Go set, raw and reference SBOMs.
For every advisory that is lost or kept, the database rows (frozen snapshot, harness/env_frozen.sh) are classified
by version range (none or given) and by module path (major version suffix such as /v2, or plain). Association only."""
import collections, glob, json, os, re, subprocess, sys
W = os.path.expanduser(sys.argv[1]); res, eco = "results_go", "go"
GRYPE = os.environ.get("GRYPE", os.path.expanduser("~/bin/grype"))
def pairs(p):
    s = set()
    for m in json.load(open(p)).get("matches", []):
        a = m.get("artifact", {}); s.add(((a.get("purl") or str(a.get("name"))).lower(), m["vulnerability"]["id"]))
    return s
lost, kept, n, tp, tl = set(), set(), 0, 0, 0
for f in sorted(glob.glob(f"{res}/raw/{eco}/*.cdx.json") + glob.glob(f"{res}/reference/{eco}/*.cdx.json")):
    stem = os.path.basename(f)[:-len(".cdx.json")]
    pin = f"{res}/{'vulns_ref' if stem.endswith('_truth') else 'vulns'}/{eco}/{stem}_grype.json"; old = f"{W}/out_grype_0.88.0/{eco}/{stem}_grype.json"
    if os.path.exists(pin) and os.path.exists(old):
        P, O = pairs(pin), pairs(old); n += 1; tp += len(P); tl += len(P - O)
        lost |= {i for _, i in P - O}; kept |= {i for _, i in P & O}
print("Grype 0.88.0 against 0.114.0 on the Go set (raw and reference SBOMs), frozen database 20261030")
print(f"SBOMs compared: {n}; pairs in 0.114.0: {tp}; lost in 0.88.0: {tl}; advisories lost or kept: {len(lost | kept)}")
tab = collections.Counter(); seen = collections.Counter()
for i in sorted(lost | kept):
    out = subprocess.run(["bash", "-c", f"source harness/env_frozen.sh; {GRYPE} db search --vuln {i}"], capture_output=True, text=True).stdout.splitlines()[1:]
    rows = [x.split() for x in out if len(x.split()) >= 4 and x.split()[2] not in ("apk", "deb", "rpm")]
    for r in rows: seen[r[2]] += 1
    blank = any(len(r) == 4 for r in rows); suffix = any(re.search(r"/v\d+$", r[1]) for r in rows)
    status = "all kept" if i not in lost else ("fully lost" if i not in kept else "partly lost")
    tab[(status, "no range" if blank else "has range", "/vN path" if suffix else "plain path")] += 1
print("ecosystems seen:", dict(seen))
for k, v in sorted(tab.items()): print(f"{k[0]:12} {k[1]:10} {k[2]:11} {v}")
