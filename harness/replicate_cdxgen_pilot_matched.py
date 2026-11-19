#!/usr/bin/env python3
"""usage: replicate_cdxgen_pilot_matched.py WORKDIR VERSION   (run from the repository root)
Purl sets of the pilot sets: stored pinned SBOM, a fresh run of cdxgen 12.9.0 and an old cdxgen, at purl and at name level.
Writes WORKDIR/replication_cdxgen_pilot_matched_VERSION.csv and prints the projects that differ."""
import csv, json, os, sys
W, V = sys.argv[1], sys.argv[2]
SETS = (("pilot", "dataset/pilot_pinned.csv", "results"), ("pilot_old", "dataset/pilot_old_pinned.csv", "results_old"))
def purls(p):
    if not os.path.exists(p): return None
    return {c["purl"] for c in json.load(open(p)).get("components", []) if c.get("purl")}
def names(s): return {x.split("?")[0].split("#")[0].rsplit("@", 1)[0] for x in s}
H = ["set", "eco", "project", "stored", "fresh", "old", "stored_not_fresh", "fresh_not_stored", "fresh_not_old", "old_not_fresh", "names_fresh_not_old", "names_old_not_fresh"]
rows = [H]
for sname, c, res in SETS:
    for r in list(csv.reader(open(c)))[1:]:
        name, eco = r[0], r[1]
        S = purls(f"{res}/raw/{eco}/{name}_cdxgen.cdx.json")
        R = purls(f"{W}/out_12.9.0_{sname}/{eco}/{name}_cdxgen.cdx.json")
        O = purls(f"{W}/out_{V}_{sname}/{eco}/{name}_cdxgen.cdx.json")
        if S is None or R is None or O is None:
            rows.append([sname, eco, name] + [""] * 8 + ["no output"]); continue
        NR, NO = names(R), names(O)
        rows.append([sname, eco, name, len(S), len(R), len(O), len(S - R), len(R - S), len(R - O), len(O - R), len(NR - NO), len(NO - NR)])
out = f"{W}/replication_cdxgen_pilot_matched_{V}.csv"
csv.writer(open(out, "w")).writerows(rows)
body = rows[1:]
same = [r for r in body if r[-1] != "no output" and r[8] == 0 and r[9] == 0]
print(f"cdxgen {V}: {len(body)} projects, fresh 12.9.0 equals old in {len(same)}, stored equals fresh in {sum(1 for r in body if r[-1] != 'no output' and r[6] == 0 and r[7] == 0)}")
print("%-9s %-6s %-16s %6s %6s %6s %8s %8s %8s %8s %8s %8s" % tuple(H))
for r in body:
    if r[-1] == "no output" or r[6] or r[7] or r[8] or r[9]:
        print("%-9s %-6s %-16s %6s %6s %6s %8s %8s %8s %8s %8s %8s" % tuple(r))
print("written", out)
