import sys, json, csv, os, glob
V, W = sys.argv[1], sys.argv[2]
if len(sys.argv) > 3 and sys.argv[3] == "go_mvn_py":
    SETS = (("go", "results_go"), ("maven", "results_mvn"), ("pypi", "results_py")); tag = "go_mvn_py_"
else:
    SETS = (("npm", "results_npm"), ("rust", "results_rust")); tag = ""
def pairs(p):
    d = json.load(open(p))
    s = set()
    for m in d.get("matches", []):
        a = m.get("artifact", {})
        key = (a.get("purl") or (str(a.get("name")) + "@" + str(a.get("version")))).lower()
        s.add((key, m["vulnerability"]["id"]))
    return d.get("descriptor", {}).get("version"), s
rows = [["eco", "sbom", "kind", "pinned_0.114.0", "old_" + V, "common", "only_pinned", "only_old"]]
vers = set(); fail = 0
for eco, res in SETS:
    for f in sorted(glob.glob(f"{res}/raw/{eco}/*.cdx.json") + glob.glob(f"{res}/reference/{eco}/*.cdx.json")):
        stem = os.path.basename(f)[: -len(".cdx.json")]
        kind = "reference" if stem.endswith("_truth") else "generator"
        pin = f"{res}/{'vulns_ref' if kind == 'reference' else 'vulns'}/{eco}/{stem}_grype.json"
        old = f"{W}/out_grype_{V}/{eco}/{stem}_grype.json"
        try:
            _, a = pairs(pin); v, b = pairs(old); vers.add(v)
        except Exception as e:
            fail += 1; rows.append([eco, stem, kind, "", "", "", "", "unreadable"]); continue
        rows.append([eco, stem, kind, len(a), len(b), len(a & b), len(a - b), len(b - a)])
out = f"{W}/replication_grype_{tag}{V}.csv"
csv.writer(open(out, "w")).writerows(rows)
data = [r for r in rows[1:] if r[3] != ""]
print(f"grype {V}: descriptor version in the outputs {sorted(vers)}; sboms {len(rows) - 1}, unreadable {fail}")
for eco in [s[0] for s in SETS]:
    for kind in ("generator", "reference"):
        s = [r for r in data if r[0] == eco and r[2] == kind]
        print(f"  {eco:5s} {kind:9s} sboms {len(s):3d} pinned {sum(r[3] for r in s):6d} old {sum(r[4] for r in s):6d} common {sum(r[5] for r in s):6d} only_pinned {sum(r[6] for r in s):5d} only_old {sum(r[7] for r in s):5d}")
diff = [r for r in data if r[6] or r[7]]
print(f"  sboms with any difference: {len(diff)} of {len(data)}")
for r in diff:
    print("   %-5s %-26s %-9s pinned %5d old %5d common %5d only_pinned %4d only_old %4d" % tuple(r))
print("written", out)
