import sys, json, csv, os
V, W = sys.argv[1], sys.argv[2]
otag = ""
if len(sys.argv) > 3 and sys.argv[3] == "npm2":
    sets = [("npm", "dataset/npm_pinned2.csv", "results_npm/raw/npm")]; tag = "npm2_"
elif len(sys.argv) > 3 and sys.argv[3] in ("pilot", "pilot_old"):
    _p = sys.argv[3]; _csv = "dataset/pilot_pinned.csv" if _p == "pilot" else "dataset/pilot_old_pinned.csv"; _res = "results" if _p == "pilot" else "results_old"
    sets = [(e, _csv, f"{_res}/raw/{e}") for e in ("npm", "go", "maven", "pypi", "rust")]; tag = _p + "_"; otag = "_" + _p
elif len(sys.argv) > 3 and sys.argv[3] == "go_mvn_py":
    sets = [("go", "dataset/go_pinned10.csv", "results_go/raw/go"), ("maven", "dataset/mvn_pinned.csv", "results_mvn/raw/maven"), ("pypi", "dataset/py_pinned.csv", "results_py/raw/pypi")]; tag = "go_mvn_py_"
else:
    sets = [("npm", "dataset/npm_set.csv", "results_npm/raw/npm"),
            ("rust", "dataset/rust_set.csv", "results_rust/raw/rust")]; tag = ""

def load(p):
    d = json.load(open(p))
    return d.get("specVersion"), {c["purl"] for c in d.get("components", []) if c.get("purl")}

rows = [["eco", "project", "pinned_12.9.0", "old_" + V, "common", "only_pinned", "only_old", "old_spec"]]
for eco, c, rd in sets:
    for r in list(csv.reader(open(c)))[1:]:
        if len(r) > 1 and r[1] in ("npm", "go", "maven", "pypi", "rust") and r[1] != eco: continue
        n = r[0]
        new = f"{rd}/{n}_cdxgen.cdx.json"
        old = f"{W}/out_{V}{otag}/{eco}/{n}_cdxgen.cdx.json"
        if not os.path.exists(old):
            rows.append([eco, n, "", "", "", "", "", "no output"]); continue
        try:
            _, a = load(new); spec, b = load(old)
        except Exception as e:
            rows.append([eco, n, "", "", "", "", "", "unreadable"]); continue
        rows.append([eco, n, len(a), len(b), len(a & b), len(a - b), len(b - a), spec])
out = f"{W}/replication_cdxgen_{tag}{V}.csv"
csv.writer(open(out, "w")).writerows(rows)
for r in rows:
    print("%-5s %-16s %13s %10s %7s %11s %8s %s" % tuple(r))
print("written", out)
