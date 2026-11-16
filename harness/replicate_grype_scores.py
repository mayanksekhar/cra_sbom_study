import csv, sys, collections
V = sys.argv[1]; S = sys.argv[2]; tag = "g088"
cols = ["ref_n", "tp", "fp", "fn", "fn_component_absent", "fn_no_version", "fn_wrong_version", "fn_scanner_miss"]
rows = [["eco", "project", "generator", "scanner"] + ["pinned_" + c for c in cols] + ["old_" + c for c in cols]]
for eco in ("npm", "rust"):
    a = {(r["project"], r["tool"], r["scanner"]): r for r in csv.DictReader(open(f"results_{eco}/findings_vs_reference.csv"))}
    b = {(r["project"], r["tool"], r["scanner"]): r for r in csv.DictReader(open(f"{S}/results_{eco}_{tag}/findings_vs_reference.csv"))}
    assert set(a) == set(b), (eco, len(a), len(b))
    for k in sorted(a):
        rows.append([eco, k[0], k[1], k[2]] + [a[k][c] for c in cols] + [b[k][c] for c in cols])
out = f"results_replication/replication_grype_scores_{V}.csv"
csv.writer(open(out, "w")).writerows(rows)
body = rows[1:]
n = len(cols)
print(f"rows {len(body)} (projects x generators x scanners)")
for scanner in ("grype", "trivy"):
    d = [r for r in body if r[3] == scanner and r[4:4 + n] != r[4 + n:]]
    print(f"{scanner}: rows whose scores differ from the pinned run: {len(d)} of {sum(1 for r in body if r[3] == scanner)}")
print("\ngrype by generator (pinned / old 0.88.0): reference findings, found, missed, extra, absent, scanner miss")
for gen in ("syft", "trivy", "cdxgen"):
    s = [r for r in body if r[3] == "grype" and r[2] == gen]
    t = lambda off, i: sum(int(r[off + i]) for r in s)
    f = lambda i: f"{t(4, i):5d} / {t(4 + n, i):5d}"
    print(f"  {gen:7s} ref {f(0)}  tp {f(1)}  fn {f(3)}  fp {f(2)}  absent {f(4)}  scanner_miss {f(7)}")
print("\nrows where found, missed or scanner miss differ (grype):")
for r in body:
    if r[3] != "grype":
        continue
    P = lambda k: r[4 + k]
    O = lambda k: r[4 + n + k]
    if P(1) != O(1) or P(3) != O(3) or P(7) != O(7):
        print(f"  {r[0]:5s} {r[1]:13s} {r[2]:7s} ref {P(0)} tp {P(1)} to {O(1)}  fn {P(3)} to {O(3)}  absent {P(4)} to {O(4)}  scanner_miss {P(7)} to {O(7)}")
print("written", out)
