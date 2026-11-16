import csv, sys
DOC = "docs/draft_front_back.md"
fails = []
def need(cond, msg):
    if not cond:
        fails.append(msg)
tot = {}
for v in ("11.11.0", "10.11.0"):
    rows = list(csv.DictReader(open(f"results_replication/replication_cdxgen_{v}.csv")))
    need(len(rows) == 11, f"{v}: {len(rows)} rows, expected 11")
    need(sum(r["eco"] == "npm" for r in rows) == 3, f"{v}: npm rows")
    need(sum(r["eco"] == "rust" for r in rows) == 8, f"{v}: rust rows")
    for r in rows:
        a, b, c = int(r["pinned_12.9.0"]), int(r["old_" + v]), int(r["common"])
        need(a == b == c, f"{v} {r['project']}: {a} {b} {c}")
        need(r["only_pinned"] == "0" and r["only_old"] == "0", f"{v} {r['project']}: differing purls")
        need(r["old_spec"] == "1.6", f"{v} {r['project']}: spec {r['old_spec']}")
    tot[v] = sum(int(r["pinned_12.9.0"]) for r in rows)
need(tot["11.11.0"] == tot["10.11.0"], "pinned totals differ between the two files")
text = open(DOC).read()
for phrase in ("cdxgen 10.11.0 and 11.11.0", "identical purl sets in all 11 projects"):
    need(phrase in text, f"missing in {DOC}: {phrase}")
g = {}
for v in ("0.88.0", "0.90.0", "0.95.0", "0.100.0"):
    rows = list(csv.DictReader(open(f"results_replication/replication_grype_{v}.csv")))
    need(len(rows) == 76, f"grype {v}: {len(rows)} rows, expected 76")
    need(sum(r["kind"] == "reference" for r in rows) == 19, f"grype {v}: reference rows")
    need(all(r["only_pinned"] == "0" and r["only_old"] == "0" for r in rows if r["kind"] == "reference"), f"grype {v}: reference sboms differ")
    g[v] = rows
def differs(r):
    return r["only_pinned"] != "0" or r["only_old"] != "0"
for v in ("0.95.0", "0.100.0"):
    need(not any(differs(r) for r in g[v]), f"grype {v}: differs from 0.114.0")
    need(sum(int(r["pinned_0.114.0"]) for r in g[v]) == 3061, f"grype {v}: pinned pair total")
r90 = g["0.90.0"]
need(sum(differs(r) for r in r90) == 15, "grype 0.90.0: expected 15 differing sboms")
need(sum(int(r["only_old"]) for r in r90) == 402, "grype 0.90.0: only_old total")
need(sum(int(r["only_pinned"]) for r in r90) == 89, "grype 0.90.0: only_pinned total")
need(all(r["sbom"].endswith(("_cdxgen", "_trivy")) for r in r90 if differs(r) and r["eco"] == "npm"), "grype 0.90.0: a differing npm sbom is not group style")
need(all(r["sbom"] == "starship_syft" for r in r90 if differs(r) and r["eco"] == "rust"), "grype 0.90.0: rust difference outside starship_syft")
sc = list(csv.DictReader(open("results_replication/replication_grype_scores_0.88.0.csv")))
need(all(r["pinned_fn_scanner_miss"] == "0" for r in sc), "scores: pinned scanner misses not 0")
miss = [r for r in sc if r["old_fn_scanner_miss"] != "0"]
need(len(miss) == 2 and all(r["project"] == "uptime-kuma" and r["scanner"] == "grype" and r["generator"] in ("cdxgen", "trivy") and r["old_fn_scanner_miss"] == "6" for r in miss), "scores: 0.88.0 scanner misses are not the two uptime-kuma rows")
for phrase in ("Grype 0.88.0, 0.90.0, 0.95.0 and 0.100.0 were rerun",):
    need(phrase in text, f"missing in {DOC}: {phrase}")
if fails:
    print("FAILED"); [print(" ", f) for f in fails]; sys.exit(1)
print("replication ok: 2 versions x 11 projects identical to 12.9.0, %d purls compared per version" % tot["11.11.0"])
print("grype replication ok: 0.95.0 and 0.100.0 identical to 0.114.0 on 76 sboms; 0.90.0 differs on 15; 0.88.0 shows 6 scanner misses in two uptime-kuma rows")
