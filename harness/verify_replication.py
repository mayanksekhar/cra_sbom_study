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
if fails:
    print("FAILED"); [print(" ", f) for f in fails]; sys.exit(1)
print("replication ok: 2 versions x 11 projects identical to 12.9.0, %d purls compared per version" % tot["11.11.0"])
