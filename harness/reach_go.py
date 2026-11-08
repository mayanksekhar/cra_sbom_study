#!/usr/bin/env python3
import collections, json, os, subprocess, sys
from pathlib import Path
root = Path(__file__).resolve().parent.parent
src = root / "dataset" / "src_old" / "node_exporter"
db = root / "vulndb" / "20261030" / "govuln"
raw = subprocess.run(["govulncheck", "-format", "json", "-db", "file://" + str(db), "./..."],
                     cwd=src, capture_output=True, text=True).stdout
dec, i, msgs = json.JSONDecoder(), 0, []
while i < len(raw):
    while i < len(raw) and raw[i].isspace():
        i += 1
    if i >= len(raw):
        break
    obj, i = dec.raw_decode(raw, i)
    msgs.append(obj)
level = {}
for m in msgs:
    f = m.get("finding")
    if not f:
        continue
    t = f["trace"][0]
    lv = 3 if t.get("function") else 2 if t.get("package") else 1
    level[f["osv"]] = max(level.get(f["osv"], 0), lv)
names = {3: "called", 2: "imported, not called", 1: "module only"}
print("govulncheck messages:", len(msgs), "| advisories with a finding:", len(level), dict(collections.Counter(names[v] for v in level.values())))
alias = {}
for p in (db / "ID").glob("*.json"):
    d = json.loads(p.read_text())
    alias[d["id"]] = {d["id"]} | set(d.get("aliases") or [])
ms = json.loads((root / "results_old/vulns_ref/go/node_exporter_truth_grype.json").read_text())["matches"]
cat = collections.Counter(); rows = []
for m in ms:
    ids = {m["vulnerability"]["id"]} | {r["id"] for r in m.get("relatedVulnerabilities", [])}
    go = sorted(g for g, al in alias.items() if al & ids)
    if not go:
        c = "no Go DB entry"
    else:
        lv = max((level.get(g, 0) for g in go), default=0)
        c = names.get(lv, "in Go DB, not reported by govulncheck")
    cat[c] += 1
    rows.append((c, m["artifact"]["name"], m["artifact"]["version"], m["vulnerability"]["id"], go[:1]))
print("grype findings on the reference:", len(ms))
for c, n in cat.most_common():
    print(f"  {n:>3}  {c}")
print("examples per category:")
shown = collections.Counter()
for r in rows:
    if shown[r[0]] < 3:
        shown[r[0]] += 1
        print("  ", r[0], "|", r[1], r[2], r[3], r[4])
