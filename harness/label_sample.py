#!/usr/bin/env python3
import csv, json, random, subprocess
from pathlib import Path
root = Path(__file__).resolve().parent.parent
R = root / "results_go"
db = root / "vulndb/20261030/govuln/ID"
reach = json.loads((R / "reach.json").read_text())
alias = {}
for p in db.glob("*.json"):
    d = json.loads(p.read_text())
    alias[d["id"]] = d
def go_record(ids):
    for g, d in alias.items():
        if g in ids or set(d.get("aliases") or []) & set(ids):
            return d
    return None
pool = {"called": [], "not called": []}
for name, rows in reach.items():
    for e in rows:
        if e["class"] in pool and go_record(set(e["ids"])):
            pool[e["class"]].append((name, e))
random.seed(20261030)
sample = []
for c in ("called", "not called"):
    sample += [(c,) + x for x in random.sample(pool[c], 20)]
random.shuffle(sample)
out = []
for i, (c, name, e) in enumerate(sample, 1):
    rec = go_record(set(e["ids"]))
    syms = sorted({s for a in rec.get("affected", []) for imp in (a.get("ecosystem_specific") or {}).get("imports", []) for s in (imp.get("symbols") or [])})
    short = sorted({s.split(".")[-1] for s in syms if len(s.split(".")[-1]) > 3})[:6]
    hits = 0
    if c == "not called" and short:
        pat = "|".join(short)
        r = subprocess.run(["grep", "-rEl", "--include=*.go", pat, str(root / "dataset/src_go" / name)], capture_output=True, text=True)
        hits = len([l for l in r.stdout.splitlines() if "/vendor/" not in l and "_test.go" not in l])
    out.append({"id": i, "project": name, "module": e["purl"], "advisory": rec["id"], "summary": rec.get("summary", "")[:110],
                "vulnerable_symbols": " ".join(syms)[:140], "govulncheck": c, "source_files_mentioning_symbols": hits if c == "not called" else "",
                "your_verdict_exploitable_yes_no_unsure": "", "your_notes": ""})
with open(R / "label_sample.csv", "w", newline="") as fh:
    w = csv.DictWriter(fh, fieldnames=list(out[0])); w.writeheader(); w.writerows(out)
print("pool sizes with a Go DB record: called", len(pool["called"]), "not called", len(pool["not called"]))
nc = [o for o in out if o["govulncheck"] == "not called"]
print("sampled not called findings:", len(nc), "| with source mentioning a vulnerable symbol name:", sum(1 for o in nc if o["source_files_mentioning_symbols"]))
for o in nc:
    if o["source_files_mentioning_symbols"]:
        print("   ", o["project"], o["advisory"], o["module"].rsplit("@", 1)[0], "files:", o["source_files_mentioning_symbols"])
print("wrote", R / "label_sample.csv")
