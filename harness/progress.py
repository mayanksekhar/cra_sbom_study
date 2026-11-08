#!/usr/bin/env python3
import collections, csv
from pathlib import Path
rows = list(csv.DictReader(open(Path(__file__).resolve().parent.parent / "docs" / "progress.csv")))
w, d, order = collections.Counter(), collections.Counter(), []
for r in rows:
    assert 0 <= float(r["done"]) <= float(r["weight"]), "done exceeds weight: " + r["item"]
    if r["phase"] not in order:
        order.append(r["phase"])
    w[r["phase"]] += float(r["weight"]); d[r["phase"]] += float(r["done"])
print(f"{'phase':<32}{'weight':>7}{'done':>7}")
for p in order:
    print(f"{p:<32}{w[p]:>7.1f}{d[p]:>7.1f}")
print(f"{'total':<32}{sum(w.values()):>7.1f}{sum(d.values()):>7.1f}   ({100 * sum(d.values()) / sum(w.values()):.1f} percent)")
print("\nnot done yet:")
for r in rows:
    if float(r["done"]) < float(r["weight"]):
        print(f"   {float(r['weight']) - float(r['done']):>4.1f}  {r['phase']}: {r['item']}")
