#!/usr/bin/env python3
"""Compare verdict files with the private answer key, direct and chain cards only. Usage: label_score.py KEY.csv VERDICTS.csv [VERDICTS2.csv ...] [--skip 1,2]"""
import argparse, collections, csv, itertools
ap = argparse.ArgumentParser()
ap.add_argument("key")
ap.add_argument("verdicts", nargs="+")
ap.add_argument("--skip", default="", help="card ids that were not blind for this labeller")
a = ap.parse_args()
skip = {s.strip() for s in a.skip.split(",") if s.strip()}
key = {r["id"]: r for r in csv.DictReader(open(a.key, newline=""))}
scored = {i for i, r in key.items() if r.get("group", "direct") in ("direct", "chain") and i not in skip}
vs = {p: {r["id"]: r["verdict"].strip().lower()[:1] for r in csv.DictReader(open(p, newline=""))} for p in a.verdicts}
print(f"scored cards (direct and chain, minus skipped): {len(scored)}")
for p, v in vs.items():
    v = {i: x for i, x in v.items() if i in scored}
    c = collections.Counter(v.values())
    print(f"== {p}: {len(v)} of {len(scored)} answered, yes {c['y']}, no {c['n']}, unsure {c['u']}")
    cm = collections.Counter((key[i]["govulncheck"], x) for i, x in v.items() if x in ("y", "n"))
    print(f"   {'govulncheck':<12}{'you: yes':>9}{'you: no':>9}")
    for g in ("called", "not called"):
        print(f"   {g:<12}{cm[(g, 'y')]:>9}{cm[(g, 'n')]:>9}")
    dec = sum(cm.values())
    if dec:
        ag = cm[("called", "y")] + cm[("not called", "n")]
        print(f"   agreement on {dec} decided answers: {ag} ({100 * ag // dec} percent)")
    for i, x in v.items():
        if (key[i]["govulncheck"] == "called" and x == "n") or (key[i]["govulncheck"] == "not called" and x == "y"):
            print(f"   disagreement: card {i} {key[i]['project']} {key[i]['advisory']} govulncheck {key[i]['govulncheck']}, you {x}")
for (p, x), (q, y) in itertools.combinations(vs.items(), 2):
    both = [i for i in x if i in y and i in scored and x[i] in ("y", "n") and y[i] in ("y", "n")]
    if both:
        print(f"== {p} vs {q}: agree on {sum(x[i] == y[i] for i in both)} of {len(both)} cards both decided")
