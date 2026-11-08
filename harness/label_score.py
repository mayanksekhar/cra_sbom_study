#!/usr/bin/env python3
"""Compare verdict files with the private answer key. Usage: label_score.py KEY.csv VERDICTS.csv [VERDICTS2.csv ...]"""
import collections, csv, itertools, sys
key = {r["id"]: r for r in csv.DictReader(open(sys.argv[1], newline=""))}
vs = {p: {r["id"]: r["verdict"].strip().lower()[:1] for r in csv.DictReader(open(p, newline=""))} for p in sys.argv[2:]}
for p, v in vs.items():
    c = collections.Counter(v.values())
    print(f"== {p}: {len(v)} answered, yes {c['y']}, no {c['n']}, unsure {c['u']}")
    cm = collections.Counter((key[i]["govulncheck"], x) for i, x in v.items() if i in key and x in ("y", "n"))
    print(f"   {'govulncheck':<12}{'you: yes':>9}{'you: no':>9}")
    for g in ("called", "not called"):
        print(f"   {g:<12}{cm[(g, 'y')]:>9}{cm[(g, 'n')]:>9}")
    dec = sum(cm.values())
    if dec:
        ag = cm[("called", "y")] + cm[("not called", "n")]
        print(f"   agreement on {dec} decided answers: {ag} ({100 * ag // dec} percent)")
    for i, x in v.items():
        if i in key and ((key[i]["govulncheck"] == "called" and x == "n") or (key[i]["govulncheck"] == "not called" and x == "y")):
            print(f"   disagreement: card {i} {key[i]['project']} {key[i]['advisory']} govulncheck {key[i]['govulncheck']}, you {x}")
for (p, a), (q, b) in itertools.combinations(vs.items(), 2):
    both = [i for i in a if i in b and a[i] in ("y", "n") and b[i] in ("y", "n")]
    if both:
        s = sum(a[i] == b[i] for i in both)
        print(f"== {p} vs {q}: agree on {s} of {len(both)} cards both decided")
