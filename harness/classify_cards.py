#!/usr/bin/env python3
"""Classify blind cards by how the vulnerable package relates to the project and add import chains. Usage: classify_cards.py CARDS.json KEY.csv [--check]"""
import argparse, collections, csv, json, re, subprocess
from pathlib import Path
root = Path(__file__).resolve().parent.parent
ap = argparse.ArgumentParser()
ap.add_argument("cards")
ap.add_argument("key")
ap.add_argument("--check", action="store_true", help="compare with the existing cards and key, write nothing")
a = ap.parse_args()
cards = json.loads(Path(a.cards).read_text())
G = {}
def load(p):
    if p not in G:
        src = root / "dataset" / "src_go" / p
        r = subprocess.run(["go", "list", "-deps", "-f", "{{.ImportPath}}\t{{join .Imports \" \"}}\t{{.Dir}}", "./..."], cwd=src, capture_output=True, text=True)
        adj, dirs = {}, {}
        for l in r.stdout.splitlines():
            x = l.split("\t")
            if len(x) >= 3:
                adj[x[0]] = x[1].split()
                dirs[x[0]] = x[2]
        own = subprocess.run(["go", "list", "./..."], cwd=src, capture_output=True, text=True).stdout.split()
        G[p] = (adj, dirs, own)
    return G[p]
def chain(p, target):
    adj, dirs, own = load(p)
    prev = {o: None for o in own if o in adj}
    q = collections.deque(prev)
    while q:
        u = q.popleft()
        if u == target:
            out = []
            while u is not None:
                out.append(u)
                u = prev[u]
            return out[::-1]
        for v in adj.get(u, []):
            if v in adj and v not in prev:
                prev[v] = u
                q.append(v)
    return None
def classify(c):
    adj, dirs, own = load(c["project"])
    if not c["packages"]:
        return "no_package", None, []
    if c["import_files"] > 0:
        return "direct", None, []
    if not adj:
        return "nograph", None, []
    if not any(p in adj for p in c["packages"]):
        return "platform", None, []
    best = None
    for pk in c["packages"]:
        ch = chain(c["project"], pk)
        if ch and (best is None or len(ch) < len(best)):
            best = ch
    if not best:
        return "chain_missing", None, []
    lines = []
    if c["symbols"]:
        pat = re.compile(r"\b(" + "|".join(c["symbols"]) + r")\b")
        for pk in best[-2:]:
            d = dirs.get(pk)
            for f in sorted(Path(d).glob("*.go")) if d else []:
                if f.name.endswith("_test.go"):
                    continue
                for n, l in enumerate(f.read_text(errors="ignore").splitlines(), 1):
                    if pat.search(l) and len(lines) < 6:
                        lines.append(f"{pk.split('/')[-1]}/{f.name}:{n}: {l.strip()[:110]}")
    return "chain", best, lines
keyrows = {r["id"]: r for r in csv.DictReader(open(a.key, newline=""))}
bad = 0
cnt = collections.Counter()
for c in cards:
    g, ch, ln = classify(c)
    cnt[g] += 1
    if a.check:
        ok = c.get("group") == g and c.get("chain") == ch and (c.get("chain_lines") or []) == ln and keyrows.get(str(c["id"]), {}).get("group") == g
        if not ok:
            bad += 1
            print(f"MISMATCH card {c['id']}: now {g}, file {c.get('group')}, key {keyrows.get(str(c['id']), {}).get('group')}")
    else:
        c["group"] = g
        if ch:
            c["chain"], c["chain_lines"] = ch, ln
if a.check:
    print(f"{len(cards)} cards, groups {dict(cnt)}, mismatches {bad}")
else:
    Path(a.cards).write_text(json.dumps(cards, indent=1))
    print(f"wrote {a.cards}: groups {dict(cnt)}. Update the key's group column separately.")
