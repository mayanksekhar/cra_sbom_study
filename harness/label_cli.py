#!/usr/bin/env python3
"""Blind labelling. Usage: label_cli.py CARDS.json VERDICTS.csv [--max N] [--skip 1,2] [--all]. Each answer is saved at once, a rerun resumes."""
import argparse, csv, json
from pathlib import Path
ap = argparse.ArgumentParser()
ap.add_argument("cards")
ap.add_argument("verdicts")
ap.add_argument("--max", type=int, default=0)
ap.add_argument("--skip", default="", help="comma separated card ids to leave out")
ap.add_argument("--all", action="store_true", help="include cards no human can decide (platform, no_package)")
a = ap.parse_args()
cards = json.loads(Path(a.cards).read_text())
skip = {s.strip() for s in a.skip.split(",") if s.strip()}
vp = Path(a.verdicts)
done = {str(r["id"]) for r in csv.DictReader(open(vp, newline=""))} if vp.exists() else set()
todo = [c for c in cards if str(c["id"]) not in done and str(c["id"]) not in skip and (a.all or c.get("group") in ("direct", "chain"))]
print(f"{len(done)} answered, {len(todo)} to go.")
print("Question: could an attacker trigger this advisory in this product as shipped?")
print("Answer y (yes), n (no, you can see why not), u (unsure). Add a short note after the letter. s skips, q quits.")
print("A name match below is not proof of a call. If you cannot tell in a couple of minutes, answer u.")
print("Please do not look up any tool's verdict for these findings before answering.")
n = 0
for c in todo:
    if a.max and n >= a.max:
        break
    print("\n" + "=" * 78)
    print(f"Card {c['id']}   [{c.get('group', '?')}]   project: {c['project']}   module: {c['module']}")
    print(f"advisory: {c['advisory']}   {c['summary']}")
    print(f"vulnerable package(s): {', '.join(c['packages']) or 'not listed'}")
    print(f"vulnerable symbols:    {', '.join(c['symbols']) or 'not listed (whole package)'}")
    g = c.get("group")
    if g == "direct":
        print(f"files in the project's own source that import the package: {c['import_files']}")
        for l in c["import_lines"]:
            print("   ", l)
        if c["symbol_lines"]:
            print("lines in those files that mention a vulnerable symbol name:")
            for l in c["symbol_lines"]:
                print("   ", l)
    elif g == "chain":
        print("The project's own code does not import the package directly. Import chain, project first:")
        for i, p in enumerate(c["chain"]):
            print("   " + ("> " if i else "  ") + p)
        if c.get("chain_lines"):
            print("lines in the last two packages of the chain that mention a vulnerable symbol name:")
            for l in c["chain_lines"]:
                print("   ", l)
        else:
            print("no line in the last two packages mentions a vulnerable symbol name")
    elif g == "platform":
        print("This package is not in the Linux build graph of the project. Not scored: answer u or s.")
    elif g == "no_package":
        print("The advisory record names no importable package. Not scored: answer u or s.")
    while True:
        try:
            ans = input("verdict [y/n/u/s/q] and note> ").strip()
        except EOFError:
            ans = "q"
        if not ans:
            continue
        ch = ans[0].lower()
        if ch in "ynu":
            new = not vp.exists()
            with open(vp, "a", newline="") as fh:
                w = csv.writer(fh)
                if new:
                    w.writerow(["id", "verdict", "note"])
                w.writerow([c["id"], ch, ans[1:].strip()])
            n += 1
            break
        if ch == "s":
            break
        if ch == "q":
            print("saved, stopping")
            raise SystemExit(0)
        print("type y, n, u, s or q")
print(f"\nthis sitting: {n} answered. Send the verdicts file back.")
