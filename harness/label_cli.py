#!/usr/bin/env python3
"""Blind labelling. Usage: python3 label_cli.py CARDS.json VERDICTS.csv [--max N]. Each answer is saved at once, a rerun resumes."""
import argparse, csv, json
from pathlib import Path
ap = argparse.ArgumentParser()
ap.add_argument("cards")
ap.add_argument("verdicts")
ap.add_argument("--max", type=int, default=0)
a = ap.parse_args()
cards = json.loads(Path(a.cards).read_text())
vp = Path(a.verdicts)
done = set()
if vp.exists():
    done = {str(r["id"]) for r in csv.DictReader(open(vp, newline=""))}
todo = [c for c in cards if str(c["id"]) not in done]
print(f"{len(done)} answered, {len(todo)} to go.")
print("Question: could an attacker trigger this advisory in this product as shipped?")
print("Answer y (yes), n (no, you can see why not), u (unsure). Add a short note after the letter. s skips, q quits.")
print("Please do not look up any tool's verdict for these findings before answering.")
n = 0
for c in todo:
    if a.max and n >= a.max:
        break
    print("\n" + "=" * 78)
    print(f"Card {c['id']}   project: {c['project']}   module: {c['module']}")
    print(f"advisory: {c['advisory']}   {c['summary']}")
    print(f"vulnerable package(s): {', '.join(c['packages']) or 'not listed'}")
    print(f"vulnerable symbols:    {', '.join(c['symbols']) or 'not listed (whole package)'}")
    print(f"files in the project's own source that import those package(s): {c['import_files']}")
    for l in c["import_lines"]:
        print("   ", l)
    if c["symbol_lines"]:
        print("lines in those files that mention a vulnerable symbol name (name match only, not proof of a call):")
        for l in c["symbol_lines"]:
            print("   ", l)
    elif c["import_files"] == 0:
        print("no direct import: any use would go through another dependency")
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
