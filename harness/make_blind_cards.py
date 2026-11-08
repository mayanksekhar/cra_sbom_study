#!/usr/bin/env python3
"""Build blind labelling cards for the sampled Go findings. Writes the cards (no oracle answer) and, separately, the answer key."""
import argparse, csv, json, subprocess
from pathlib import Path
root = Path(__file__).resolve().parent.parent
ap = argparse.ArgumentParser()
ap.add_argument("--cards", required=True)
ap.add_argument("--key", required=True)
a = ap.parse_args()
GODB = root / "vulndb" / "20261030" / "govuln" / "ID"

def grep(args, src):
    r = subprocess.run(["grep", "-rn", "--include=*.go"] + args + [str(src)], capture_output=True, text=True)
    out = []
    for l in r.stdout.splitlines():
        f = l.split(":", 1)[0]
        if "/vendor/" in f or f.endswith("_test.go"):
            continue
        out.append(l.replace(str(src) + "/", ""))
    return out

rows = list(csv.DictReader(open(root / "labels" / "label_sample.csv", newline="")))
cards, key = [], []
for r in rows:
    src = root / "dataset" / "src_go" / r["project"]
    p = GODB / (r["advisory"] + ".json")
    rec = json.loads(p.read_text()) if p.exists() else {}
    paths, syms = [], []
    for aff in rec.get("affected", []):
        for imp in (aff.get("ecosystem_specific") or {}).get("imports", []):
            paths.append(imp["path"])
            syms += imp.get("symbols") or []
    short = sorted({s.split(".")[-1] for s in syms if len(s.split(".")[-1]) > 3})[:8]
    hits = []
    for pth in sorted(set(paths)):
        hits += grep(["-F", '"%s"' % pth], src)
    files = sorted({h.split(":", 1)[0] for h in hits})
    uses = []
    if files and short:
        pat = r"\b(" + "|".join(short) + r")\b"
        for f in files[:40]:
            rr = subprocess.run(["grep", "-nE", pat, str(src / f)], capture_output=True, text=True)
            uses += [f"{f}:{l}" for l in rr.stdout.splitlines()]
    cid = r["id"]
    cards.append({"id": cid, "project": r["project"], "module": r["module"], "advisory": r["advisory"],
                  "summary": (rec.get("summary") or r.get("summary") or "")[:200], "packages": sorted(set(paths)), "symbols": short,
                  "import_files": len(files), "import_lines": [h[:160] for h in hits[:4]], "symbol_lines": [u[:160] for u in uses[:4]]})
    key.append({"id": cid, "project": r["project"], "module": r["module"], "advisory": r["advisory"], "govulncheck": r["govulncheck"]})
Path(a.cards).write_text(json.dumps(cards, indent=1))
with open(a.key, "w", newline="") as fh:
    w = csv.DictWriter(fh, fieldnames=list(key[0]))
    w.writeheader()
    w.writerows(key)
print(f"{len(cards)} cards -> {a.cards}; key -> {a.key}")
print("cards with no direct import:", sum(1 for c in cards if c["import_files"] == 0), "| cards with symbol lines:", sum(1 for c in cards if c["symbol_lines"]))
