"""Scan the truth lists for path style names, odd versions and the product name itself.
Usage (from the repository root): python3 -I harness/truth_scan.py
Reads groundtruth*/ECO/*_{mainmodule,KIND}.txt, prints counts per ecosystem and up to 6 samples per finding."""
import re, glob, collections
from pathlib import Path
KINDS = {"go": ["runtime_multi"], "maven": ["shipped"], "npm": ["shipped", "tree_shipped"], "pypi": ["lock", "shipped"], "rust": ["shipped", "tree_lock"]}
stats = collections.defaultdict(lambda: collections.Counter()); samples = collections.defaultdict(list)
for gdir in sorted(glob.glob("groundtruth*")):
    for eco, kinds in KINDS.items():
        d = Path(gdir) / eco
        if not d.is_dir(): continue
        for mm in sorted(d.glob("*_mainmodule.txt")):
            name = mm.name[: -len("_mainmodule.txt")]; main = mm.read_text().strip().lower()
            for kind in kinds:
                f = d / f"{name}_{kind}.txt"
                if not f.exists(): continue
                for line in f.read_text().split():
                    if not line.startswith("pkg:"): continue
                    typ, _, rest = line[4:].partition("/")
                    i = rest.rfind("@"); path, ver = rest[:i], rest[i + 1:]
                    s = stats[eco]; s["purls"] += 1
                    slash = "/" in path and (typ in ("pypi", "cargo") or (typ == "npm" and not path.startswith("@")))
                    badver = not re.match(r"^v?\d", ver)
                    own = path.lower() == main
                    for flag, hit in (("slash", slash), ("version", badver), ("own", own)):
                        if hit:
                            s[flag] += 1
                            if len(samples[(eco, flag)]) < 6: samples[(eco, flag)].append(f"{gdir}/{eco}/{name}_{kind}: {line}")
for eco, s in stats.items():
    print(f"{eco:6s} purls {s['purls']:7d} | name with a slash {s['slash']:4d} | odd version {s['version']:4d} | product's own name {s['own']:4d}")
for (eco, flag), ex in sorted(samples.items()):
    print(f"-- {eco} {flag}")
    for e in ex: print("   ", e)
