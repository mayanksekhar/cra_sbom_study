#!/usr/bin/env python3
"""Mechanical check of reachability verdicts: is the vulnerable symbol present in the built product binary? Writes only to --out."""
import argparse, collections, csv, json, subprocess
from pathlib import Path
root = Path(__file__).resolve().parent.parent
ap = argparse.ArgumentParser()
ap.add_argument("--out", default="/tmp/mech")
ap.add_argument("--gcflags", default="", help="for example all=-l to disable inlining")
ap.add_argument("--projects", default="", help="comma separated subset")
a = ap.parse_args()
out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
DB = root / "vulndb" / "20261030" / "govuln" / "ID"
MAINS = {"alertmanager": ["./cmd/alertmanager", "./cmd/amtool"], "blackbox_exporter": ["."], "restic": ["./cmd/restic"], "fzf": ["."],
         "k9s": ["."], "helm": ["./cmd/helm"], "caddy": ["./cmd/caddy"], "nats-server": ["."], "cli": ["./cmd/gh"], "hugo": ["."]}
reach = json.loads((root / "results_go" / "reach.json").read_text())

def build(p):
    syms, ok = set(), []
    for i, m in enumerate(MAINS[p]):
        b = out / f"{p}_{i}.bin"
        r = subprocess.run(["go", "build"] + (["-gcflags=" + a.gcflags] if a.gcflags else []) + ["-o", str(b), m], cwd=root / "dataset" / "src_go" / p, capture_output=True, text=True)
        if r.returncode != 0:
            print(f"BUILD FAILED {p} {m}: {(r.stderr.strip().splitlines() or [''])[-1][:100]}", flush=True)
            continue
        nm = subprocess.run(["go", "tool", "nm", str(b)], capture_output=True, text=True).stdout
        syms |= {l.split(None, 2)[2] for l in nm.splitlines() if len(l.split(None, 2)) == 3}
        ok.append(m)
    return syms, ok

def forms(pkg, s):
    if "." in s:
        t, m = s.split(".", 1)
        return [f"{pkg}.{s}", f"{pkg}.(*{t}).{m}"]
    return [f"{pkg}.{s}"]

rows = []
cross = collections.Counter()
called_absent = []
for p, es in reach.items():
    if a.projects and p not in a.projects.split(","):
        continue
    syms, ok = build(p)
    pkgs_present = {x.rsplit(".", 1)[0] if "(" not in x else x.split(".(")[0] for x in syms}
    print(f"{p}: built {len(ok)} of {len(MAINS[p])} binaries, {len(syms)} symbols", flush=True)
    for e in es:
        gids = [i for i in e["ids"] if i.startswith("GO-")]
        if not ok:
            res = "no binary"
        elif not gids:
            res = "no GO id"
        else:
            fn_hit = fn_total = pkg_hit = pkg_total = 0
            for g in gids:
                rp = DB / (g + ".json")
                if not rp.exists():
                    continue
                for aff in json.loads(rp.read_text())["affected"]:
                    for imp in (aff.get("ecosystem_specific") or {}).get("imports", []):
                        pkg_total += 1
                        pp = imp["path"]
                        if any(x.startswith(pp + ".") for x in syms):
                            pkg_hit += 1
                        for s in imp.get("symbols") or []:
                            fn_total += 1
                            if any(f in syms for f in forms(pp, s)):
                                fn_hit += 1
            if fn_total:
                res = "function present" if fn_hit else "all listed functions absent"
            elif pkg_total:
                res = "package symbols present" if pkg_hit else "package absent"
            else:
                res = "no record"
        cross[(e["class"], res)] += 1
        rows.append([p, e["purl"], ";".join(e["ids"]), e["class"], res])
        if e["class"] == "called" and res in ("all listed functions absent", "package absent"):
            called_absent.append((p, e["purl"], e["ids"][:3], res))
with open(out / "mech_result.csv", "w", newline="") as fh:
    w = csv.writer(fh); w.writerow(["project", "purl", "ids", "govulncheck", "mechanical"]); w.writerows(rows)
res_all = sorted({r for _, r in cross})
print("\ngovulncheck class x mechanical result (findings)")
print(f"{'class':<12}" + "".join(f"{r[:22]:>24}" for r in res_all))
for c in ("called", "not called", "unknown"):
    print(f"{c:<12}" + "".join(f"{cross[(c, r)]:>24}" for r in res_all))
print("\ncalled but absent from the binary:", len(called_absent))
for x in called_absent[:15]:
    print("  ", x)
print("result file:", out / "mech_result.csv")
