#!/usr/bin/env python3
import csv, re, json
from pathlib import Path
from urllib.parse import unquote

root = Path(__file__).resolve().parent.parent
import os
SUF = os.environ.get("SET_SUFFIX", "")
RES = root / ("results" + SUF)
GTR = root / ("groundtruth" + SUF)
diffs = RES / "diffs"
diffs.mkdir(parents=True, exist_ok=True)
KINDS = {"go": ["declared", "modgraph", "runtime_multi"], "maven": ["all", "shipped"],
         "npm": ["all", "shipped", "tree_all", "tree_shipped"], "pypi": ["shipped", "lock"], "rust": ["lock", "all", "shipped", "tree_lock"]}
TYPE = {"go": "golang", "maven": "maven", "npm": "npm", "pypi": "pypi", "rust": "cargo"}

def norm(purl):
    p = unquote(purl.strip().split("#")[0].split("?")[0])
    if not p.startswith("pkg:"):
        return None
    ptype, _, rest = p[4:].partition("/")
    i = rest.rfind("@")
    path, version = (rest[:i], rest[i + 1:]) if i > 0 else (rest, "")
    path = path.lower()
    if ptype.lower() == "pypi":
        path = re.sub(r"[-_.]+", "-", path)
    return ptype.lower(), path, version

def sbom_purls(path):
    doc = json.loads(path.read_text())
    out = []
    def walk(comps):
        for c in comps or []:
            if c.get("purl"):
                out.append(c["purl"])
            walk(c.get("components"))
    walk(doc.get("components"))
    walk(((doc.get("metadata") or {}).get("component") or {}).get("components"))
    return out

def prf(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return round(p, 3), round(r, 3), round(f, 3)

def fmt(k):
    return "pkg:" + k[0] + "/" + k[1] + ("@" + k[2] if len(k) > 2 and k[2] else "")

levels = (("name", lambda n: n[:2]), ("nv", lambda n: n))
rows = []
for eco, kinds in KINDS.items():
    gt = GTR / eco
    for sbom in sorted((RES / "raw" / eco).glob("*.cdx.json")):
        stem = sbom.name[: -len(".cdx.json")]
        project, tool = stem.rsplit("_", 1)
        base = project.replace("_nolock", "")
        mm = {l.strip().lower() for l in (gt / f"{base}_mainmodule.txt").read_text().split()}
        normed = [n for n in (norm(x) for x in sbom_purls(sbom)) if n]
        eco_all = [n for n in normed if n[0] == TYPE[eco]]
        mvf = gt / f"{base}_mainversion.txt"
        mv = mvf.read_text().strip().lower() if mvf.exists() else None
        comps = [n for n in eco_all if not (n[1] in mm and (mv is None or n[2] in ("", mv)))]
        for kind in kinds:
            tf = gt / f"{base}_{kind}.txt"
            if not tf.exists():
                continue
            truth = {norm(l) for l in tf.read_text().split()}
            truth.discard(None)
            r = {"eco": eco, "project": project, "tool": tool, "truth": kind,
                 "sbom_n": len(comps), "self": len(eco_all) - len(comps),
                 "other": len(normed) - len(eco_all), "dupes": len(comps) - len(set(comps))}
            for level, key in levels:
                got = {key(n) for n in comps}
                exp = {key(n) for n in truth}
                tp, fp, fn = len(got & exp), len(got - exp), len(exp - got)
                p, rc, f = prf(tp, fp, fn)
                r.update({f"{level}_tp": tp, f"{level}_fp": fp, f"{level}_fn": fn,
                          f"{level}_p": p, f"{level}_r": rc, f"{level}_f1": f})
                lines = ["FP " + fmt(k) for k in sorted(got - exp)] + ["FN " + fmt(k) for k in sorted(exp - got)]
                (diffs / f"{project}_{tool}_{kind}_{level}.txt").write_text("\n".join(lines) + "\n")
            rows.append(r)

with open(RES / "metrics.csv", "w", newline="") as fh:
    w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
    w.writeheader()
    w.writerows(rows)

print(f"{'project':<17}{'tool':<8}{'truth':<14}{'n':>5}{'self':>5}{'oth':>5}{'dup':>5} | tp/fp/fn  P/R/F1 (name+ver)")
for r in rows:
    print(f"{r['project']:<17}{r['tool']:<8}{r['truth']:<14}{r['sbom_n']:>5}{r['self']:>5}{r['other']:>5}{r['dupes']:>5} | "
          f"{r['nv_tp']:>3}/{r['nv_fp']:>3}/{r['nv_fn']:>3}  {r['nv_p']:.2f}/{r['nv_r']:.2f}/{r['nv_f1']:.2f}")
