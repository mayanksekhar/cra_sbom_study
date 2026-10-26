#!/usr/bin/env python3
import json, csv
from pathlib import Path
from urllib.parse import unquote

root = Path(__file__).resolve().parent.parent
diffs = root / "results" / "diffs"
diffs.mkdir(parents=True, exist_ok=True)

def norm(purl):
    p = purl.strip().split("#")[0].split("?")[0]
    p = unquote(p)
    if not p.startswith("pkg:"):
        return None
    ptype, _, rest = p[4:].partition("/")
    path, _, version = rest.partition("@")
    return ptype.lower(), path.lower(), version

def sbom_purls(path):
    doc = json.loads(path.read_text())
    out = []
    def walk(comps):
        for c in comps or []:
            if c.get("purl"):
                out.append(c["purl"])
            walk(c.get("components"))
    walk(doc.get("components"))
    return out

def prf(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return round(p, 3), round(r, 3), round(f, 3)

def fmt(k):
    return "pkg:" + k[0] + "/" + k[1] + ("@" + k[2] if len(k) > 2 else "")

levels = (("name", lambda n: n[:2]), ("nv", lambda n: n))
rows = []
for sbom in sorted((root / "results" / "raw" / "go").glob("*.cdx.json")):
    stem = sbom.name[: -len(".cdx.json")]
    project, tool = stem.rsplit("_", 1)
    normed = [n for n in (norm(x) for x in sbom_purls(sbom)) if n]
    go = [n for n in normed if n[0] == "golang"]
    for kind in ("modgraph", "runtime"):
        tfile = root / "groundtruth" / "go" / f"{project}_{kind}.txt"
        truth = {norm(l) for l in tfile.read_text().split()}
        truth.discard(None)
        r = {"project": project, "tool": tool, "truth": kind,
             "sbom_go": len(go), "other": len(normed) - len(go),
             "dupes": len(go) - len(set(go))}
        for level, key in levels:
            got = {key(n) for n in go}
            exp = {key(n) for n in truth}
            tp, fp, fn = len(got & exp), len(got - exp), len(exp - got)
            p, rc, f = prf(tp, fp, fn)
            r.update({f"{level}_tp": tp, f"{level}_fp": fp, f"{level}_fn": fn,
                      f"{level}_p": p, f"{level}_r": rc, f"{level}_f1": f})
            lines = ["FP " + fmt(k) for k in sorted(got - exp)] + ["FN " + fmt(k) for k in sorted(exp - got)]
            (diffs / f"{project}_{tool}_{kind}_{level}.txt").write_text("\n".join(lines) + "\n")
        rows.append(r)

with open(root / "results" / "metrics_go.csv", "w", newline="") as fh:
    w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
    w.writeheader()
    w.writerows(rows)

print(f"{'project':<14}{'tool':<8}{'truth':<9}{'n':>4}{'oth':>4}{'dup':>4} | name P/R/F1       | name+ver tp/fp/fn  P/R/F1")
for r in rows:
    print(f"{r['project']:<14}{r['tool']:<8}{r['truth']:<9}{r['sbom_go']:>4}{r['other']:>4}{r['dupes']:>4} | "
          f"{r['name_p']:.2f}/{r['name_r']:.2f}/{r['name_f1']:.2f} | "
          f"{r['nv_tp']:>3}/{r['nv_fp']:>3}/{r['nv_fn']:>3}  {r['nv_p']:.2f}/{r['nv_r']:.2f}/{r['nv_f1']:.2f}")
