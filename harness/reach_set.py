#!/usr/bin/env python3
import argparse, collections, csv, json, subprocess
from pathlib import Path
from urllib.parse import unquote
root = Path(__file__).resolve().parent.parent
ap = argparse.ArgumentParser()
ap.add_argument("--src", required=True); ap.add_argument("--csv", required=True); ap.add_argument("--res", required=True)
a = ap.parse_args()
R, db = root / a.res, root / "vulndb/20261030/govuln"
alias = {}
for p in (db / "ID").glob("*.json"):
    d = json.loads(p.read_text())
    alias[d["id"]] = {d["id"]} | set(d.get("aliases") or [])
def path_of(purl):
    u = unquote((purl or "").split("?")[0]).lower()
    if u.startswith("pkg:golang/"):
        u = u[len("pkg:golang/"):]
    return u
def parse(raw):
    dec, i, out = json.JSONDecoder(), 0, []
    while i < len(raw):
        while i < len(raw) and raw[i].isspace():
            i += 1
        if i >= len(raw):
            break
        obj, i = dec.raw_decode(raw, i)
        out.append(obj)
    return out
result, tot = {}, collections.Counter()
print(f"{'project':<18}{'status':<10}{'findings':>9}{'called':>8}{'not called':>11}{'unknown':>9}")
for r in csv.DictReader(open(root / a.csv)):
    name = r["name"]
    p = subprocess.run(["govulncheck", "-format", "json", "-db", "file://" + str(db), "./..."], cwd=root / a.src / name, capture_output=True, text=True)
    msgs = parse(p.stdout)
    if not msgs and p.returncode not in (0, 3):
        print(f"{name:<18}FAILED     {p.stderr.strip()[-80:]}")
        continue
    level = {}
    for m in msgs:
        f = m.get("finding")
        if f:
            t = f["trace"][0]
            lv = 3 if t.get("function") else 2 if t.get("package") else 1
            level[f["osv"]] = max(level.get(f["osv"], 0), lv)
    items = []
    for scanner in ("grype", "trivy"):
        d = json.loads((R / "vulns_ref/go" / f"{name}_truth_{scanner}.json").read_text())
        if scanner == "grype":
            for m in d["matches"]:
                items.append((path_of(m["artifact"]["purl"]), {m["vulnerability"]["id"]} | {x["id"] for x in m.get("relatedVulnerabilities", [])}))
        else:
            for res in d.get("Results") or []:
                for v in res.get("Vulnerabilities") or []:
                    items.append((path_of((v.get("PkgIdentifier") or {}).get("PURL")), {v["VulnerabilityID"]} | set(v.get("VendorIDs") or [])))
    merged = []
    for pk, ids in items:
        for e in merged:
            if e[0] == pk and e[1] & ids:
                e[1] |= ids
                break
        else:
            merged.append([pk, set(ids)])
    cls = collections.Counter(); rows = []
    for pk, ids in merged:
        go = [g for g, al in alias.items() if al & ids]
        lv = max((level.get(g, 0) for g in go), default=0)
        c = "called" if lv == 3 else "not called" if lv else "unknown"
        cls[c] += 1
        rows.append({"purl": pk, "ids": sorted(ids), "class": c})
    result[name] = rows
    tot.update(cls)
    print(f"{name:<18}{'ok':<10}{len(merged):>9}{cls['called']:>8}{cls['not called']:>11}{cls['unknown']:>9}")
print(f"{'total':<28}{sum(tot.values()):>9}{tot['called']:>8}{tot['not called']:>11}{tot['unknown']:>9}")
(R / "reach.json").write_text(json.dumps(result))
