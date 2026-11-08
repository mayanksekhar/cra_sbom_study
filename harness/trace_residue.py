#!/usr/bin/env python3
import collections, json
from pathlib import Path
from urllib.parse import unquote
root = Path(__file__).resolve().parent.parent
R = root / "results_go"
db = root / "vulndb/20261030/govuln/ID"
reach = json.loads((R / "reach.json").read_text())
godb = {}
for p in db.glob("*.json"):
    d = json.loads(p.read_text())
    for i in {d["id"]} | set(d.get("aliases") or []):
        godb.setdefault(i, set()).add(d["id"])

print("== A. findings with no govulncheck verdict (class unknown)")
rows, kinds, byproj = [], collections.Counter(), collections.Counter()
for name, es in sorted(reach.items()):
    for e in es:
        if e["class"] != "unknown":
            continue
        has = any(i in godb for i in e["ids"])
        kinds["Go DB record exists, no verdict" if has else "no Go DB record under any alias"] += 1
        byproj[name] += 1
        rows.append((name, e["purl"], sorted(e["ids"]), has))
print("total:", len(rows), dict(byproj))
print(dict(kinds))
for r in rows:
    print("  ", r[0], r[1], r[2], "(Go DB record)" if r[3] else "(no Go DB record)")

def path_of(purl):
    u = unquote((purl or "").split("?")[0]).lower()
    return u[len("pkg:golang/"):] if u.startswith("pkg:golang/") else u
def g_items(f):
    return [(path_of(m["artifact"]["purl"]), {m["vulnerability"]["id"]} | {r["id"] for r in m.get("relatedVulnerabilities", [])})
            for m in json.loads(Path(f).read_text())["matches"]]
def t_items(f):
    out = []
    for res in json.loads(Path(f).read_text()).get("Results") or []:
        for v in res.get("Vulnerabilities") or []:
            out.append((path_of((v.get("PkgIdentifier") or {}).get("PURL")), {v["VulnerabilityID"]} | set(v.get("VendorIDs") or [])))
    return out
def only(a, b):
    return [(k, ids) for k, ids in a if not any(k == k2 and ids & ids2 for k2, ids2 in b)]
def cls(name, k, ids):
    for e in reach[name]:
        if e["purl"] == k and set(e["ids"]) & ids:
            return e["class"]
    return "not in reach.json"

print("\n== B. findings only one scanner reports on the reference SBOMs")
c_g, c_t, per = collections.Counter(), collections.Counter(), {}
for name in sorted(reach):
    g = g_items(R / "vulns_ref/go" / f"{name}_truth_grype.json")
    t = t_items(R / "vulns_ref/go" / f"{name}_truth_trivy.json")
    go_, to_ = only(g, t), only(t, g)
    per[name] = (len(go_), len(to_))
    for k, ids in go_:
        c_g[cls(name, k, ids)] += 1
    for k, ids in to_:
        c_t[cls(name, k, ids)] += 1
print("per project (grype only, trivy only):", {k: v for k, v in per.items() if v != (0, 0)})
print("grype only by class:", dict(c_g), "| total", sum(c_g.values()))
print("trivy only by class:", dict(c_t), "| total", sum(c_t.values()))
print("expected from the VEX test: 356 minus 353 = 3 not called findings that Trivy does not see")
