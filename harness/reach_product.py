#!/usr/bin/env python3
"""Product level reachability: govulncheck on the product packages only, one project per invocation, same classification as reach_set.py.
Usage: reach_product.py run PROJECT | check | merge"""
import collections, json, subprocess, sys
from pathlib import Path
from urllib.parse import unquote
root = Path(__file__).resolve().parent.parent
R, db = root / "results_go", root / "vulndb/20261030/govuln"
OUTD = R / "reach_product"
TARGETS = {"alertmanager": ["./cmd/alertmanager", "./cmd/amtool"], "blackbox_exporter": ["."], "restic": ["./cmd/restic"], "fzf": ["."], "k9s": ["."],
           "helm": ["./cmd/helm"], "caddy": ["./cmd/caddy"], "nats-server": ["."], "cli": ["./cmd/gh"], "hugo": ["."]}

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

def run(name):
    alias = {}
    for p in (db / "ID").glob("*.json"):
        d = json.loads(p.read_text())
        alias[d["id"]] = {d["id"]} | set(d.get("aliases") or [])
    p = subprocess.run(["govulncheck", "-format", "json", "-db", "file://" + str(db), *TARGETS[name]], cwd=root / "dataset/src_go" / name, capture_output=True, text=True)
    msgs = parse(p.stdout)
    if not msgs and p.returncode not in (0, 3):
        print(f"FAILED {name}: {p.stderr.strip()[-120:]}")
        sys.exit(2)
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
    cls, rows = collections.Counter(), []
    for pk, ids in merged:
        go = [g for g, al in alias.items() if al & ids]
        lv = max((level.get(g, 0) for g in go), default=0)
        c = "called" if lv == 3 else "not called" if lv else "unknown"
        cls[c] += 1
        rows.append({"purl": pk, "ids": sorted(ids), "class": c})
    OUTD.mkdir(exist_ok=True)
    (OUTD / f"{name}.json").write_text(json.dumps(rows))
    print(f"{name}: findings {len(merged)}, called {cls['called']}, not called {cls['not called']}, unknown {cls['unknown']}")

def check():
    for name, tg in TARGETS.items():
        r = subprocess.run(["go", "list", *tg], cwd=root / "dataset/src_go" / name, capture_output=True, text=True)
        print(f"{name:<18}{'ok  ' + ' '.join(r.stdout.split())[:70] if r.returncode == 0 else 'ERROR ' + r.stderr.strip()[-80:]}")

def merge():
    old = json.loads((R / "reach.json").read_text())
    new, missing = {}, []
    for name in TARGETS:
        f = OUTD / f"{name}.json"
        if f.exists():
            new[name] = json.loads(f.read_text())
        else:
            missing.append(name)
    to, tn, trans = collections.Counter(), collections.Counter(), collections.Counter()
    print(f"{'project':<18}{'old: called':>12}{'not':>6}{'unk':>5}{'new: called':>13}{'not':>6}{'unk':>5}")
    for name, rows in new.items():
        om = {(e["purl"], tuple(e["ids"])): e["class"] for e in old[name]}
        co, cn = collections.Counter(e["class"] for e in old[name]), collections.Counter(r["class"] for r in rows)
        to.update(co); tn.update(cn)
        for r in rows:
            trans[(om.get((r["purl"], tuple(r["ids"])), "(not in old)"), r["class"])] += 1
        print(f"{name:<18}{co['called']:>12}{co['not called']:>6}{co['unknown']:>5}{cn['called']:>13}{cn['not called']:>6}{cn['unknown']:>5}")
    print(f"{'total (done only)':<18}{to['called']:>12}{to['not called']:>6}{to['unknown']:>5}{tn['called']:>13}{tn['not called']:>6}{tn['unknown']:>5}")
    print("\nold class -> new class (findings)")
    for (o, n), c in sorted(trans.items()):
        print(f"   {o:<13} -> {n:<11}{c:>5}")
    print("not done yet:", missing or "none")
    (R / "reach_product.json").write_text(json.dumps(new))
    print("wrote", R / "reach_product.json", "for", len(new), "projects (reach.json untouched)", "| MISSING at product level: " + ", ".join(missing) if missing else "")

{"run": lambda: run(sys.argv[2]), "check": check, "merge": merge}[sys.argv[1]]()
