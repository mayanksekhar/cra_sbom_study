#!/usr/bin/env python3
import collections, json, os, subprocess
from pathlib import Path
from urllib.parse import unquote
root = Path(__file__).resolve().parent.parent
snap = os.environ["SNAP"]
R = root / "results_go"
V = R / "vex"
reach = json.loads((R / "reach.json").read_text())
names = sorted(reach)
norm = lambda p: unquote((p or "").split("?")[0]).lower()
def path_of(purl):
    u = norm(purl)
    return u[len("pkg:golang/"):] if u.startswith("pkg:golang/") else u
def classify(q, purl, ids):
    for e in reach[q]:
        if set(e["ids"]) & set(ids) and (e["purl"] == purl or e["purl"].rsplit("@", 1)[0] == purl.rsplit("@", 1)[0]):
            return e["class"]
    return "unknown"
def scan(scanner, q, vex=None):
    sb = V / f"{q}.cdx.json"
    if scanner == "grype":
        cmd = ["grype", "sbom:" + str(sb), "-o", "json", "-q"] + (["--vex", str(vex)] if vex else [])
        try:
            d = json.loads(subprocess.run(cmd, capture_output=True, text=True).stdout)
        except ValueError:
            return None
        raw = [(path_of(m["artifact"]["purl"]), {m["vulnerability"]["id"]} | {r["id"] for r in m.get("relatedVulnerabilities", [])}) for m in d["matches"]]
    else:
        cmd = ["trivy", "sbom", "--cache-dir", snap + "/trivy", "--skip-db-update", "--skip-java-db-update", "--scanners", "vuln", "--format", "json", "-q"] + (["--vex", str(vex)] if vex else []) + [str(sb)]
        try:
            d = json.loads(subprocess.run(cmd, capture_output=True, text=True).stdout)
        except ValueError:
            return None
        raw = []
        for r in d.get("Results") or []:
            for v in r.get("Vulnerabilities") or []:
                raw.append((path_of((v.get("PkgIdentifier") or {}).get("PURL")), {v["VulnerabilityID"]} | set(v.get("VendorIDs") or [])))
    return [(pu, ids, classify(q, pu, ids)) for pu, ids in raw]

nc = {n: [(e["purl"], set(e["ids"])) for e in reach[n] if e["class"] == "not called"] for n in names}
cl = {n: [(e["purl"], set(e["ids"])) for e in reach[n] if e["class"] == "called"] for n in names}
pairs, risk = {}, set()
for p in names:
    for q in names:
        if p == q:
            continue
        hit = [(pu, sorted(ids)[0]) for pu, ids in cl[q] if any(pu == pu2 and ids & ids2 for pu2, ids2 in nc[p])]
        if hit:
            pairs[(p, q)] = hit
            risk |= {(q,) + h for h in hit}
total_called = sum(len(v) for v in cl.values())
print(f"ordered project pairs: {len(names) * (len(names) - 1)}; pairs where P's module level file covers a called finding of Q: {len(pairs)}")
print(f"distinct called findings that some other project's file would suppress: {len(risk)} of {total_called}")
per_q = collections.Counter(r[0] for r in risk)
print("at risk per project:", dict(sorted(per_q.items())))
for (pu, i) in sorted({(r[1], r[2]) for r in risk})[:6]:
    print("   example:", pu, i)

base = {}
def baseline(s, q):
    if (s, q) not in base:
        base[(s, q)] = scan(s, q)
    return base[(s, q)]
print(f"\n{'P file':>19} -> {'applied to Q':<19}{'predicted':>10}{'trivy B':>9}{'grype B':>9}{'trivy A':>9}   (called findings removed)")
for (p, q), hit in sorted(pairs.items(), key=lambda x: -len(x[1]))[:12]:
    row = []
    for s, form in (("trivy", "B"), ("grype", "B"), ("trivy", "A")):
        b, a = baseline(s, q), scan(s, q, V / f"{p}_vex_{form}.json")
        row.append("ERR" if b is None or a is None else sum(1 for x in b if x[2] == "called") - sum(1 for x in a if x[2] == "called"))
    print(f"{p:>19} -> {q:<19}{len(hit):>10}{str(row[0]):>9}{str(row[1]):>9}{str(row[2]):>9}")

print("\n== findings classified unknown in the baseline scans of the corrected SBOMs")
for s in ("trivy", "grype"):
    tot = on_root = 0
    ex = []
    for q in names:
        main = (root / "groundtruth_go/go" / f"{q}_mainmodule.txt").read_text().strip().lower()
        b = baseline(s, q)
        if b is None:
            continue
        for pu, ids, c in b:
            if c == "unknown":
                tot += 1
                if pu.rsplit("@", 1)[0] == main:
                    on_root += 1
                elif len(ex) < 4:
                    ex.append((q, pu, sorted(ids)[0]))
    print(f"{s}: unknown {tot}, on the product's own module {on_root}, elsewhere {tot - on_root}")
    for e in ex:
        print("     elsewhere:", e)
