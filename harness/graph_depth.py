#!/usr/bin/env python3
import collections, json
from pathlib import Path
from urllib.parse import unquote
root = Path(__file__).resolve().parent.parent
R = root / "results_old"
vexA = json.loads((R / "vex/scale_vex_A.json").read_text())
norm = lambda p: unquote(p.split("?")[0]).lower()
vuln = {norm(st["products"][0]["subcomponents"][0]["identifiers"]["purl"]) for st in vexA["statements"]}
print("distinct vulnerable modules in the VEX:", len(vuln))
print(f"{'sbom':<8}{'comps':>6}{'root kids':>10}{'present':>8}{'direct':>7}{'depth2':>7}{'reach':>6}{'unreach':>8}")
for tool in ("syft", "trivy", "cdxgen"):
    d = json.loads((R / "raw/go" / f"node_exporter_{tool}.cdx.json").read_text())
    rref = d["metadata"]["component"].get("bom-ref")
    adj = {x["ref"]: x.get("dependsOn") or [] for x in d.get("dependencies") or []}
    ref_of = {}
    for c in d.get("components") or []:
        if c.get("purl"):
            ref_of.setdefault(norm(c["purl"]), set()).add(c.get("bom-ref"))
    depth, q = {rref: 0}, collections.deque([rref])
    while q:
        n = q.popleft()
        for m in adj.get(n, []):
            if m not in depth:
                depth[m] = depth[n] + 1
                q.append(m)
    present = direct = d2 = reach = 0
    for v in vuln:
        refs = ref_of.get(v, set())
        if not refs:
            continue
        present += 1
        dm = min((depth[r] for r in refs if r in depth), default=None)
        if dm is not None:
            reach += 1
            direct += dm == 1
            d2 += dm == 2
    print(f"{tool:<8}{len(d.get('components') or []):>6}{len(adj.get(rref, [])):>10}{present:>8}{direct:>7}{d2:>7}{reach:>6}{present - reach:>8}")
