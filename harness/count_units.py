#!/usr/bin/env python3
import json
from pathlib import Path
from urllib.parse import unquote
root = Path(__file__).resolve().parent.parent
R = root / "results_go"
reach = json.loads((R / "reach.json").read_text())

def path_of(purl):
    u = unquote((purl or "").split("?")[0]).lower()
    return u[len("pkg:golang/"):] if u.startswith("pkg:golang/") else u

def grype_items(p):
    return [(path_of(m["artifact"]["purl"]), {m["vulnerability"]["id"]} | {r["id"] for r in m.get("relatedVulnerabilities", [])}, m["vulnerability"]["id"])
            for m in json.loads(Path(p).read_text())["matches"]]

def trivy_items(p):
    out = []
    for res in json.loads(Path(p).read_text()).get("Results") or []:
        for v in res.get("Vulnerabilities") or []:
            pu = path_of((v.get("PkgIdentifier") or {}).get("PURL")) or (v["PkgName"] + "@" + v["InstalledVersion"]).lower()
            out.append((pu, {v["VulnerabilityID"]} | set(v.get("VendorIDs") or []), v["VulnerabilityID"]))
    return out

def n_clusters(items):
    parent = list(range(len(items)))
    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i
    first = {}
    for i, (pu, ids, _) in enumerate(items):
        for x in ids:
            if (pu, x) in first:
                a, b = find(i), find(first[(pu, x)])
                if a != b:
                    parent[a] = b
            else:
                first[(pu, x)] = i
    return len({find(i) for i in range(len(items))})

print(f"{'project':<20}{'grype raw':>10}{'distinct pairs':>15}{'grype clusters':>15}{'trivy clusters':>15}{'union clusters':>15}{'reach.json':>11}")
tot = [0] * 6
for name in sorted(reach):
    g = grype_items(R / "vulns_ref/go" / f"{name}_truth_grype.json")
    t = trivy_items(R / "vulns_ref/go" / f"{name}_truth_trivy.json")
    row = [len(g), len({(a, c) for a, _, c in g}), n_clusters(g), n_clusters(t), n_clusters(g + t), len(reach[name])]
    tot = [x + y for x, y in zip(tot, row)]
    print(f"{name:<20}{row[0]:>10}{row[1]:>15}{row[2]:>15}{row[3]:>15}{row[4]:>15}{row[5]:>11}")
print(f"{'total':<20}{tot[0]:>10}{tot[1]:>15}{tot[2]:>15}{tot[3]:>15}{tot[4]:>15}{tot[5]:>11}")
