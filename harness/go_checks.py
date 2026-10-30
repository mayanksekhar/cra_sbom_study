#!/usr/bin/env python3
import csv, json, subprocess
from pathlib import Path
from urllib.parse import unquote
root = Path(__file__).resolve().parent.parent
R = root / "results_go"
tags = {r["name"]: r["tag"] for r in csv.DictReader(open(root / "dataset/go_pinned10.csv"))}

def path_of(purl):
    u = unquote((purl or "").split("?")[0]).lower()
    if u.startswith("pkg:golang/"):
        u = u[len("pkg:golang/"):]
    return u.rsplit("@", 1)[0] if "@" in u else u

def grype_matches(path):
    r = subprocess.run(["grype", "sbom:" + str(path), "-o", "json", "-q"], capture_output=True, text=True)
    try:
        return json.loads(r.stdout)["matches"]
    except ValueError:
        return None

print("== 1. findings on the product's own module, cdxgen SBOMs, Grype: root purl without version vs with the tag")
print(f"{'project':<20}{'tag':<10}{'root purl':<46}{'no version':>11}{'with tag':>9}")
tmp = Path("/tmp/cra_root")
tmp.mkdir(exist_ok=True)
tot0 = tot1 = 0
for p, tag in sorted(tags.items()):
    mm = (root / "groundtruth_go/go" / f"{p}_mainmodule.txt").read_text().strip().lower()
    sb = json.loads((R / "raw/go" / f"{p}_cdxgen.cdx.json").read_text())
    mc = sb["metadata"]["component"]
    orig = mc.get("purl")
    if not orig:
        print(f"{p:<20}no root purl")
        continue
    n0 = sum(1 for m in json.loads((R / "vulns/go" / f"{p}_cdxgen_grype.json").read_text())["matches"] if path_of(m["artifact"]["purl"]) == mm)
    mc["purl"] = orig.split("@")[0] + "@" + tag
    mc["version"] = tag
    f = tmp / f"{p}.cdx.json"
    f.write_text(json.dumps(sb))
    ms = grype_matches(f)
    n1 = "ERR" if ms is None else sum(1 for m in ms if path_of(m["artifact"]["purl"]) == mm)
    tot0 += n0
    tot1 += n1 if n1 != "ERR" else 0
    print(f"{p:<20}{tag:<10}{orig[:44]:<46}{n0:>11}{str(n1):>9}")
print(f"{'total':<76}{tot0:>11}{tot1:>9}")

def g_items(path):
    out = []
    for m in json.loads(Path(path).read_text())["matches"]:
        v = m["vulnerability"]
        out.append((path_of(m["artifact"]["purl"]), {v["id"]} | {r["id"] for r in m.get("relatedVulnerabilities", [])}, v["id"]))
    return out

def t_items(path):
    out = []
    for res in json.loads(Path(path).read_text()).get("Results") or []:
        for v in res.get("Vulnerabilities") or []:
            pu = (v.get("PkgIdentifier") or {}).get("PURL") or ""
            out.append((path_of(pu), {v["VulnerabilityID"]} | set(v.get("VendorIDs") or []), v["VulnerabilityID"]))
    return out

def only(a, b):
    by = {}
    for k, ids, i in b:
        by.setdefault(k, []).append(ids)
    return [(k, i) for k, ids, i in a if not any(ids & x for x in by.get(k, []))]

print("\n== 2. findings on the same reference SBOM that only one scanner reports")
for p in ("caddy", "cli", "helm", "hugo"):
    g = g_items(R / "vulns_ref/go" / f"{p}_truth_grype.json")
    t = t_items(R / "vulns_ref/go" / f"{p}_truth_trivy.json")
    go_, to_ = only(g, t), only(t, g)
    print(f"{p}: grype {len(g)}, trivy {len(t)}, grype only {len(go_)}, trivy only {len(to_)}")
    for k, i in go_[:5]:
        print("   grype only:", k, i)
    for k, i in to_[:3]:
        print("   trivy only:", k, i)
