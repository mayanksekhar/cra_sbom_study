#!/usr/bin/env python3
import collections, csv, json, os, subprocess
from pathlib import Path
root = Path(__file__).resolve().parent.parent
R = root / "results_go" / "product"
R.mkdir(parents=True, exist_ok=True)
snap, osvc = os.environ["SNAP"], os.environ["OSV_CACHE"]
tags = {r["name"]: r["tag"] for r in csv.DictReader(open(root / "dataset/go_pinned10.csv"))}
godb = []
for p in (root / "vulndb/20261030/govuln/ID").glob("*.json"):
    d = json.loads(p.read_text())
    godb.append(({d["id"]} | set(d.get("aliases") or []), {a["package"]["name"].lower() for a in d.get("affected", [])}))

def run_json(cmd, env=None):
    r = subprocess.run(cmd, capture_output=True, text=True, env=env)
    try:
        return json.loads(r.stdout)
    except ValueError:
        return None

def grype(sb):
    d = run_json(["grype", "sbom:" + str(sb), "-o", "json", "-q"])
    if d is None:
        return None
    return [({m["vulnerability"]["id"]} | {x["id"] for x in m.get("relatedVulnerabilities", [])}, m["vulnerability"].get("severity", "")) for m in d["matches"]]

def trivy(sb):
    d = run_json(["trivy", "sbom", "--cache-dir", snap + "/trivy", "--skip-db-update", "--skip-java-db-update", "--scanners", "vuln", "--format", "json", "-q", str(sb)])
    if d is None:
        return None
    out = []
    for r in d.get("Results") or []:
        for v in r.get("Vulnerabilities") or []:
            out.append(({v["VulnerabilityID"]} | set(v.get("VendorIDs") or []), v.get("Severity", "")))
    return out

def osv(sb):
    d = run_json(["osv-scanner", "scan", "source", "--offline-vulnerabilities", "--sbom", str(sb), "--format", "json"], dict(os.environ, XDG_CACHE_HOME=osvc))
    if d is None:
        return None
    out = []
    for res in d.get("results") or []:
        for pk in res.get("packages") or []:
            for v in pk.get("vulnerabilities") or []:
                out.append(({v["id"]} | set(v.get("aliases") or []), ""))
    return out

def clusters(items):
    groups = []
    for ids, sc in items:
        new = {"ids": set(ids), "sc": {sc}}
        for g in [g for g in groups if g["ids"] & ids]:
            new["ids"] |= g["ids"]
            new["sc"] |= g["sc"]
            groups.remove(g)
        groups.append(new)
    return groups

H = ("project", "tag", "grype_raw", "grype_high_crit", "clusters", "all_three", "two_of_three", "grype_only", "trivy_only", "osv_only", "in_go_db_for_module")
rows = []
for p, tag in sorted(tags.items()):
    main = (root / "groundtruth_go/go" / f"{p}_mainmodule.txt").read_text().strip()
    purl = "pkg:golang/%s@%s" % (main, tag)
    sb = R / f"{p}.cdx.json"
    sb.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                              "components": [{"type": "library", "name": main, "version": tag, "purl": purl, "bom-ref": purl}]}))
    res = {"grype": grype(sb), "trivy": trivy(sb), "osv": osv(sb)}
    bad = [k for k, v in res.items() if v is None]
    if bad:
        print(f"{p:<20}scan failed: {bad}")
        continue
    groups = clusters([(ids, s) for s, lst in res.items() for ids, _ in lst])
    ingodb = sum(1 for g in groups if any(a & g["ids"] and main.lower() in pk for a, pk in godb))
    rows.append((p, tag, len(res["grype"]), sum(1 for _, sv in res["grype"] if sv in ("Critical", "High")), len(groups),
                 sum(1 for g in groups if len(g["sc"]) == 3), sum(1 for g in groups if len(g["sc"]) == 2),
                 sum(1 for g in groups if g["sc"] == {"grype"}), sum(1 for g in groups if g["sc"] == {"trivy"}),
                 sum(1 for g in groups if g["sc"] == {"osv"}), ingodb))
print(f"{'project':<20}{'tag':<10}{'grype raw':>10}{'hi/crit':>8}{'clusters':>9}{'all 3':>6}{'2 of 3':>7}{'g only':>7}{'t only':>7}{'o only':>7}{'in Go DB':>9}")
for r in rows:
    print(f"{r[0]:<20}{r[1]:<10}" + "".join(f"{x:>{w}}" for x, w in zip(r[2:], (10, 8, 9, 6, 7, 7, 7, 7, 9))))
tot = [sum(r[i] for r in rows) for i in range(2, 11)]
print(f"{'total':<30}" + "".join(f"{x:>{w}}" for x, w in zip(tot, (10, 8, 9, 6, 7, 7, 7, 7, 9))))
with open(root / "results_go" / "product_findings.csv", "w", newline="") as fh:
    w = csv.writer(fh); w.writerow(H); w.writerows(rows)
