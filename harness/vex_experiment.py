#!/usr/bin/env python3
import csv, json, os, subprocess
from pathlib import Path
root = Path(__file__).resolve().parent.parent
out = root / "results" / "vex"
out.mkdir(parents=True, exist_ok=True)
snap = os.environ["SNAP"]

ref = json.loads((root / "results/reference/go/node_exporter_truth.cdx.json").read_text())
ver = subprocess.run(["git", "-C", str(root / "dataset/src/node_exporter"), "describe", "--tags", "--always"],
                     capture_output=True, text=True).stdout.strip()
NE = "pkg:golang/github.com/prometheus/node_exporter@" + ver
OTHER = "pkg:golang/example.com/other_app@1.0.0"

def write_sbom(name, purl, comps):
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
           "metadata": {"component": {"type": "application", "name": name, "version": purl.rsplit("@", 1)[1],
                                      "purl": purl, "bom-ref": "root"}},
           "components": comps}
    if os.environ.get("GRAPH"):
        for c in comps:
            c["bom-ref"] = c["purl"]
        doc["dependencies"] = [{"ref": "root", "dependsOn": [c["purl"] for c in comps]}] + [{"ref": c["purl"], "dependsOn": []} for c in comps]
    p = out / (name + ("_graph" if os.environ.get("GRAPH") else "") + ".cdx.json")
    p.write_text(json.dumps(doc))
    return p

keep = ("golang.org/x/net@", "golang.org/x/crypto@")
sboms = {"node_exporter": write_sbom("node_exporter", NE, ref["components"]),
         "other_app": write_sbom("other_app", OTHER, [c for c in ref["components"] if any(k in c["purl"] for k in keep)])}

def run_grype(sb, vex=None):
    cmd = ["grype", "sbom:" + str(sb), "-o", "json", "-q"]
    if vex:
        cmd += ["--vex", str(vex)]
    r = subprocess.run(cmd, capture_output=True, text=True)
    try:
        d = json.loads(r.stdout)
    except ValueError:
        return None, r.stderr[-300:]
    return d, ""

def run_trivy(sb, vex=None):
    cmd = ["trivy", "sbom", "--cache-dir", snap + "/trivy", "--skip-db-update", "--skip-java-db-update",
           "--scanners", "vuln", "--format", "json", "-q"]
    if vex:
        cmd += ["--vex", str(vex)]
    cmd.append(str(sb))
    r = subprocess.run(cmd, capture_output=True, text=True)
    try:
        d = json.loads(r.stdout)
    except ValueError:
        return None, r.stderr[-300:]
    return d, ""

pk = {}
g, err = run_grype(sboms["node_exporter"])
if g is None:
    raise SystemExit("grype baseline failed: " + err)
for m in g["matches"]:
    ids = pk.setdefault(m["artifact"]["purl"], set())
    ids.add(m["vulnerability"]["id"])
    for rel in m.get("relatedVulnerabilities", []):
        ids.add(rel["id"])
t, err = run_trivy(sboms["node_exporter"])
if t is None:
    raise SystemExit("trivy baseline failed: " + err)
for res in t.get("Results") or []:
    for v in res.get("Vulnerabilities") or []:
        p = ((v.get("PkgIdentifier") or {}).get("PURL") or "").split("?")[0]
        ids = pk.setdefault(p, set())
        ids.add(v["VulnerabilityID"])
        ids.update(v.get("VendorIDs") or [])
print("product purl:", NE)
print("packages with findings:", {k: sorted(v) for k, v in pk.items()})

def write_vex(kind):
    stmts = []
    for pkg, ids in sorted(pk.items()):
        for i in sorted(ids):
            if kind == "A":
                prod = {"@id": NE, "identifiers": {"purl": NE}, "subcomponents": [{"@id": pkg, "identifiers": {"purl": pkg}}]}
            else:
                prod = {"@id": pkg, "identifiers": {"purl": pkg}}
            stmts.append({"vulnerability": {"name": i}, "products": [prod], "status": "not_affected",
                          "justification": "vulnerable_code_not_in_execute_path"})
    doc = {"@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://example.org/vex/" + kind,
           "author": "cra_sbom_study", "timestamp": "2026-10-30T12:00:00Z", "version": 1, "statements": stmts}
    p = out / ("vex_" + kind + ".json")
    p.write_text(json.dumps(doc, indent=1))
    return p

vexes = {"none": None, "A": write_vex("A"), "B": write_vex("B")}
rows = []
for sname, sb in sboms.items():
    for vname, vp in vexes.items():
        gd, ge = run_grype(sb, vp)
        td, te = run_trivy(sb, vp)
        rows.append({"sbom": sname, "vex": vname,
                     "grype_left": len(gd["matches"]) if gd else "ERR",
                     "grype_ignored": len(gd.get("ignoredMatches") or []) if gd else "ERR",
                     "trivy_left": sum(len(r.get("Vulnerabilities") or []) for r in (td.get("Results") or [])) if td else "ERR",
                     "err": (ge + te).strip()[:120]})
with open(out / ("vex_matrix_graph.csv" if os.environ.get("GRAPH") else "vex_matrix.csv"), "w", newline="") as fh:
    w = csv.DictWriter(fh, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
print(f"{'sbom':<15}{'vex':<6}{'grype_left':>11}{'grype_ign':>10}{'trivy_left':>11}  err")
for r in rows:
    print(f"{r['sbom']:<15}{r['vex']:<6}{r['grype_left']:>11}{r['grype_ignored']:>10}{r['trivy_left']:>11}  {r['err']}")
