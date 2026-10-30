#!/usr/bin/env python3
import collections, copy, datetime, json, os, subprocess
from pathlib import Path
from urllib.parse import unquote
root = Path(__file__).resolve().parent.parent
snap = os.environ["SNAP"]
R = root / "results_old"
vexA = json.loads((R / "vex/scale_vex_A.json").read_text())
norm = lambda p: unquote(p.split("?")[0]).lower()
notcalled = collections.defaultdict(set)
for st in vexA["statements"]:
    notcalled[norm(st["products"][0]["subcomponents"][0]["identifiers"]["purl"])].add(st["vulnerability"]["name"])
tag = subprocess.run(["git", "-C", str(root / "dataset/src_old/node_exporter"), "describe", "--tags", "--always"],
                     capture_output=True, text=True).stdout.strip()
ROOT = "pkg:golang/github.com/prometheus/node_exporter@" + tag

def trivy_scan(sb, v):
    cmd = ["trivy", "sbom", "--cache-dir", snap + "/trivy", "--skip-db-update", "--skip-java-db-update", "--scanners", "vuln", "--format", "json", "-q"] + (["--vex", str(v)] if v else []) + [str(sb)]
    try:
        d = json.loads(subprocess.run(cmd, capture_output=True, text=True).stdout)
    except ValueError:
        return None
    out = []
    for res in d.get("Results") or []:
        for x in res.get("Vulnerabilities") or []:
            pu = norm((x.get("PkgIdentifier") or {}).get("PURL") or "")
            ids = {x["VulnerabilityID"]} | set(x.get("VendorIDs") or [])
            out.append("not called" if ids & notcalled.get(pu, set()) else "called")
    return out

def mk_vex(name, mc):
    pid = mc.get("purl") or mc.get("bom-ref")
    prod = {"@id": pid}
    if mc.get("purl"):
        prod["identifiers"] = {"purl": mc["purl"]}
    sts = [{"vulnerability": st["vulnerability"], "products": [dict(prod, subcomponents=st["products"][0]["subcomponents"])],
            "status": st["status"], "justification": st["justification"]} for st in vexA["statements"]]
    p = R / "vex" / (name + "_vex.json")
    p.write_text(json.dumps({"@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://example.org/vex/" + name, "author": "cra_sbom_study",
                             "timestamp": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"), "version": 1, "statements": [dict(s) for s in sts]}))
    return p

base = json.loads((R / "raw/go/node_exporter_syft.cdx.json").read_text())

def v_purl(d):
    d["metadata"]["component"]["purl"] = ROOT

def v_type(d):
    d["metadata"]["component"].update({"type": "application", "name": "github.com/prometheus/node_exporter", "version": tag})

def v_ref(d):
    mc = d["metadata"]["component"]
    old = mc["bom-ref"]; mc["bom-ref"] = ROOT
    for e in d.get("dependencies") or []:
        if e["ref"] == old:
            e["ref"] = ROOT

def v_flat(d):
    mc = d["metadata"]["component"]
    refs = [c["bom-ref"] for c in d.get("components") or [] if c.get("purl", "").startswith("pkg:golang/") and c.get("bom-ref")]
    d["dependencies"] = [{"ref": mc["bom-ref"], "dependsOn": refs}] + [{"ref": r, "dependsOn": []} for r in refs]

def v_flat_keepdeps(d):
    mc = d["metadata"]["component"]
    refs = [c["bom-ref"] for c in d.get("components") or [] if c.get("purl", "").startswith("pkg:golang/") and c.get("bom-ref")]
    d["dependencies"] = (d.get("dependencies") or []) + [{"ref": mc["bom-ref"], "dependsOn": refs}]

def v_nonpurl(d):
    d["components"] = [c for c in d.get("components") or [] if c.get("purl", "").startswith("pkg:golang/")]

variants = [
    ("original", []), ("purl only", [v_purl]), ("type+name+version only", [v_type]), ("ref=purl only", [v_ref]),
    ("flat only", [v_flat]), ("keep deps + root edges", [v_flat_keepdeps]),
    ("purl+flat", [v_purl, v_flat]), ("purl+ref=purl+flat", [v_purl, v_ref, v_flat]),
    ("purl+type+flat", [v_purl, v_type, v_flat]), ("purl+type+ref+flat", [v_purl, v_type, v_ref, v_flat]),
    ("purl+type+flat, golang only", [v_purl, v_type, v_nonpurl, v_flat]),
]
print(f"{'variant':<32}{'left':>5}{'called kept':>13}{'removed':>10}")
for i, (label, fns) in enumerate(variants):
    d = copy.deepcopy(base)
    for f in fns:
        f(d)
    name = "bisect_%02d" % i
    sb = R / "vex" / (name + ".cdx.json")
    sb.write_text(json.dumps(d))
    vp = mk_vex(name, d["metadata"]["component"])
    b, a = trivy_scan(sb, None), trivy_scan(sb, vp)
    if b is None or a is None:
        print(f"{label:<32}scan failed")
        continue
    cb, ca = collections.Counter(b), collections.Counter(a)
    print(f"{label:<32}{len(a):>5}{ca['called']:>8} of {cb['called']:<3}{cb['not called'] - ca['not called']:>5} of {cb['not called']}")
