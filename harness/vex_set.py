#!/usr/bin/env python3
import collections, csv, datetime, json, os, subprocess
from pathlib import Path
from urllib.parse import unquote
root = Path(__file__).resolve().parent.parent
snap = os.environ["SNAP"]
R = root / "results_go"
import argparse
_ap = argparse.ArgumentParser()
_ap.add_argument("--reach", default="reach.json")
_ap.add_argument("--tag", default="")
A = _ap.parse_args()
out = R / ("vex" + A.tag)
out.mkdir(exist_ok=True)
reach = json.loads((R / A.reach).read_text())
tags = {r["name"]: r["tag"] for r in csv.DictReader(open(root / "dataset/go_pinned10.csv")) if r["name"] in reach}
norm = lambda p: unquote((p or "").split("?")[0]).lower()
def path_of(purl):
    u = norm(purl)
    return u[len("pkg:golang/"):] if u.startswith("pkg:golang/") else u

def build_sbom(name):
    ref = json.loads((R / f"reference/go/{name}_truth.cdx.json").read_text())
    main = (root / "groundtruth_go/go" / f"{name}_mainmodule.txt").read_text().strip()
    rp = "pkg:golang/" + main + "@" + tags[name]
    comps = [dict(c, **{"bom-ref": c["purl"]}) for c in ref["components"]]
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
           "metadata": {"component": {"type": "application", "name": main, "version": tags[name], "purl": rp, "bom-ref": "root"}},
           "components": comps,
           "dependencies": [{"ref": "root", "dependsOn": [c["purl"] for c in comps]}] + [{"ref": c["purl"], "dependsOn": []} for c in comps]}
    p = out / f"{name}.cdx.json"
    p.write_text(json.dumps(doc))
    return p, rp

def build_vex(name, rp, form):
    st, seen = [], set()
    byver = {norm(c["purl"]): c["purl"] for c in json.loads((R / f"reference/go/{name}_truth.cdx.json").read_text())["components"]}
    for e in reach[name]:
        if e["class"] != "not called":
            continue
        full = next((v for k, v in byver.items() if path_of(k) == e["purl"] or path_of(k).rsplit("@", 1)[0] == e["purl"].rsplit("@", 1)[0]), None)
        pk = full or ("pkg:golang/" + e["purl"])
        for i in e["ids"]:
            if (pk, i) in seen:
                continue
            seen.add((pk, i))
            prod = ({"@id": rp, "identifiers": {"purl": rp}, "subcomponents": [{"@id": pk, "identifiers": {"purl": pk}}]} if form == "A"
                    else {"@id": pk, "identifiers": {"purl": pk}})
            st.append({"vulnerability": {"name": i}, "products": [prod], "status": "not_affected", "justification": "vulnerable_code_not_in_execute_path"})
    p = out / f"{name}_vex_{form}.json"
    p.write_text(json.dumps({"@context": "https://openvex.dev/ns/v0.2.0", "@id": f"https://example.org/vex/{name}_{form}", "author": "cra_sbom_study",
                             "timestamp": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"), "version": 1, "statements": st}))
    return p

def classify(name, purl, ids):
    for e in reach[name]:
        if set(e["ids"]) & set(ids) and (e["purl"] == purl or e["purl"].rsplit("@", 1)[0] == purl.rsplit("@", 1)[0]):
            return e["class"]
    return "unknown"

def scan(scanner, sb, vex, name):
    if scanner == "grype":
        cmd = ["grype", "sbom:" + str(sb), "-o", "json", "-q"] + (["--vex", str(vex)] if vex else [])
        try:
            d = json.loads(subprocess.run(cmd, capture_output=True, text=True).stdout)
        except ValueError:
            return None
        return [classify(name, path_of(m["artifact"]["purl"]), {m["vulnerability"]["id"]} | {r["id"] for r in m.get("relatedVulnerabilities", [])}) for m in d["matches"]]
    cmd = ["trivy", "sbom", "--cache-dir", snap + "/trivy", "--skip-db-update", "--skip-java-db-update", "--scanners", "vuln", "--format", "json", "-q"] + (["--vex", str(vex)] if vex else []) + [str(sb)]
    try:
        d = json.loads(subprocess.run(cmd, capture_output=True, text=True).stdout)
    except ValueError:
        return None
    res = []
    for r in d.get("Results") or []:
        for v in r.get("Vulnerabilities") or []:
            res.append(classify(name, path_of((v.get("PkgIdentifier") or {}).get("PURL")), {v["VulnerabilityID"]} | set(v.get("VendorIDs") or [])))
    return res

tot = collections.defaultdict(collections.Counter)
rows = []
for name in tags:
    sb, rp = build_sbom(name)
    vexes = {"A": build_vex(name, rp, "A"), "B": build_vex(name, rp, "B")}
    for scanner in ("trivy", "grype"):
        base = scan(scanner, sb, None, name)
        if base is None:
            print(f"{name:<18}{scanner}: baseline scan failed"); continue
        cb = collections.Counter(base)
        for form, vp in vexes.items():
            a = scan(scanner, sb, vp, name)
            if a is None:
                print(f"{name:<18}{scanner} {form}: scan failed"); continue
            ca = collections.Counter(a)
            k = (scanner, form)
            tot[k].update({"called_total": cb["called"], "called_removed": cb["called"] - ca["called"], "nc_total": cb["not called"], "nc_removed": cb["not called"] - ca["not called"],
                           "unk_total": cb["unknown"], "left": len(a)})
            rows.append((name, scanner, form, cb["called"] - ca["called"], cb["not called"] - ca["not called"], cb["not called"]))
print(f"\n{'scanner':<8}{'form':<5}{'called removed (false suppression)':>36}{'not called removed':>24}{'left':>7}")
for (scanner, form), c in sorted(tot.items()):
    print(f"{scanner:<8}{form:<5}{c['called_removed']:>20} of {c['called_total']:<8}{c['nc_removed']:>14} of {c['nc_total']:<5}{c['left']:>7}")
print("\nper project, trivy form A: called removed, not called removed of total")
for n, s, f, cr, nr, nt in rows:
    if s == "trivy" and f == "A":
        print(f"   {n:<18}{cr:>4}{nr:>6} of {nt}")
with open(R / ("vex_set" + A.tag + ".csv"), "w", newline="") as fh:
    w = csv.writer(fh); w.writerow(["project", "scanner", "form", "called_removed", "notcalled_removed", "notcalled_total"]); w.writerows(rows)
