#!/usr/bin/env python3
import collections, csv, datetime, json, os, subprocess
from pathlib import Path
root = Path(__file__).resolve().parent.parent
snap = os.environ["SNAP"]
src = root / "dataset/src_old/node_exporter"
db = root / "vulndb/20261030/govuln"
R = root / "results_old"
out = R / "vex"
out.mkdir(parents=True, exist_ok=True)

raw = subprocess.run(["govulncheck", "-format", "json", "-db", "file://" + str(db), "./..."],
                     cwd=src, capture_output=True, text=True).stdout
dec, i, msgs = json.JSONDecoder(), 0, []
while i < len(raw):
    while i < len(raw) and raw[i].isspace():
        i += 1
    if i >= len(raw):
        break
    obj, i = dec.raw_decode(raw, i)
    msgs.append(obj)
level = {}
for m in msgs:
    f = m.get("finding")
    if f:
        t = f["trace"][0]
        lv = 3 if t.get("function") else 2 if t.get("package") else 1
        level[f["osv"]] = max(level.get(f["osv"], 0), lv)
alias = {}
for p in (db / "ID").glob("*.json"):
    d = json.loads(p.read_text())
    alias[d["id"]] = {d["id"]} | set(d.get("aliases") or [])

def cls_of(ids):
    go = [g for g, al in alias.items() if al & ids]
    lv = max((level.get(g, 0) for g in go), default=0)
    return "called" if lv == 3 else "not called" if lv else "unknown"

def g_ids(m):
    return {m["vulnerability"]["id"]} | {r["id"] for r in m.get("relatedVulnerabilities", [])}

def t_list(d):
    out_l = []
    for res in d.get("Results") or []:
        for v in res.get("Vulnerabilities") or []:
            pu = ((v.get("PkgIdentifier") or {}).get("PURL") or "").split("?")[0]
            out_l.append((pu, {v["VulnerabilityID"]} | set(v.get("VendorIDs") or [])))
    return out_l

gref = json.loads((R / "vulns_ref/go/node_exporter_truth_grype.json").read_text())
tref = json.loads((R / "vulns_ref/go/node_exporter_truth_trivy.json").read_text())
entries = []
tl = t_list(tref)
for m in gref["matches"]:
    purl, u = m["artifact"]["purl"].split("?")[0], g_ids(m)
    for pu, T in tl:
        if pu == purl and T & u:
            u = u | T
    entries.append((purl, u))
for pu, T in tl:
    if not any(pu == e[0] and T & e[1] for e in entries):
        entries.append((pu, T))
classified = [(p, u, cls_of(u)) for p, u in entries]
print("findings (union of Grype and Trivy):", dict(collections.Counter(c for _, _, c in classified)))

tag = subprocess.run(["git", "-C", str(src), "describe", "--tags", "--always"], capture_output=True, text=True).stdout.strip()
ROOT = "pkg:golang/github.com/prometheus/node_exporter@" + tag

def vex(form):
    st, seen = [], set()
    for purl, ids, c in classified:
        if c != "not called":
            continue
        for i in sorted(ids):
            if (purl, i) in seen:
                continue
            seen.add((purl, i))
            if form == "A":
                prod = {"@id": ROOT, "identifiers": {"purl": ROOT}, "subcomponents": [{"@id": purl, "identifiers": {"purl": purl}}]}
            else:
                prod = {"@id": purl, "identifiers": {"purl": purl}}
            st.append({"vulnerability": {"name": i}, "products": [prod], "status": "not_affected",
                       "justification": "vulnerable_code_not_in_execute_path"})
    doc = {"@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://example.org/vex/scale_" + form, "author": "cra_sbom_study",
           "timestamp": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"), "version": 1, "statements": st}
    p = out / ("scale_vex_" + form + ".json")
    p.write_text(json.dumps(doc, indent=1))
    return p

ref = json.loads((R / "reference/go/node_exporter_truth.cdx.json").read_text())
def sbom(graph):
    comps = [dict(c) for c in ref["components"]]
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
           "metadata": {"component": {"type": "application", "name": "node_exporter", "version": tag, "purl": ROOT, "bom-ref": "root"}},
           "components": comps}
    if graph:
        for c in comps:
            c["bom-ref"] = c["purl"]
        doc["dependencies"] = [{"ref": "root", "dependsOn": [c["purl"] for c in comps]}] + [{"ref": c["purl"], "dependsOn": []} for c in comps]
    p = out / ("scale_sbom_" + ("graph" if graph else "flat") + ".cdx.json")
    p.write_text(json.dumps(doc))
    return p

def scan_grype(sb, v):
    cmd = ["grype", "sbom:" + str(sb), "-o", "json", "-q"] + (["--vex", str(v)] if v else [])
    d = json.loads(subprocess.run(cmd, capture_output=True, text=True).stdout)
    return [cls_of(g_ids(m)) for m in d["matches"]]

def scan_trivy(sb, v):
    cmd = ["trivy", "sbom", "--cache-dir", snap + "/trivy", "--skip-db-update", "--skip-java-db-update", "--scanners", "vuln", "--format", "json", "-q"] + (["--vex", str(v)] if v else []) + [str(sb)]
    d = json.loads(subprocess.run(cmd, capture_output=True, text=True).stdout)
    return [cls_of(ids) for _, ids in t_list(d)]

sg, sf = sbom(True), sbom(False)
vA, vB = vex("A"), vex("B")
print("statements in A:", len(json.loads(vA.read_text())["statements"]))
runs = [("none", sg, None), ("A", sg, vA), ("B", sg, vB), ("A_flat", sf, vA)]
rows, base = [], {}
print(f"{'scanner':<8}{'vex':<8}{'left':>5}  {'called kept':>12}  {'false suppr.':>13}  {'not called removed':>19}")
for scanner, fn in (("grype", scan_grype), ("trivy", scan_trivy)):
    for name, sb, v in runs:
        c = collections.Counter(fn(sb, v))
        if name == "none":
            base[scanner] = c
        bc, bn = base[scanner]["called"], base[scanner]["not called"]
        row = {"scanner": scanner, "vex": name, "left": sum(c.values()), "called_kept": c["called"], "called_total": bc,
               "false_suppression": bc - c["called"], "notcalled_removed": bn - c["not called"], "notcalled_total": bn, "unknown": c["unknown"]}
        rows.append(row)
        print(f"{scanner:<8}{name:<8}{row['left']:>5}  {c['called']:>5} of {bc:<5}  {row['false_suppression']:>13}  {row['notcalled_removed']:>9} of {bn:<8}")
with open(out / "vex_scale.csv", "w", newline="") as fh:
    w = csv.DictWriter(fh, fieldnames=list(rows[0]))
    w.writeheader()
    w.writerows(rows)
