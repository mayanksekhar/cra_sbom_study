#!/usr/bin/env python3
import csv, json
from collections import Counter
from pathlib import Path
from urllib.parse import unquote
root = Path(__file__).resolve().parent.parent
import os
SUF = os.environ.get("SET_SUFFIX", "")
RES = root / ("results" + SUF)

def parse(purl):
    p = unquote((purl or "").split("?")[0].split("#")[0]).lower()
    if not p.startswith("pkg:"):
        return None
    t, _, body = p[4:].partition("/")
    i = body.rfind("@")
    path, ver = (body[:i], body[i + 1:]) if i > 0 else (body, "")
    return t, path, ver

def sbom_keys(path):
    doc = json.loads(path.read_text()); out = set()
    def walk(cs):
        for c in cs or []:
            k = parse(c.get("purl"))
            if k:
                out.add(k)
            walk(c.get("components"))
    walk(doc.get("components"))
    return out

def load_grype(path):
    out = set()
    for m in json.loads(path.read_text()).get("matches", []):
        a = m["artifact"]
        out.add((parse(a.get("purl") or f'pkg:unknown/{a["name"]}@{a["version"]}'), m["vulnerability"]["id"]))
    return out

def load_trivy(path):
    out = set()
    for r in json.loads(path.read_text()).get("Results") or []:
        for v in r.get("Vulnerabilities") or []:
            k = parse((v.get("PkgIdentifier") or {}).get("PURL") or f'pkg:unknown/{v["PkgName"]}@{v["InstalledVersion"]}')
            out.add((k, v["VulnerabilityID"]))
    return out

def cluster_ids(items):
    """merge findings on the same component that share an advisory id; keep the first id as the cluster name"""
    groups = []
    for k, vid, ids in items:
        hit = [g for g in groups if g[0] == k and g[2] & ids]
        if hit:
            g = hit[0]
            g[2] |= ids
            for other in hit[1:]:
                g[2] |= other[2]
                groups.remove(other)
        else:
            groups.append([k, vid, set(ids)])
    return {(g[0], g[1]) for g in groups}

def load_grype_c(path):
    items = []
    for m in json.loads(path.read_text()).get("matches", []):
        a = m["artifact"]
        ids = {m["vulnerability"]["id"]} | {r["id"] for r in m.get("relatedVulnerabilities", [])}
        items.append((parse(a.get("purl") or f'pkg:unknown/{a["name"]}@{a["version"]}'), m["vulnerability"]["id"], ids))
    return cluster_ids(items)

def load_trivy_c(path):
    items = []
    for r in json.loads(path.read_text()).get("Results") or []:
        for v in r.get("Vulnerabilities") or []:
            k = parse((v.get("PkgIdentifier") or {}).get("PURL") or f'pkg:unknown/{v["PkgName"]}@{v["InstalledVersion"]}')
            items.append((k, v["VulnerabilityID"], {v["VulnerabilityID"]} | set(v.get("VendorIDs") or [])))
    return cluster_ids(items)

LOAD = {"grype": load_grype_c, "trivy": load_trivy_c}
CATS = ("fp_root", "fp_not_shipped", "fp_other_version", "fn_component_absent", "fn_no_version", "fn_wrong_version", "fn_scanner_miss")
rows = []
for d in sorted((RES / "vulns").iterdir()):
    eco = d.name
    for g in sorted(d.glob("*_grype.json")):
        stem = g.name[: -len("_grype.json")]
        project, tool = stem.rsplit("_", 1)
        base = project.replace("_nolock", "")
        sb = sbom_keys(RES / "raw" / eco / f"{stem}.cdx.json")
        sbp = {}
        for t, p, v in sb:
            sbp.setdefault((t, p), set()).add(v)
        refp = {(t, p) for t, p, v in sbom_keys(RES / "reference" / eco / f"{base}_truth.cdx.json")}
        mmf = root / ("groundtruth" + SUF) / eco / f"{base}_mainmodule.txt"
        mm = {l.strip().lower() for l in mmf.read_text().split()} if mmf.exists() else set()
        for scanner, load in LOAD.items():
            scan = d / f"{stem}_{scanner}.json"
            ref = RES / "vulns_ref" / eco / f"{base}_truth_{scanner}.json"
            if not ref.exists() or not scan.exists() or scan.stat().st_size == 0:
                continue
            rf, gf = load(ref), load(scan)
            cat = Counter()
            for k, vid in gf - rf:
                if k[1] in mm:
                    cat["fp_root"] += 1
                else:
                    cat["fp_other_version" if (k[0], k[1]) in refp else "fp_not_shipped"] += 1
            for k, vid in rf - gf:
                if k in sb:
                    cat["fn_scanner_miss"] += 1
                elif (k[0], k[1]) in sbp:
                    cat["fn_no_version" if sbp[(k[0], k[1])] == {""} else "fn_wrong_version"] += 1
                else:
                    cat["fn_component_absent"] += 1
            r = {"project": project, "tool": tool, "scanner": scanner, "ref_n": len(rf), "got_n": len(gf),
                 "tp": len(gf & rf), "fp": len(gf - rf), "fn": len(rf - gf)}
            r.update({c: cat[c] for c in CATS})
            rows.append(r)

with open(RES / "findings_vs_reference.csv", "w", newline="") as fh:
    w = csv.DictWriter(fh, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
print(f"{'sbom':<26}{'scan':<7}{'ref':>4}{'got':>5}{'tp':>4}{'fp':>4}{'fn':>4} | fp:notship/othver  fn:absent/nover/wrongver/scanner")
for r in rows:
    if r["ref_n"] or r["got_n"]:
        print(f"{r['project'] + '_' + r['tool']:<26}{r['scanner']:<7}{r['ref_n']:>4}{r['got_n']:>5}{r['tp']:>4}{r['fp']:>4}{r['fn']:>4} | "
              f"{r['fp_not_shipped']:>10}/{r['fp_other_version']:<6} {r['fn_component_absent']:>9}/{r['fn_no_version']}/{r['fn_wrong_version']}/{r['fn_scanner_miss']}")
