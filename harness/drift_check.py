#!/usr/bin/env python3
"""Drift of Grype findings on the reference SBOMs between the frozen database (20261030) and a newer one downloaded to a scratch folder."""
import csv, json, os, shutil, subprocess, sys
from pathlib import Path
root = Path(__file__).resolve().parent.parent
SCR = Path("/tmp/drift_grype_new")
if shutil.disk_usage("/tmp").free < 4 * 2**30:
    sys.exit("less than 4 GB free in /tmp, stopping")
SCR.mkdir(exist_ok=True)
env = dict(os.environ, GRYPE_DB_CACHE_DIR=str(SCR), GRYPE_DB_AUTO_UPDATE="true")
r = subprocess.run(["grype", "db", "update"], env=env, capture_output=True, text=True)
print("db update exit", r.returncode, (r.stdout + r.stderr).strip().splitlines()[-1:] )
if r.returncode != 0:
    sys.exit("database download failed, stopping")
env["GRYPE_DB_AUTO_UPDATE"] = "false"
st = subprocess.run(["grype", "db", "status"], env=env, capture_output=True, text=True)
print("\n".join(l[:150] for l in (st.stdout + st.stderr).strip().splitlines()[:6]))
SETS = {"results": "pilot", "results_old": "older pins", "results_go": "go", "results_mvn": "maven", "results_py": "pypi", "results_rust": "rust", "results_npm": "npm"}

def clusters(data):
    items = []
    for m in data.get("matches", []):
        a = m["artifact"]
        pk = (a.get("purl") or f"{a.get('name')}@{a.get('version')}").split("?")[0].lower()
        items.append((pk, {m["vulnerability"]["id"]} | {x["id"] for x in m.get("relatedVulnerabilities", [])}))
    merged = []
    for pk, ids in items:
        for e in merged:
            if e[0] == pk and e[1] & ids:
                e[1] |= ids
                break
        else:
            merged.append([pk, set(ids)])
    return merged

def compare(old, new):
    both = sum(1 for o in old if any(n[0] == o[0] and n[1] & o[1] for n in new))
    added = sum(1 for n in new if not any(o[0] == n[0] and o[1] & n[1] for o in old))
    return both, len(old) - both, added

rows, tot, errors = [], {}, []
for d, label in SETS.items():
    agg = dict(sboms=0, old=0, new=0, both=0, removed=0, added=0, old26=0, both26=0, removed26=0, added26=0)
    for f in sorted((root / d / "reference").glob("*/*_truth.cdx.json")):
        proj = f.name[: -len("_truth.cdx.json")]
        if proj.endswith("_nolock"):
            continue
        eco = f.parent.name
        oldf = root / d / "vulns_ref" / eco / f"{proj}_truth_grype.json"
        if not oldf.exists():
            errors.append(f"{label} {proj}: no stored result")
            continue
        comps = json.loads(f.read_text()).get("components") or []
        if comps:
            p = subprocess.run(["grype", "sbom:" + str(f), "-o", "json", "-q"], env=env, capture_output=True, text=True)
            try:
                new = clusters(json.loads(p.stdout))
            except Exception:
                errors.append(f"{label} {proj}: grype output not JSON: {p.stderr.strip()[-80:]}")
                continue
        else:
            new = []
        old = clusters(json.loads(oldf.read_text()))
        b, rm, ad = compare(old, new)
        agg["sboms"] += 1; agg["old"] += len(old); agg["new"] += len(new); agg["both"] += b; agg["removed"] += rm; agg["added"] += ad
        if label == "pilot":
            f26 = root / d / "vulns_ref_20261026" / eco / f"{proj}_truth_grype.json"
            if f26.exists():
                o26 = clusters(json.loads(f26.read_text()))
                b2, rm2, ad2 = compare(o26, old)
                agg["old26"] += len(o26); agg["both26"] += b2; agg["removed26"] += rm2; agg["added26"] += ad2
    rows.append((label, agg))
print(f"\n{'set':<12}{'sboms':>6}{'20261030':>10}{'20261110':>10}{'in both':>9}{'only old':>9}{'only new':>9}")
for label, a in rows:
    print(f"{label:<12}{a['sboms']:>6}{a['old']:>10}{a['new']:>10}{a['both']:>9}{a['removed']:>9}{a['added']:>9}")
T = {k: sum(a[k] for _, a in rows) for k in rows[0][1]}
print(f"{'total':<12}{T['sboms']:>6}{T['old']:>10}{T['new']:>10}{T['both']:>9}{T['removed']:>9}{T['added']:>9}")
pa = dict(rows)["pilot"]
print(f"\npilot, 20261026 against 20261030: {pa['old26']} findings -> {pa['old']}, in both {pa['both26']}, only 20261026 {pa['removed26']}, only 20261030 {pa['added26']}")
if errors:
    print("\nnot compared:", errors)
out = root / "results_drift"
out.mkdir(exist_ok=True)
with open(out / "drift_20261110.csv", "w", newline="") as fh:
    w = csv.writer(fh)
    w.writerow(["set", "sboms", "findings_20261030", "findings_20261110", "in_both", "only_20261030", "only_20261110"])
    for label, a in rows:
        w.writerow([label, a["sboms"], a["old"], a["new"], a["both"], a["removed"], a["added"]])
print("wrote", out / "drift_20261110.csv")
