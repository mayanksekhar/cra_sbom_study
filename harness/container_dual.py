#!/usr/bin/env python3
"""Add Trivy source package properties, derived from the truth file, to a reference SBOM.
usage: container_dual.py NAME WORKDIR
writes WORKDIR/ref/NAME_truth_dual.cdx.json"""
import json, re, sys
from pathlib import Path

name, work = sys.argv[1], Path(sys.argv[2])
truth = json.loads((work / "truth" / f"{name}.json").read_text())
ref = json.loads((work / "ref" / f"{name}_truth.cdx.json").read_text())
deb = truth["kind"] == "deb"
by = {p["name"]: p for p in truth["packages"]}

def split(v):
    epoch = None
    m = re.match(r"^(\d+):(.*)$", v)
    if m:
        epoch, v = m.group(1), m.group(2)
    if "-" in v:
        ver, rel = v.rsplit("-", 1)
    else:
        ver, rel = v, ""
    return epoch, ver, rel

for c in ref["components"]:
    p = by.get(c["name"])
    if not p or not (c.get("purl") or "").startswith(("pkg:deb/", "pkg:apk/")):
        continue
    props = [("PkgID", f"{p['name']}@{p['version']}"), ("PkgType", "debian" if deb else "alpine"), ("SrcName", p["source"])]
    if deb:
        e, v, r = split(p["source_version"])
        props += [("SrcVersion", v), ("SrcRelease", r)]
        if e:
            props.append(("SrcEpoch", e))
    else:
        props.append(("SrcVersion", p["source_version"]))
    c["properties"] = (c.get("properties") or []) + [{"name": f"aquasecurity:trivy:{k}", "value": v} for k, v in props]
(work / "ref" / f"{name}_truth_dual.cdx.json").write_text(json.dumps(ref))
