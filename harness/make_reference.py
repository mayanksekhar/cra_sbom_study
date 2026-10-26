#!/usr/bin/env python3
import json, subprocess, os
from pathlib import Path
from urllib.parse import unquote
root = Path(__file__).resolve().parent.parent
REF = {("go","cobra"):"runtime_multi", ("go","node_exporter"):"runtime_multi",
       ("maven","spring_petclinic"):"shipped", ("maven","commons_text"):"shipped",
       ("npm","express"):"shipped", ("npm","axios"):"shipped",
       ("pypi","flask"):"lock", ("pypi","requests"):"shipped",
       ("rust","ripgrep"):"shipped", ("rust","fd"):"shipped"}
for (eco, name), kind in REF.items():
    comps = []
    for line in (root/"groundtruth"/eco/f"{name}_{kind}.txt").read_text().split():
        ptype, _, rest = line[4:].partition("/")
        i = rest.rfind("@"); path, ver = rest[:i], rest[i+1:]
        grp, _, nm = path.rpartition("/")
        if ptype == "npm" and path.startswith("@"):
            purl = "pkg:npm/" + path.replace("@", "%40", 1) + "@" + ver
        else:
            purl = "pkg:" + ptype + "/" + path + "@" + ver
        c = {"type": "library", "name": nm if ptype in ("maven","golang","npm") else path, "version": ver, "purl": purl}
        if ptype == "maven": c["group"] = grp
        comps.append(c)
    out = root/"results"/"reference"/eco; out.mkdir(parents=True, exist_ok=True)
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": comps}
    (out/f"{name}_truth.cdx.json").write_text(json.dumps(doc))
print("reference SBOMs written")
