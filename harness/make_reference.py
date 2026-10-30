#!/usr/bin/env python3
import json, os
from pathlib import Path
root = Path(__file__).resolve().parent.parent
SUF = os.environ.get("SET_SUFFIX", "")
GTR, RES = root / ("groundtruth" + SUF), root / ("results" + SUF)
PREF = {"go": ["runtime_multi"], "maven": ["shipped"], "npm": ["shipped"], "pypi": ["lock", "shipped"], "rust": ["shipped"]}
n = 0
for eco, prefs in PREF.items():
    d = GTR / eco
    if not d.exists():
        continue
    for mm in sorted(d.glob("*_mainmodule.txt")):
        name = mm.name[: -len("_mainmodule.txt")]
        kind = next((k for k in prefs if (d / f"{name}_{k}.txt").exists()), None)
        if not kind:
            continue
        comps = []
        for line in (d / f"{name}_{kind}.txt").read_text().split():
            ptype, _, rest = line[4:].partition("/")
            i = rest.rfind("@"); path, ver = rest[:i], rest[i + 1:]
            grp, _, nm = path.rpartition("/")
            if ptype == "npm" and path.startswith("@"):
                purl = "pkg:npm/" + path.replace("@", "%40", 1) + "@" + ver
            else:
                purl = "pkg:" + ptype + "/" + path + "@" + ver
            c = {"type": "library", "name": nm if ptype == "maven" else path, "version": ver, "purl": purl}
            if ptype == "maven":
                c["group"] = grp
            comps.append(c)
        o = RES / "reference" / eco
        o.mkdir(parents=True, exist_ok=True)
        (o / f"{name}_truth.cdx.json").write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": comps}))
        n += 1
print("reference SBOMs written:", n, "in", RES)
