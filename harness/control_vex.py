#!/usr/bin/env python3
import json, os, subprocess
from pathlib import Path
root = Path(__file__).resolve().parent.parent
out = root / "results" / "vex"
snap = os.environ["SNAP"]
ctl = root / "dataset" / "controls" / "other_app"
mods = subprocess.run(["go", "list", "-deps", "-f", "{{if and .Module (not .Module.Main)}}{{.Module.Path}}@{{.Module.Version}}{{end}}", "./..."],
                      cwd=ctl, capture_output=True, text=True).stdout.split()
comps = []
for m in sorted(set(mods)):
    path, ver = m.rsplit("@", 1)
    purl = "pkg:golang/" + path + "@" + ver
    comps.append({"type": "library", "name": path, "version": ver, "purl": purl, "bom-ref": purl})
rp = "pkg:golang/example.com/other_app@1.0.0"
doc = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
       "metadata": {"component": {"type": "application", "name": "example.com/other_app", "version": "1.0.0", "purl": rp, "bom-ref": "root"}},
       "components": comps,
       "dependencies": [{"ref": "root", "dependsOn": [c["purl"] for c in comps]}] + [{"ref": c["purl"], "dependsOn": []} for c in comps]}
sb = out / "control_app_graph.cdx.json"
sb.write_text(json.dumps(doc))
print("components:", [c["purl"] for c in comps])

def grype(vex):
    cmd = ["grype", "sbom:" + str(sb), "-o", "json", "-q"] + (["--vex", str(vex)] if vex else [])
    d = json.loads(subprocess.run(cmd, capture_output=True, text=True).stdout)
    return len(d["matches"]), len(d.get("ignoredMatches") or [])

def trivy(vex):
    cmd = ["trivy", "sbom", "--cache-dir", snap + "/trivy", "--skip-db-update", "--skip-java-db-update", "--scanners", "vuln", "--format", "json", "-q"] + (["--vex", str(vex)] if vex else []) + [str(sb)]
    d = json.loads(subprocess.run(cmd, capture_output=True, text=True).stdout)
    return sum(len(r.get("Vulnerabilities") or []) for r in d.get("Results") or [])

print(f"{'vex':<6}{'grype_left':>11}{'grype_ign':>10}{'trivy_left':>11}")
for name, v in (("none", None), ("A", out / "vex_A.json"), ("B", out / "vex_B.json")):
    gl, gi = grype(v)
    print(f"{name:<6}{gl:>11}{gi:>10}{trivy(v):>11}")
