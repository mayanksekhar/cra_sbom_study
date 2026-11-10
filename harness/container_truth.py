#!/usr/bin/env python3
"""Truth for container images from the image's own package database, and a reference SBOM built from it.
Usage: container_truth.py NAME IMAGE_REF WORKDIR   (reads WORKDIR/tar/NAME.tar exported filesystem listing via podman export)"""
import json, re, subprocess, sys, tarfile, io
from pathlib import Path
name, ref, work = sys.argv[1], sys.argv[2], Path(sys.argv[3])
cid = subprocess.run(["podman", "create", ref], capture_output=True, text=True).stdout.strip()
raw = subprocess.run(["podman", "export", cid], capture_output=True).stdout
subprocess.run(["podman", "rm", cid], capture_output=True)
tf = tarfile.open(fileobj=io.BytesIO(raw))
def read(*paths):
    for p in paths:
        for cand in (p, "./" + p):
            try:
                m = tf.getmember(cand)
                if m.issym() or m.islnk():
                    continue
                return tf.extractfile(m).read().decode("utf-8", "replace")
            except KeyError:
                pass
    return ""
osr = dict(l.split("=", 1) for l in read("etc/os-release", "usr/lib/os-release").splitlines() if "=" in l)
osid, osver = osr.get("ID", "").strip('"'), osr.get("VERSION_ID", "").strip('"')
pkgs = []
dpkg = read("var/lib/dpkg/status")
apk = read("lib/apk/db/installed")
if dpkg:
    kind = "deb"
    for block in dpkg.split("\n\n"):
        f = dict(re.findall(r"^([A-Za-z-]+): (.*)$", block, re.M))
        if f.get("Status", "").strip() != "install ok installed" or "Package" not in f:
            continue
        src, srcver = f["Package"], f["Version"]
        if "Source" in f:
            m = re.match(r"^(\S+)(?: \((.+)\))?$", f["Source"].strip())
            src, srcver = m.group(1), (m.group(2) or f["Version"])
        pkgs.append({"name": f["Package"], "version": f["Version"], "arch": f.get("Architecture", ""), "source": src, "source_version": srcver})
elif apk:
    kind = "apk"
    for block in apk.split("\n\n"):
        f = dict(l.split(":", 1) for l in block.splitlines() if len(l) > 1 and l[1] == ":")
        if "P" in f:
            pkgs.append({"name": f["P"], "version": f["V"], "arch": f.get("A", ""), "source": f.get("o", f["P"]), "source_version": f["V"]})
else:
    print(f"{name}: no dpkg or apk database found (os {osid} {osver})"); sys.exit(2)
(work / "truth" / f"{name}.json").write_text(json.dumps({"image": ref, "os": osid, "os_version": osver, "kind": kind, "packages": pkgs}, indent=1))
comps = [{"type": "operating-system", "name": osid, "version": osver, "bom-ref": "os"}]
for p in pkgs:
    q = f"arch={p['arch']}&distro={osid}-{osver}"
    if p["source"] != p["name"]:
        q += f"&upstream={p['source']}"
        if kind == "deb" and p["source_version"] != p["version"]:
            q = q.replace(f"&upstream={p['source']}", f"&upstream={p['source']}%40{p['source_version']}")
    purl = f"pkg:{kind}/{osid}/{p['name']}@{p['version']}?{q}"
    comps.append({"type": "library", "name": p["name"], "version": p["version"], "purl": purl, "bom-ref": purl})
(work / "ref" / f"{name}_truth.cdx.json").write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": comps}))
print(f"{name}: os {osid} {osver}, {kind}, {len(pkgs)} installed packages")
