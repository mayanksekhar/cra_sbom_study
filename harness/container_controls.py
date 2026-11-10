#!/usr/bin/env python3
"""Container controls: what a scanner needs from an SBOM, shown by adding one field at a time.
usage: container_controls.py WORKDIR OUTDIR   (set TMPDIR to a folder on disk first)
Grype reading Trivy's SBOM: as generated; with the upstream qualifier of the reference purl added;
with upstream and the distro value of the reference. Trivy reading Syft's SBOM: as generated; with
Trivy's source properties copied on. Grype reading cdxgen's SBOM: as generated; with upstream added.
Trivy reading cdxgen's SBOM: as generated; with an operating system component derived from the truth;
with that component and a dependency graph linking it to every OS package.
The reference is the same scanner's scan of the dual reference. Writes OUTDIR/container_controls.csv."""
import csv, json, re, subprocess, sys
from pathlib import Path

W, OUT = Path(sys.argv[1]), Path(sys.argv[2])
(W / "ctl").mkdir(exist_ok=True)
imgs = [l.split(",")[0] for l in (W / "images.csv").read_text().splitlines()[1:]]
load = lambda p: json.loads(Path(p).read_text())

def grype(path):
    r = subprocess.run(["grype", f"sbom:{path}", "-o", "json", "-q"], capture_output=True, text=True, stdin=subprocess.DEVNULL)
    return {(m["artifact"]["name"], m["artifact"]["version"], m["vulnerability"]["id"]) for m in json.loads(r.stdout)["matches"] if m["artifact"]["type"] in ("deb", "apk")}

def trivy(path):
    r = subprocess.run(["trivy", "sbom", str(path), "--skip-db-update", "--skip-java-db-update", "--format", "json", "-q"], capture_output=True, text=True, stdin=subprocess.DEVNULL)
    d = json.loads(r.stdout)
    return {(v["PkgName"], v["InstalledVersion"], v["VulnerabilityID"]) for res in d.get("Results") or [] if res.get("Class") == "os-pkgs" for v in res.get("Vulnerabilities") or []}

def purl_variant(n, gen, fix_distro):
    ref = {x["name"]: x["purl"] for x in load(W / "ref" / f"{n}_truth_dual.cdx.json")["components"] if x.get("purl")}
    d = load(W / "out" / f"{n}_{gen}.cdx.json")
    for x in d["components"]:
        p, r = x.get("purl") or "", ref.get(x["name"], "")
        if not p.startswith(("pkg:deb/", "pkg:apk/")) or not r:
            continue
        m = re.search(r"upstream=[^&]+", r)
        if m and "upstream=" not in p:
            p += ("&" if "?" in p else "?") + m.group(0)
        if fix_distro and p.startswith("pkg:apk/"):
            p = re.sub(r"distro=[^&]+", re.search(r"distro=[^&]+", r).group(0), p)
        x["purl"] = p
    out = W / "ctl" / f"{n}_{gen}_{'distro' if fix_distro else 'up'}.cdx.json"
    out.write_text(json.dumps(d))
    return out

def props_variant(n):
    tp = {x["name"]: [p for p in (x.get("properties") or []) if p["name"].startswith("aquasecurity:trivy:") and "Layer" not in p["name"]] for x in load(W / "out" / f"{n}_trivy.cdx.json")["components"]}
    d = load(W / "out" / f"{n}_syft.cdx.json")
    for x in d["components"]:
        if tp.get(x["name"]) and (x.get("purl") or "").startswith(("pkg:deb/", "pkg:apk/")):
            x["properties"] = (x.get("properties") or []) + tp[x["name"]]
    out = W / "ctl" / f"{n}_syft_props.cdx.json"
    out.write_text(json.dumps(d))
    return out

def os_variant(n, graph):
    d = load(W / "out" / f"{n}_cdxgen.cdx.json")
    truth = load(W / "truth" / f"{n}.json")
    rid = f"os-{n}"
    d["components"].append({"type": "operating-system", "bom-ref": rid, "name": truth["os"], "version": truth["os_version"]})
    if graph:
        root = (d.get("metadata", {}).get("component") or {}).get("bom-ref")
        pk = [x["bom-ref"] for x in d["components"] if x.get("bom-ref") and (x.get("purl") or "").startswith(("pkg:deb/", "pkg:apk/"))]
        d["dependencies"] = (d.get("dependencies") or []) + [{"ref": root, "dependsOn": [rid]}, {"ref": rid, "dependsOn": pk}]
    out = W / "ctl" / f"{n}_cdxgen_os{'graph' if graph else ''}.cdx.json"
    out.write_text(json.dumps(d))
    return out

rows = []
for n in imgs:
    ref_g, ref_t = grype(W / "ref" / f"{n}_truth_dual.cdx.json"), trivy(W / "ref" / f"{n}_truth_dual.cdx.json")
    for variant, src in (("as generated", W / "out" / f"{n}_trivy.cdx.json"), ("with upstream", purl_variant(n, "trivy", False)), ("with upstream and distro", purl_variant(n, "trivy", True))):
        g = grype(src)
        rows.append([n, "grype", "trivy", variant, len(ref_g), len(g & ref_g), len(g - ref_g)])
    for variant, src in (("as generated", W / "out" / f"{n}_syft.cdx.json"), ("with trivy properties", props_variant(n))):
        g = trivy(src)
        rows.append([n, "trivy", "syft", variant, len(ref_t), len(g & ref_t), len(g - ref_t)])
    for variant, src in (("as generated", W / "out" / f"{n}_cdxgen.cdx.json"), ("with upstream", purl_variant(n, "cdxgen", False))):
        g = grype(src)
        rows.append([n, "grype", "cdxgen", variant, len(ref_g), len(g & ref_g), len(g - ref_g)])
    for variant, src in (("as generated", W / "out" / f"{n}_cdxgen.cdx.json"), ("with os component", os_variant(n, False)), ("with os component and graph", os_variant(n, True))):
        g = trivy(src)
        rows.append([n, "trivy", "cdxgen", variant, len(ref_t), len(g & ref_t), len(g - ref_t)])
with open(OUT / "container_controls.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["image", "scanner", "generator", "variant", "reference", "found", "extra"])
    w.writerows(rows)
