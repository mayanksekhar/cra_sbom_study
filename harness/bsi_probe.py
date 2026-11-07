#!/usr/bin/env python3
"""Partial probe of generator SBOMs against a few BSI TR-03183-2 v2.1.0 requirements. Not a conformance test."""
import collections, json
from pathlib import Path
root = Path(__file__).resolve().parent.parent
DIRS = ["results", "results_old", "results_go", "results_mvn", "results_py"]

def walk(cs):
    for c in cs or []:
        yield c
        yield from walk(c.get("components"))

stats = collections.defaultdict(collections.Counter)
specs = collections.defaultdict(collections.Counter)
for d in DIRS:
    for f in sorted((root / d / "raw").glob("*/*.cdx.json")):
        tool = f.name[: -len(".cdx.json")].rsplit("_", 1)[1]
        doc = json.loads(f.read_text())
        s = stats[tool]
        s["sboms"] += 1
        specs[tool][str(doc.get("specVersion"))] += 1
        mc = (doc.get("metadata") or {}).get("component") or {}
        s["root_version"] += bool(mc.get("version"))
        s["root_purl"] += bool(mc.get("purl"))
        ref = mc.get("bom-ref")
        edges = {x["ref"]: x.get("dependsOn") or [] for x in doc.get("dependencies") or []}
        s["root_edges"] += bool(ref and edges.get(ref))
        s["embedded_vulns"] += bool(doc.get("vulnerabilities"))
        s["compositions"] += bool(doc.get("compositions"))
        pk = [c for c in walk(doc.get("components")) if c.get("purl")]
        s["packages"] += len(pk)
        s["pkg_noversion"] += sum(1 for c in pk if not c.get("version"))
print("Partial BSI TR-03183-2 v2.1.0 probe over all generator SBOMs (5 sets). Counts are SBOM files unless stated.")
print(f"{'generator':<9}{'sboms':>6}{'root version':>14}{'root purl':>10}{'root edges':>11}{'vulns embedded':>15}{'compositions':>13}{'pkgs':>7}{'no version':>11}")
for t, s in sorted(stats.items()):
    print(f"{t:<9}{s['sboms']:>6}{s['root_version']:>14}{s['root_purl']:>10}{s['root_edges']:>11}{s['embedded_vulns']:>15}{s['compositions']:>13}{s['packages']:>7}{s['pkg_noversion']:>11}")
print("spec versions:", {t: dict(c) for t, c in sorted(specs.items())})
