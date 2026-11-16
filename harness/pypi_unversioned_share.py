# usage: pypi_unversioned_share.py  (run from the repository root with the data archive; counts Grype pairs on purls without a version per PyPI SBOM and the false positives of the score)
import csv, glob, json
from collections import defaultdict
from pathlib import Path
fp = {(r["project"], r["tool"]): int(r["fp"]) for r in csv.DictReader(open("results_py/findings_vs_reference.csv")) if r["scanner"] == "grype"}
tot = defaultdict(lambda: [0, 0, 0])
print(f"{'project':<14}{'tool':<8}{'pairs':>6}{'on unversioned':>16}{'fp in score':>13}")
for f in sorted(glob.glob("results_py/vulns/pypi/*_grype.json")):
    stem = Path(f).name[: -len("_grype.json")]; proj, _, tool = stem.rpartition("_")
    d = json.loads(Path(f).read_text()); s = set()
    for m in d.get("matches", []):
        a = m.get("artifact", {}); s.add(((a.get("purl") or (str(a.get("name")) + "@" + str(a.get("version")))).lower(), m["vulnerability"]["id"]))
    unv = sum(1 for k in s if "@" not in k[0]); n = len(s)
    if unv or tool == "cdxgen":
        print(f"{proj:<14}{tool:<8}{n:>6}{unv:>16}{fp.get((proj, tool), -1):>13}")
    t = tot[tool]; t[0] += n; t[1] += unv; t[2] += fp.get((proj, tool), 0)
print("== totals per generator: pairs, on unversioned purls, false positives in the score")
for tool, t in sorted(tot.items()): print(f"   {tool:<8}{t[0]:>6}{t[1]:>8}{t[2]:>8}")
