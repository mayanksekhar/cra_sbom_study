# usage: replicate_grype_go_py_trace.py WORKDIR  (counts of the differences between Grype 0.90.0 and 0.95.0 and the pinned scans on the Go and PyPI sets)
import glob, json, sys
from collections import Counter
from pathlib import Path
W = Path(sys.argv[1])
def pairs(p):
    d = json.loads(Path(p).read_text()); s = set()
    for m in d.get("matches", []):
        a = m.get("artifact", {})
        s.add(((a.get("purl") or (str(a.get("name")) + "@" + str(a.get("version")))).lower(), m["vulnerability"]["id"]))
    return s
def files(res, eco):
    return sorted(glob.glob(f"{res}/vulns/{eco}/*_grype.json") + glob.glob(f"{res}/vulns_ref/{eco}/*_grype.json"))
print("== Go, Grype 0.90.0 against the pinned 0.114.0, all 40 SBOMs, by advisory id prefix")
pin_c, lost_c, gain_c = Counter(), Counter(), Counter()
for f in files("results_go", "go"):
    a = pairs(f); b = pairs(W / "out_grype_0.90.0" / "go" / Path(f).name)
    for k in a: pin_c[k[1].split("-")[0]] += 1
    for k in a - b: lost_c[k[1].split("-")[0]] += 1
    for k in b - a: gain_c[k[1].split("-")[0]] += 1; print("   gained in 0.90.0:", Path(f).name, k)
for p in sorted(pin_c): print(f"   {p:5s} pinned {pin_c[p]:5d} lost {lost_c[p]:5d} gained {gain_c[p]:3d}")
def has_version(purl): return "@" in purl
print("== PyPI, all 32 SBOMs: pairs on purls with and without a version")
for ver in ("0.90.0", "0.95.0"):
    lost = Counter(); extra = Counter()
    for f in files("results_py", "pypi"):
        a = pairs(f); b = pairs(W / f"out_grype_{ver}" / "pypi" / Path(f).name)
        for k in a - b: lost[has_version(k[0])] += 1
        for k in b - a: extra[has_version(k[0])] += 1
    print(f"   {ver}: lost on versioned purls {lost[True]}, on unversioned {lost[False]} | extra on versioned {extra[True]}, on unversioned {extra[False]}")
pin_unv = sum(1 for f in files("results_py", "pypi") for k in pairs(f) if not has_version(k[0]))
pin_all = sum(1 for f in files("results_py", "pypi") for k in pairs(f))
print(f"   pinned 0.114.0: {pin_unv} of {pin_all} pairs are on unversioned purls")
print("== the SBOMs that carry unversioned purls (pypi), count of such components")
for f in sorted(glob.glob("results_py/raw/pypi/*.cdx.json")):
    cs = json.loads(Path(f).read_text()).get("components", [])
    n = sum(1 for c in cs if c.get("purl") and "@" not in c["purl"])
    if n: print(f"   {Path(f).name[:-9]:<26} {n:4d} of {len(cs)}")
