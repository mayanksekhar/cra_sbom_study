"""Control for the CycloneDX group field in old Grype releases (uptime-kuma, npm).
Usage: replicate_grype_group_control.py WORKDIR
WORKDIR holds oldgrype/VERSION/grype (see fetch_old_grype.sh). Run after: source harness/env_frozen.sh
Run from the repository root. The modified SBOM copy is written to WORKDIR."""
import json, os, subprocess, sys
W = sys.argv[1]
PROJECT = "uptime-kuma"
def pairs(d):
    s = {}
    for m in d.get("matches", []):
        a = m["artifact"]
        s.setdefault(((a.get("purl") or "").lower(), m["vulnerability"]["id"]), a)
    return s
def scan(v, f):
    r = subprocess.run([f"{W}/oldgrype/{v}/grype", f"sbom:{f}", "-o", "json", "-q"], capture_output=True, text=True)
    return pairs(json.loads(r.stdout))
R = set(pairs(json.load(open(f"results_npm/vulns_ref/npm/{PROJECT}_truth_grype.json"))))
res = {}
for tool in ("trivy", "cdxgen"):
    f = f"results_npm/raw/npm/{PROJECT}_{tool}.cdx.json"
    res[tool] = (f, pairs(json.load(open(f"results_npm/vulns/npm/{PROJECT}_{tool}_grype.json"))))
print("== 1 evidence: pairs 0.88.0 reports on the trivy sbom that 0.114.0 does not (first 8)")
f, G = res["trivy"]
O = scan("0.88.0", f)
for k in sorted(set(O) - set(G))[:8]:
    a = O[k]
    print("   ", k[1], "| artifact name", a.get("name"), "version", a.get("version"), "| purl", a.get("purl"))
print("   total only_old", len(set(O) - set(G)), "of which artifact name has no scope slash while the purl has %40:",
      sum(1 for k in set(O) - set(G) if "%40" in k[0] and "/" not in O[k].get("name", "")))
print("== 2 control: group merged into name on a copy of the trivy sbom, scanned with 0.88.0")
sb = json.load(open(f))
def walk(cs):
    for c in cs or []:
        if c.get("group"):
            c["name"] = c["group"] + "/" + c["name"]
            del c["group"]
        walk(c.get("components"))
walk(sb.get("components"))
walk((sb.get("metadata") or {}).get("component", {}).get("components"))
cf = f"{W}/ctl_{PROJECT}_trivy_group_in_name.cdx.json"
json.dump(sb, open(cf, "w"))
O2 = scan("0.88.0", cf)
print("   reference findings lost, as generated:", len((set(G) & R) - set(O)), "| after merging group into name:", len((set(G) & R) - set(O2)))
print("   only_old pairs, as generated:", len(set(O) - set(G)), "| after:", len(set(O2) - set(G)))
print("== 3 bisect: reference findings lost and extra pairs per version")
for tool in ("trivy", "cdxgen"):
    f, G = res[tool]
    for v in ("0.88.0", "0.90.0", "0.95.0", "0.97.0", "0.100.0"):
        O = scan(v, f)
        print(f"   {tool:7s} {v:8s} lost {len((set(G) & R) - set(O))}  only_old {len(set(O) - set(G))}  only_pinned {len(set(G) - set(O))}")
