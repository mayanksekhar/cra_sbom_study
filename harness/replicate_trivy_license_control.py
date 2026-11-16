"""Control for Trivy and a package-lock.json whose entry has its license written as a list (nest).
Usage (repository root, after: source harness/env_frozen.sh): python3 -I harness/replicate_trivy_license_control.py WORKDIR
Scans an unmodified copy and a copy with every license list in the root lock converted to a string, with the
flags of gen_set.sh and debug output. Counts are compared with the truth list nest_tree_shipped.txt.
WORKDIR receives the copies, SBOMs and logs. The record is written to results_replication/trivy_license_control_nest.txt."""
import json, re, shutil, subprocess, sys
from pathlib import Path
W = Path(sys.argv[1]); SRC = Path("dataset/src_npm2/nest")
OUT = Path("results_replication/trivy_license_control_nest.txt")
def norm(p): return (p or "").replace("%40", "@").lower().split("?")[0]
truth = {norm(x) for x in Path("groundtruth_npm/npm/nest_tree_shipped.txt").read_text().split()}
lines = []
def say(s):
    print(s); lines.append(s)
for lab in ("nest_unmodified", "nest_control"):
    shutil.rmtree(W / lab, ignore_errors=True); shutil.copytree(SRC, W / lab)
lock = W / "nest_control/package-lock.json"
d = json.loads(lock.read_text()); n = 0
for v in d["packages"].values():
    if isinstance(v.get("license"), list):
        v["license"] = " OR ".join(v["license"]); n += 1
lock.write_text(json.dumps(d, indent=2))
say("trivy: " + subprocess.run(["trivy", "--version"], capture_output=True, text=True).stdout.splitlines()[0])
say(f"license lists changed in the control copy: {n}")
for lab in ("nest_unmodified", "nest_control"):
    sbom = W / f"{lab}.cdx.json"
    r = subprocess.run(["trivy", "fs", "--skip-db-update", "--skip-java-db-update", "--format", "cyclonedx", "--output", str(sbom), "--debug", str(W / lab)],
                       stdin=subprocess.DEVNULL, capture_output=True, text=True)
    text = r.stdout + r.stderr; (W / f"{lab}.log").write_text(text)
    if r.returncode != 0:
        print("trivy failed for", lab); sys.exit(1)
    walk = sum("Walk error" in l for l in text.splitlines())
    m = re.search(r"Number of language-specific files\s+num=(\d+)", text)
    cs = json.load(open(sbom)).get("components", [])
    got = {norm(c["purl"]) for c in cs if c.get("purl")}
    say(f"{lab}: components {len(cs)}, walk errors {walk}, language specific files {m.group(1) if m else 'none'}, truth components found {len(truth & got)} of {len(truth)}, missing {len(truth - got)}")
OUT.write_text("\n".join(lines) + "\n")
