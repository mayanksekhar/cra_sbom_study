#!/usr/bin/env python3
"""Recompute the container set figures from tracked files and require the same phrases in the draft."""
import csv, json, sys
from pathlib import Path

root = Path(__file__).resolve().parent.parent
R = root / "results_containers"
D = " ".join((root / "docs" / "draft.md").read_text().split())
FB = " ".join((root / "docs" / "draft_front_back.md").read_text().split())
rows = lambda n: list(csv.DictReader(open(R / n)))
fail = []
def need(cond, msg):
    if not cond:
        fail.append(msg)
imgs = [r["name"] for r in rows("images.csv")]
truth = {n: json.loads((R / "truth" / f"{n}.json").read_text()) for n in imgs}
counts = [len(truth[n]["packages"]) for n in imgs]
cstr = ", ".join(map(str, counts[:-1])) + " and " + str(counts[-1])
comp, cal, sco, ctl = rows("container_components.csv"), rows("container_calibration.csv"), rows("container_scoring.csv"), rows("container_controls.csv")
need(len(comp) == 2 * len(imgs) and all(int(r["truth"]) == counts[imgs.index(r["image"])] and int(r["true_positive"]) == int(r["truth"]) and int(r["extra"]) == 0 and int(r["missed"]) == 0 for r in comp), "component level: every package found, 0 extra, 0 missed")
ref_g = sum(int(r["reference"]) for r in cal if r["scanner"] == "grype")
ref_t = sum(int(r["reference"]) for r in cal if r["scanner"] == "trivy")
cpe = sum(int(r["only_image_cpe_match"]) for r in cal)
gi = [r for r in cal if r["scanner"] == "grype"]
ti = [r for r in cal if r["scanner"] == "trivy"]
need(all(int(r["only_image"]) == int(r["only_image_cpe_match"]) for r in gi), "grype: every image only finding is a CPE match")
need(all(int(r["only_reference"]) == 0 for r in gi), "grype: nothing only in the reference")
need(all(int(r["only_image"]) == 0 for r in ti), "trivy: nothing only in the image scan")
ng = sum(int(r["only_reference"]) for r in ti)
need(ng == sum(int(r["only_reference"]) for r in ti if r["image"] == "nginx"), "trivy: reference only findings are all on nginx")
cs = ", ".join(str(r["only_image"]) for r in gi if int(r["only_image"]) > 0)
cs = cs.rsplit(", ", 1)[0] + " and " + cs.rsplit(", ", 1)[1]
def tot(s, g):
    rr = [r for r in sco if r["scanner"] == s and r["generator"] == g]
    return sum(int(r["reference"]) for r in rr), sum(int(r["found"]) for r in rr), sum(int(r["extra"]) for r in rr)
pc = lambda a, b: f"{100 * b / a:.1f}"
(gs, gsf, gse), (gt, gtf, gte), (ts, tsf, tse), (tt, ttf, tte) = tot("grype", "syft"), tot("grype", "trivy"), tot("trivy", "syft"), tot("trivy", "trivy")
need(gs == ref_g and gt == ref_g and ts == ref_t and tt == ref_t, "scoring references equal calibration references")
need(gse == cpe and gte == 0 and tse == 0 and tte == 0, "extras: grype syft equal the CPE findings, the others 0")
def ct(s, g, v):
    rr = [r for r in ctl if r["scanner"] == s and r["generator"] == g and r["variant"] == v]
    return sum(int(r["found"]) for r in rr), sum(int(r["extra"]) for r in rr)
up, upx = ct("grype", "trivy", "with upstream")
ud, udx = ct("grype", "trivy", "with upstream and distro")
pr, prx = ct("trivy", "syft", "with trivy properties")
debref = sum(int(r["reference"]) for r in gi if "deb" in truth[r["image"]]["kind"] or "dpkg" in truth[r["image"]]["kind"])
need(up == debref, "upstream alone equals the Debian image references")
need(upx == udx == prx == 0, "no extra finding in any control")
phr = [
 f"carry {cstr} installed packages",
 "(0 extra, 0 missed)",
 f"The reference holds {ref_g} findings under Grype 0.114.0 and {ref_t} under Trivy 0.69.3",
 f"except {cpe} findings that Grype reports only through a CPE on busybox ({cs} on Alpine 3.20.3, Alpine 3.18.9 and postgres) and {ng} findings on the nginx.org build",
 f"Grype finds {gsf} of {gs} ({pc(gs, gsf)} percent) from Syft's SBOMs and {gtf} ({pc(gt, gtf)} percent) from Trivy's; Trivy finds {tsf} of {ts} ({pc(ts, tsf)} percent) from Syft's SBOMs and {ttf} ({pc(tt, ttf)} percent) from its own",
 f"lets Grype find {up} of {ref_g} (all five Debian images), adding the Alpine distro value lets it find {ud} of {ref_g}, and copying Trivy's source properties onto Syft's SBOMs lets Trivy find {pr} of {ref_t}, with no extra finding in any control",
]
for p in phr:
    need(p in D, "draft.md lacks: " + p[:90])
need("9. Container scope:" in FB, "threats item 9 missing")
need("Future work: software in container images outside the package database" in FB, "future work sentence not updated")
need("Future work: container images," not in FB, "old future work sentence still present")
for f in fail:
    print("FAIL", f)
print("container set numbers:", "ok" if not fail else f"{len(fail)} failed")
sys.exit(1 if fail else 0)
