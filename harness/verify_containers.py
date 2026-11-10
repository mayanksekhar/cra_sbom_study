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
need(len(comp) == 3 * len(imgs), "component rows: 3 generators over the images")
for r in comp:
    c = counts[imgs.index(r["image"])]
    ok = int(r["truth"]) == c and int(r["true_positive"]) == c and int(r["missed"]) == 0
    if r["generator"] in ("syft", "trivy"):
        ok = ok and int(r["extra"]) == 0
    else:
        ok = ok and int(r["extra"]) == int(r["extra_source"]) and int(r["extra"]) > 0
    need(ok, f"component row {r['image']} {r['generator']}")
cx = [r["extra"] for r in comp if r["generator"] == "cdxgen"]
cxs = ", ".join(cx[:-1]) + " and " + cx[-1]
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
(gs, gsf, gse), (gt, gtf, gte), (gc, gcf, gce) = tot("grype", "syft"), tot("grype", "trivy"), tot("grype", "cdxgen")
(ts, tsf, tse), (tt, ttf, tte), (tc, tcf, tce) = tot("trivy", "syft"), tot("trivy", "trivy"), tot("trivy", "cdxgen")
need(gs == gt == gc == ref_g and ts == tt == tc == ref_t, "scoring references equal calibration references")
need(gse == cpe and gte == 0 and tse == 0 and tte == 0 and tce == 0, "extras: grype syft equal the CPE findings, the others 0 apart from grype cdxgen")
def ct(s, g, v):
    rr = [r for r in ctl if r["scanner"] == s and r["generator"] == g and r["variant"] == v]
    return sum(int(r["found"]) for r in rr), sum(int(r["extra"]) for r in rr)
up, upx = ct("grype", "trivy", "with upstream")
ud, udx = ct("grype", "trivy", "with upstream and distro")
pr, prx = ct("trivy", "syft", "with trivy properties")
cu, cux = ct("grype", "cdxgen", "with upstream")
debref = sum(int(r["reference"]) for r in gi if "deb" in truth[r["image"]]["kind"] or "dpkg" in truth[r["image"]]["kind"])
need(up == debref, "upstream alone equals the Debian image references")
need(upx == udx == prx == 0, "no extra finding in the controls on Trivy's and Syft's SBOMs")
need(cu == ref_g and cux == gce, "cdxgen with upstream: all reference findings, extras unchanged")
for v in ("as generated", "with os component", "with os component and graph"):
    need(ct("trivy", "cdxgen", v) == (0, 0), "trivy on cdxgen stays at 0: " + v)
phr = [
 f"carry {cstr} installed packages",
 "(0 extra, 0 missed)",
 f"cdxgen 12.9.0 lists every one as well (0 missed) and adds, on every image, extra OS components ({cxs}), every one of them the name of a source package of the truth",
 f"The reference holds {ref_g} findings under Grype 0.114.0 and {ref_t} under Trivy 0.69.3",
 f"except {cpe} findings that Grype reports only through a CPE on busybox ({cs} on Alpine 3.20.3, Alpine 3.18.9 and postgres) and {ng} findings on the nginx.org build",
 f"Grype finds {gsf} of {gs} ({pc(gs, gsf)} percent) from Syft's SBOMs, {gtf} ({pc(gt, gtf)} percent) from Trivy's and {gcf} ({pc(gc, gcf)} percent) from cdxgen's; Trivy finds {ttf} of {tt} ({pc(tt, ttf)} percent) from its own SBOMs, {tsf} ({pc(ts, tsf)} percent) from Syft's and {tcf} ({pc(tc, tcf)} percent) from cdxgen's",
 f"The {gce} extra findings Grype reports on cdxgen's SBOMs",
 f"lets Grype find {up} of {ref_g} (all five Debian images), adding the Alpine distro value lets it find {ud} of {ref_g}, adding the upstream qualifier to cdxgen's purls lets Grype find {cu} of {ref_g}, and copying Trivy's source properties onto Syft's SBOMs lets Trivy find {pr} of {ref_t}, with no extra finding in the controls on Trivy's and Syft's SBOMs",
 "both leave the count at 0 and the cause is not established",
]
for p in phr:
    need(p in D, "draft.md lacks: " + p[:90])
need("9. Container scope:" in FB, "threats item 9 missing")
need("Future work: software in container images outside the package database" in FB, "future work sentence not updated")
for bad in ("Future work: container images,", "cdxgen was not run on images"):
    need(bad not in FB and bad not in D, "old wording still present: " + bad)
for f in fail:
    print("FAIL", f)
print("container set numbers:", "ok" if not fail else f"{len(fail)} failed")
sys.exit(1 if fail else 0)
