#!/usr/bin/env python3
"""Generate the figures of the study as plain SVG from tracked summary files. Usage: make_figures.py [--out DIR]"""
import argparse, collections, csv, json
from pathlib import Path
root = Path(__file__).resolve().parent.parent
ap = argparse.ArgumentParser()
ap.add_argument("--out", default=str(root / "docs" / "figures"))
a = ap.parse_args()
out = Path(a.out)
out.mkdir(parents=True, exist_ok=True)
FONT = 'font-family="DejaVu Sans, Arial, sans-serif"'

def esc(t):
    return str(t).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def text(x, y, s, size=11, anchor="start", weight="normal", fill="#111111"):
    return f'<text x="{x:.1f}" y="{y:.1f}" font-size="{size}" text-anchor="{anchor}" font-weight="{weight}" fill="{fill}" {FONT}>{esc(s)}</text>'

def rect(x, y, w, h, fill):
    return f'<rect x="{x:.1f}" y="{y:.1f}" width="{max(w, 0):.1f}" height="{max(h, 0):.1f}" fill="{fill}"/>'

def line(x1, y1, x2, y2, stroke="#d0d0d0"):
    return f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" stroke="{stroke}" stroke-width="1"/>'

def svg(w, h, body, title):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img" aria-label="{esc(title)}">\n'
            f'<rect width="{w}" height="{h}" fill="#ffffff"/>\n' + "\n".join(body) + "\n</svg>\n")

# Figure 1: findings recovered per generator and set
SETS = [("Pilot", "results"), ("Older pins", "results_old"), ("Go", "results_go"), ("Maven", "results_mvn"), ("PyPI", "results_py"), ("Rust", "results_rust"), ("npm", "results_npm")]
TOOLS = [("cdxgen", "#1f77b4"), ("syft", "#ff7f0e"), ("trivy", "#2ca02c")]
data = {}
for label, d in SETS:
    c = collections.defaultdict(lambda: [0, 0])
    for r in csv.DictReader(open(root / d / "findings_vs_reference.csv")):
        if r["scanner"] == "grype" and not r["project"].endswith("_nolock"):
            c[r["tool"]][0] += int(r["tp"])
            c[r["tool"]][1] += int(r["ref_n"])
    data[label] = c
W, H, L, R, T, B = 900, 440, 70, 880, 90, 370
gw = (R - L) / len(SETS)
bw = gw * 0.26
body = [text(L, 28, "Reference findings recovered from each generator's SBOM (scored with Grype)", 15, weight="bold"),
        text(L, 48, "Share of the reference findings in each set. n is the number of reference findings.", 11, fill="#444444")]
for k in range(5):
    pct = 25 * k
    y = B - pct / 100 * (B - T)
    body.append(line(L, y, R, y))
    body.append(text(L - 8, y + 4, f"{pct}%", 10, "end", fill="#444444"))
for i, (label, d) in enumerate(SETS):
    x0 = L + i * gw + (gw - (3 * bw + 4)) / 2
    n = data[label]["cdxgen"][1]
    for j, (tool, color) in enumerate(TOOLS):
        tp, ref = data[label][tool]
        pct = 100 * tp / ref if ref else 0
        x = x0 + j * (bw + 2)
        y = B - pct / 100 * (B - T)
        body.append(rect(x, y, bw, B - y, color))
        body.append(text(x + bw / 2, y - 4, f"{pct:.0f}", 10, "middle"))
        print(f"fig1 {label:<11}{tool:<8}{tp:>5} of {ref:<5}{pct:6.1f}%")
    body.append(text(L + i * gw + gw / 2, B + 18, label, 11, "middle"))
    body.append(text(L + i * gw + gw / 2, B + 32, f"n = {n}", 10, "middle", fill="#444444"))
lx = L
for tool, color in TOOLS:
    body.append(rect(lx, 62, 12, 12, color))
    body.append(text(lx + 17, 72, tool, 11))
    lx += 90
(out / "fig1_findings_recovered.svg").write_text(svg(W, H, body, "Reference findings recovered per generator and set"))

# Figure 2: reachability classes per Go project at product level
reach = json.load(open(root / "results_go" / "reach_product.json"))
rows = []
for p, es in reach.items():
    c = collections.Counter(e["class"] for e in es)
    rows.append((p, c["called"], c["not called"], c["unknown"]))
rows.sort(key=lambda r: (-(r[1] + r[2] + r[3]), r[0]))
maxn = max(r[1] + r[2] + r[3] for r in rows)
LX, PX, PW, RH, TOP = 20, 170, 640, 30, 100
H2 = TOP + RH * len(rows) + 30
COL = {"called": "#d62728", "not called": "#9ecae1", "unknown": "#bdbdbd"}
tot = [sum(r[k] for r in rows) for k in (1, 2, 3)]
body = [text(LX, 28, "Go findings by reachability class at product level", 15, weight="bold"),
        text(LX, 48, f"Nine of ten projects (k9s could not be analysed within the memory available): {tot[0]} called, {tot[1]} not called, {tot[2]} unknown.", 11, fill="#444444")]
lx = LX
for key in ("called", "not called", "unknown"):
    body.append(rect(lx, 62, 12, 12, COL[key]))
    body.append(text(lx + 17, 72, key, 11))
    lx += 100
for i, (p, c1, c2, c3) in enumerate(rows):
    y = TOP + i * RH
    body.append(text(PX - 8, y + 18, p, 11, "end"))
    x = PX
    for val, key in ((c1, "called"), (c2, "not called"), (c3, "unknown")):
        w = val / maxn * PW
        body.append(rect(x, y + 4, w, RH - 8, COL[key]))
        if w >= 20:
            body.append(text(x + w / 2, y + 19, val, 10, "middle", fill="#ffffff" if key == "called" else "#111111"))
        x += w
    body.append(text(x + 6, y + 19, c1 + c2 + c3, 10, fill="#444444"))
    print(f"fig2 {p:<18}called {c1:>3}  not called {c2:>3}  unknown {c3:>3}")
(out / "fig2_reachability_by_project.svg").write_text(svg(900, H2, body, "Go findings by reachability class at product level"))

# Figure 3: not called findings removed by VEX statements
vx = list(csv.DictReader(open(root / "results_go" / "vex_set_product.csv")))
combos = [("trivy", "A", "Trivy, form A"), ("trivy", "B", "Trivy, form B"), ("grype", "A", "Grype, form A"), ("grype", "B", "Grype, form B")]
W3, H3, L3, R3, T3, B3 = 640, 420, 70, 620, 100, 330
gw3 = (R3 - L3) / 4
bars = []
for sc, fm, lab in combos:
    rr = [r for r in vx if r["scanner"] == sc and r["form"] == fm]
    bars.append((lab, sum(int(r["notcalled_removed"]) for r in rr), sum(int(r["notcalled_total"]) for r in rr), sum(int(r["called_removed"]) for r in rr)))
body = [text(L3, 28, "Not called findings removed by VEX statements", 15, weight="bold"),
        text(L3, 48, "Product level, nine Go projects. Form A: statements scoped to the product. Form B: scoped to the module.", 11, fill="#444444")]
for k in range(5):
    pct = 25 * k
    y = B3 - pct / 100 * (B3 - T3)
    body.append(line(L3, y, R3, y))
    body.append(text(L3 - 8, y + 4, f"{pct}%", 10, "end", fill="#444444"))
for i, (lab, rem, tt, cr) in enumerate(bars):
    pct = 100 * rem / tt if tt else 0
    bwid = gw3 * 0.5
    x = L3 + i * gw3 + (gw3 - bwid) / 2
    y = B3 - pct / 100 * (B3 - T3)
    body.append(rect(x, y, bwid, B3 - y, "#1f77b4"))
    body.append(text(x + bwid / 2, y - 6, f"{rem} of {tt}", 11, "middle"))
    body.append(text(L3 + i * gw3 + gw3 / 2, B3 + 18, lab, 11, "middle"))
    body.append(text(L3 + i * gw3 + gw3 / 2, B3 + 34, f"called findings removed: {cr}", 10, "middle", fill="#444444"))
    print(f"fig3 {lab:<15}{rem:>4} of {tt:<4}{pct:6.1f}%  called removed {cr}")
(out / "fig3_vex_removal.svg").write_text(svg(W3, H3, body, "Not called findings removed by VEX statements"))

m, c = data["Maven"]["syft"], data["PyPI"]["cdxgen"]
cr_all = ", ".join(f"{b[0]} {b[3]}" for b in bars)
idx = ["# Figures", "",
       "Generated by harness/make_figures.py from summary files tracked in this repository. Regenerate with python3 harness/make_figures.py. python3 harness/check_all.py checks that these files match what the script produces.", "",
       "## Figure 1", "", "![Reference findings recovered per generator and set](fig1_findings_recovered.svg)", "",
       f"Share of the reference findings that each generator's SBOM recovers when scanned with Grype, per set. The reference is built from the shipped set of each project. For example Syft recovers {m[0]} of {m[1]} on Maven and cdxgen {c[0]} of {c[1]} on PyPI.", "",
       "## Figure 2", "", "![Go findings by reachability class at product level](fig2_reachability_by_project.svg)", "",
       f"Product level classes from govulncheck run on the packages of each shipped binary (results_go/reach_product.json): {tot[0]} called, {tot[1]} not called, {tot[2]} unknown over nine projects. k9s is missing because its analysis exceeded the memory available.", "",
       "## Figure 3", "", "![Not called findings removed by VEX statements](fig3_vex_removal.svg)", "",
       f"Share of not called findings removed when the scanner is given VEX statements marking them not_affected (results_go/vex_set_product.csv). Called findings removed per combination: {cr_all}.", ""]
(out / "index.md").write_text("\n".join(idx))
print("figures written to", out)
