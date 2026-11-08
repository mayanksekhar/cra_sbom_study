#!/usr/bin/env python3
"""Run the repository's number checks. A check whose data is not present is skipped with a message."""
import subprocess, sys
from pathlib import Path
root = Path(__file__).resolve().parent.parent
CSVS = [f"{d}/findings_vs_reference.csv" for d in ("results", "results_old", "results_go", "results_mvn", "results_py")]
SUMMARY = CSVS + ["results_go/reach.json", "results_go/product_findings.csv", "results_go/vex_set.csv"]
RAW = [f"{d}/raw" for d in ("results", "results_old", "results_go", "results_mvn", "results_py")]
DOCS = ["docs/draft.md", "docs/draft_section7.md", "docs/draft_front_back.md"]
CHECKS = [
    ("progress rubric", "harness/progress.py", ["docs/progress.csv"]),
    ("findings table (regenerates docs/table_findings.md)", "harness/make_table_findings.py", CSVS),
    ("draft headline numbers", "harness/verify_draft_numbers.py", SUMMARY + DOCS),
    ("abstract numbers", "harness/verify_front.py", CSVS + DOCS),
    ("section 7 numbers", "harness/verify_section7.py", SUMMARY + RAW + DOCS),
    ("BSI probe of generator SBOMs", "harness/bsi_probe.py", RAW),
]
skipped = failed = 0
for name, script, needs in CHECKS:
    missing = [n for n in needs if not (root / n).exists()]
    if missing:
        skipped += 1
        print(f"SKIPPED  {name}: needs {', '.join(missing[:3])}{' ...' if len(missing) > 3 else ''} (see docs/REPRODUCE.md, data archive)")
        continue
    r = subprocess.run([sys.executable, str(root / script)], capture_output=True, text=True, cwd=root)
    out = (r.stdout + r.stderr).strip().splitlines()
    bad = r.returncode != 0 or any("MISSING" in l for l in out)
    failed += bad
    print(f"{'FAILED ' if bad else 'OK     '}  {name}: {out[-1][:100] if out else '(no output)'}")
    if bad:
        for l in out[-6:]:
            print("          ", l[:110])
    if script.endswith("make_table_findings.py") and (root / ".git").exists():
        d = subprocess.run(["git", "diff", "--quiet", "--", "docs/table_findings.md"], cwd=root)
        print(f"{'OK     ' if d.returncode == 0 else 'DIFFERS'}  regenerated table {'matches' if d.returncode == 0 else 'differs from'} the tracked docs/table_findings.md")
        failed += d.returncode != 0
print(f"\n{len(CHECKS) - skipped - failed} ok, {failed} failed, {skipped} skipped")
sys.exit(1 if failed else 0)
