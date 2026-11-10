#!/usr/bin/env python3
"""Regenerate the figures into a temporary folder and compare them byte for byte with docs/figures."""
import subprocess, sys, tempfile
from pathlib import Path
root = Path(__file__).resolve().parent.parent
with tempfile.TemporaryDirectory() as td:
    subprocess.run([sys.executable, str(root / "harness" / "make_figures.py"), "--out", td], check=True, capture_output=True)
    bad = 0
    for p in sorted(Path(td).iterdir()):
        f = root / "docs" / "figures" / p.name
        same = f.exists() and f.read_bytes() == p.read_bytes()
        bad += not same
        print("OK     " if same else "DIFFERS", p.name)
    print("figures not matching the tracked files:", bad)
    sys.exit(1 if bad else 0)
