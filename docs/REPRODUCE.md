# Reproducing the numbers

## What can be reproduced
The headline numbers can be recomputed from the summary files in this repository and, for the SBOM probes, from the data archive. The vulnerability databases (about 13 GB) are not published and cannot be rebuilt, because upstream data changes daily. Their file checksums are in tools/dbsnap_20261026.txt, tools/dbsnap_20261030.txt and tools/govuln_20261030.sha256. Running the full pipeline again would give different findings.

## Steps
1. Clone the repository. Run: python3 harness/check_all.py
   Expected without the archive: 5 ok, 0 failed, 2 skipped.
2. Download cra_data_20261108_clean2.tar.gz from the release page. Check it: sha256sum -c against the checksum in README.md.
3. Extract at the repository root without overwriting tracked files: tar -xzf cra_data_20261108_clean2.tar.gz --skip-old-files
4. Run again: python3 harness/check_all.py
   Expected with the archive: 7 ok, 0 failed, 0 skipped, and git status shows no changed files.

## Known and expected
1. Nine JSON files in the archive are empty. They are OSV Scanner outputs for SBOMs that crashed the scanner (five Syft SBOMs for npm and PyPI projects, express without a lockfile with Syft and Trivy) or produced no output (three PyPI cases).
2. The regenerated docs/table_findings.md must equal the tracked file. The check reports DIFFERS if it does not.

## Order of the pipeline (run by the author only, not by anyone else)
harness/fetch_set.sh, gen_set.sh, scan_set.sh, make_reference.py, score.py, score_findings.py, then the experiment scripts (vex_*.py, control_*.py, reach_*.py). They need the pinned tool versions in tools/pinned_versions.txt, the project sources at the pinned commits and the frozen databases.
