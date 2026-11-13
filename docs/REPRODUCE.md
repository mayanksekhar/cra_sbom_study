# Reproducing the numbers

## What can be reproduced
The headline numbers can be recomputed from the summary files in this repository and, for the SBOM probes, from the data archive. The vulnerability databases (about 13 GB) are not published and cannot be rebuilt, because upstream data changes daily. Their file checksums are in tools/dbsnap_20261026.txt, tools/dbsnap_20261030.txt and tools/govuln_20261030.sha256. Running the full pipeline again would give different findings.

## Steps
1. Clone the repository. Run: python3 harness/check_all.py
   Expected without the archive: 8 ok, 0 failed, 2 skipped.
2. Obtain cra_data_20261108_clean2.tar.gz (not yet published, it will be attached to a release of this repository). Check it with: echo "2af88c76e9d39e2b5fbb58261742d4921e6a8b026d007c3291c60244e45b3c12  cra_data_20261108_clean2.tar.gz" | sha256sum -c
3. Extract at the repository root without overwriting tracked files: tar -xzf cra_data_20261108_clean2.tar.gz --skip-old-files
4. Run again: python3 harness/check_all.py
   Expected with the archive: 10 ok, 0 failed, 0 skipped, and git status shows no changed files.

## Known and expected
1. Nine JSON files in the archive are empty. They are OSV Scanner outputs. Five are for Syft SBOMs of npm and PyPI projects, which crash OSV Scanner 2.7.0 (unsupported ecosystem: GitHub Actions). Four are for SBOMs from which OSV Scanner produced no output: three Trivy SBOMs with no components (express without a lockfile, fastapi, pip) and the Syft SBOM of django, whose cause was not checked individually.
       results/vulns/npm/axios_syft_osv.json
       results/vulns/npm/express_syft_osv.json
       results/vulns/npm/express_nolock_syft_osv.json
       results/vulns/pypi/flask_syft_osv.json
       results/vulns/pypi/requests_syft_osv.json
       results/vulns/npm/express_nolock_trivy_osv.json
       results_py/vulns/pypi/fastapi_trivy_osv.json
       results_py/vulns/pypi/pip_trivy_osv.json
       results_py/vulns/pypi/django_syft_osv.json
2. The regenerated docs/table_findings.md must equal the tracked file. The check reports DIFFERS if it does not.
3. The container set (results_containers) is checked from the tracked summary files and truth lists by harness/verify_containers.py. The image archives, SBOMs and scan outputs are not in the repository or in the data archive. They are rebuilt with harness/container_pull.sh (podman, images pulled by tag; the digests it records must equal those in results_containers/images.csv), harness/container_sbom.sh (Syft 1.45.1, Trivy 0.69.3 and cdxgen 12.9.0), harness/container_score.py, container_controls.py and container_components.py, with the frozen databases of tools/dbsnap_*.txt. Set TMPDIR to a folder on disk before running them: with /tmp on a RAM backed filesystem, cdxgen and Grype fail on the larger images (disk quota errors).
4. The older cdxgen replication (results_replication) is checked from two tracked CSVs by harness/verify_replication.py. To rerun it, use harness/replicate_cdxgen.sh VERSION WORKDIR (it installs that cdxgen release with npm into WORKDIR, separate from tools/, and runs it on fresh copies of the npm and Rust projects) and then harness/replicate_cdxgen_compare.py VERSION WORKDIR, which compares the purl sets with the pinned SBOMs in results_npm and results_rust. Versions run: 10.11.0 and 11.11.0.
5. The npm set is two lists: dataset/npm_set.csv (3 projects) and dataset/npm_set2.csv (8 projects chosen by the rule in docs/npm_selection.md with harness/probe_npm_candidates.sh; probe output in results_npm/probe.csv). Both are in results_npm and groundtruth_npm. harness/gen_set.sh reads CRA_WORK to move its work folder off a RAM backed /tmp (default /tmp/cra_work).

## Order of the pipeline (run by the author only, not by anyone else)
harness/fetch_set.sh, gen_set.sh, scan_set.sh, make_reference.py, score.py, score_findings.py, then the experiment scripts (vex_*.py, control_*.py, reach_*.py). They need the pinned tool versions in tools/pinned_versions.txt, the project sources at the pinned commits and the frozen databases.
